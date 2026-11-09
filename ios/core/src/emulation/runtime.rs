//! Guest-only Android runtime. No native ADI calls or guest-to-host pointers.
use super::{Cpu, Fault, Memory, Permissions, elf::Image};
use sideload::anisette::local_adi::elf::Elf;
use std::collections::BTreeMap;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const CORE: u64 = 0x1000_0000;
const STORE: u64 = 0x2000_0000;
const HEAP: u64 = 0x3000_0000;
const HEAP_SIZE: usize = 16 * 1024 * 1024;
const STACK: u64 = 0x4000_0000;
const STACK_SIZE: usize = 2 * 1024 * 1024;
const TLS: u64 = 0x5000_0000;
const TRAPS: u64 = 0x7000_0000;
const RETURN: u64 = 0xffff_ffff_ffff_fff0;
const MAX_BUFFER: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct RuntimeError {
    pub fault: Fault,
    pub pc: u64,
}
pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;
impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest ADI {:?} at {:#x}", self.fault, self.pc)
    }
}
impl std::error::Error for RuntimeError {}
impl From<Fault> for RuntimeError {
    fn from(fault: Fault) -> Self {
        Self { fault, pc: 0 }
    }
}

struct GuestFile {
    file: File,
    append: bool,
}

pub struct Runtime {
    pub memory: Memory,
    symbols: BTreeMap<String, u64>,
    core_symbols: BTreeMap<String, u64>,
    traps: BTreeMap<u64, String>,
    free: BTreeMap<u64, usize>,
    allocated: BTreeMap<u64, usize>,
    storage: Option<PathBuf>,
    files: BTreeMap<u32, GuestFile>,
    trace_files: bool,
}
impl Runtime {
    pub fn new(core: &[u8], store: &[u8]) -> RuntimeResult<Self> {
        let mut imports = BTreeMap::new();
        let mut traps = BTreeMap::new();
        for bytes in [core, store] {
            let elf = Elf::parse(bytes).map_err(|_| Fault::InvalidElf)?;
            for symbol in elf
                .symbols
                .iter()
                .filter(|s| !s.defined && !s.name.is_empty() && !s.weak)
            {
                if !imports.contains_key(&symbol.name) {
                    if imports.len() >= 4096 {
                        return Err(Fault::UnresolvedImport.into());
                    }
                    let address = TRAPS + (imports.len() as u64) * 8;
                    imports.insert(symbol.name.clone(), address);
                    traps.insert(address, symbol.name.clone());
                }
            }
        }
        let core = Image::load(core, CORE, &imports)?;
        let core_symbols: BTreeMap<_, _> = core.exports().map(|(k, v)| (k.to_owned(), v)).collect();
        imports.extend(core_symbols.clone());
        let store = Image::load(store, STORE, &imports)?;
        let symbols = store.exports().map(|(k, v)| (k.to_owned(), v)).collect();
        let mut memory = core.memory;
        memory.append(store.memory)?;
        memory.map(HEAP, HEAP_SIZE, &[], Permissions::DATA)?;
        memory.map(STACK, STACK_SIZE, &[], Permissions::DATA)?;
        memory.map(TLS, 4096, &[], Permissions::DATA)?;
        Ok(Self {
            memory,
            symbols,
            core_symbols,
            traps,
            free: BTreeMap::from([(HEAP, HEAP_SIZE)]),
            allocated: BTreeMap::new(),
            storage: None,
            files: BTreeMap::new(),
            trace_files: std::env::var_os("SIDELOAD_GUEST_FS_TRACE").is_some(),
        })
    }
    /// Existing private directory. Guest file names resolve under virtual /adi.
    pub fn set_storage(&mut self, path: &Path) -> RuntimeResult<()> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Fault::Read)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Fault::Read.into());
        }
        self.storage = Some(fs::canonicalize(path).map_err(|_| Fault::Read)?);
        Ok(())
    }
    fn path(&self, address: u64) -> RuntimeResult<Option<PathBuf>> {
        let bytes = self.string(address)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Fault::Read)?;
        let relative = text.strip_prefix("/adi/").unwrap_or(text);
        if relative.is_empty()
            || matches!(relative, "." | "..")
            || relative.len() > 255
            || !relative
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(Fault::Read.into());
        }
        let Some(root) = &self.storage else {
            return Ok(None);
        };
        let path = root.join(relative);
        if let Ok(m) = fs::symlink_metadata(&path) {
            if !m.is_file() || m.file_type().is_symlink() {
                return Err(Fault::Read.into());
            }
        }
        Ok(Some(path))
    }
    fn errno(&mut self, value: u32) -> RuntimeResult<u64> {
        self.memory.store(TLS + 256, 4, value as u64)?;
        Ok(u64::MAX)
    }
    fn io_error(&mut self, error: std::io::Error) -> RuntimeResult<u64> {
        use std::io::ErrorKind;
        self.errno(match error.kind() {
            ErrorKind::NotFound => 2,
            ErrorKind::PermissionDenied => 13,
            ErrorKind::AlreadyExists => 17,
            _ => 5,
        })
    }
    fn stat(&mut self, output: u64, metadata: &fs::Metadata) -> RuntimeResult<u64> {
        let mut bytes = [0u8; 128];
        bytes[16..20].copy_from_slice(
            &(if metadata.is_dir() {
                0o40700u32
            } else {
                0o100600u32
            })
            .to_le_bytes(),
        );
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[48..56].copy_from_slice(&metadata.len().to_le_bytes());
        bytes[56..60].copy_from_slice(&4096u32.to_le_bytes());
        bytes[64..72].copy_from_slice(&metadata.len().div_ceil(512).to_le_bytes());
        for (offset, time) in [
            (72, metadata.accessed()),
            (88, metadata.modified()),
            (104, metadata.modified()),
        ] {
            if let Ok(value) = time.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map_err(std::io::Error::other)
            }) {
                bytes[offset..offset + 8].copy_from_slice(&value.as_secs().to_le_bytes());
                bytes[offset + 8..offset + 16]
                    .copy_from_slice(&(value.subsec_nanos() as u64).to_le_bytes());
            }
        }
        self.memory.write(output, &bytes)?;
        Ok(0)
    }
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
    /// Static import name for developer diagnostics; never returns guest buffers.
    pub fn import_at(&self, address: u64) -> Option<&str> {
        self.traps.get(&address).map(String::as_str)
    }
    pub fn allocate(&mut self, size: usize) -> RuntimeResult<u64> {
        if size > MAX_BUFFER {
            return Err(Fault::Mapping.into());
        }
        let size = size.max(1).checked_add(15).ok_or(Fault::Mapping)? & !15;
        let (&address, &available) = self
            .free
            .iter()
            .find(|(_, n)| **n >= size)
            .ok_or(Fault::Mapping)?;
        self.free.remove(&address);
        if size < available {
            self.free.insert(address + size as u64, available - size);
        }
        self.allocated.insert(address, size);
        Ok(address)
    }
    pub fn release(&mut self, address: u64) -> RuntimeResult<()> {
        if address == 0 {
            return Ok(());
        }
        let mut start = address;
        let mut size = self.allocated.remove(&address).ok_or(Fault::Write)?;
        if let Some((&before, &length)) = self.free.range(..address).next_back() {
            if before + length as u64 == address {
                start = before;
                size += length;
                self.free.remove(&before);
            }
        }
        if let Some(length) = self.free.remove(&(start + size as u64)) {
            size += length;
        }
        self.free.insert(start, size);
        Ok(())
    }
    pub fn buffer(&mut self, bytes: &[u8]) -> RuntimeResult<u64> {
        let address = self.allocate(bytes.len())?;
        self.memory.write(address, bytes)?;
        Ok(address)
    }
    pub fn c_string(&mut self, value: &str) -> RuntimeResult<u64> {
        if value.as_bytes().contains(&0) {
            return Err(Fault::Read.into());
        }
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.buffer(&bytes)
    }
    fn string(&self, address: u64) -> RuntimeResult<Vec<u8>> {
        let mut bytes = Vec::new();
        for i in 0..8192 {
            let byte = self
                .memory
                .read(address.checked_add(i).ok_or(Fault::Read)?, 1)?[0];
            if byte == 0 {
                return Ok(bytes);
            }
            bytes.push(byte);
        }
        Err(Fault::Read.into())
    }
    pub fn call(&mut self, name: &str, arguments: &[u64], budget: usize) -> RuntimeResult<u64> {
        let address = self.symbol(name).ok_or(Fault::UnresolvedImport)?;
        let mut budget = budget;
        self.call_at(
            address,
            arguments,
            STACK + STACK_SIZE as u64,
            &mut budget,
            0,
            Instant::now() + Duration::from_secs(20),
        )
    }
    fn call_at(
        &mut self,
        address: u64,
        arguments: &[u64],
        stack: u64,
        budget: &mut usize,
        depth: usize,
        deadline: Instant,
    ) -> RuntimeResult<u64> {
        if depth >= 16 || arguments.len() > 8 || Instant::now() >= deadline {
            return Err(Fault::BudgetExhausted.into());
        }
        let mut cpu = Cpu {
            pc: address,
            sp: stack & !15,
            tpidr: TLS,
            ..Cpu::default()
        };
        cpu.x[..arguments.len()].copy_from_slice(arguments);
        cpu.x[30] = RETURN;
        let mut steps = 0u32;
        while cpu.pc != RETURN {
            if *budget == 0 || (steps & 1023 == 0 && Instant::now() >= deadline) {
                return Err(RuntimeError {
                    fault: Fault::BudgetExhausted,
                    pc: cpu.pc,
                });
            }
            steps = steps.wrapping_add(1);
            *budget -= 1;
            let result = if let Some(name) = self.traps.get(&cpu.pc).cloned() {
                let result = self.dispatch(&name, &mut cpu, budget, depth, deadline);
                // Explicit developer diagnostics: only static operation names,
                // flags and return status, never paths or guest buffer contents.
                if self.trace_files
                    && matches!(
                        name.as_str(),
                        "open"
                            | "close"
                            | "read"
                            | "write"
                            | "lstat"
                            | "fstat"
                            | "stat"
                            | "chmod"
                            | "mkdir"
                            | "ftruncate"
                    )
                {
                    match &result {
                        Ok(value) if name == "open" => eprintln!(
                            "guest fs: open flags={:#x} result={}",
                            cpu.x[1], *value as i64
                        ),
                        Ok(value) => eprintln!("guest fs: {name} result={}", *value as i64),
                        Err(e) => eprintln!("guest fs: {name} fault={:?}", e.fault),
                    }
                }
                result.map(|value| {
                    cpu.x[0] = value;
                    cpu.pc = cpu.x[30];
                })
            } else {
                cpu.step(&mut self.memory).map_err(RuntimeError::from)
            };
            if let Err(error) = result {
                return Err(RuntimeError {
                    fault: error.fault,
                    pc: cpu.pc,
                });
            }
        }
        Ok(cpu.x[0])
    }
    fn length(value: u64, budget: &mut usize) -> RuntimeResult<usize> {
        let size = usize::try_from(value).map_err(|_| Fault::Read)?;
        if size > MAX_BUFFER {
            return Err(Fault::Read.into());
        }
        *budget = budget
            .checked_sub(size / 16)
            .ok_or(Fault::BudgetExhausted)?;
        Ok(size)
    }
    fn dispatch(
        &mut self,
        name: &str,
        cpu: &mut Cpu,
        budget: &mut usize,
        depth: usize,
        deadline: Instant,
    ) -> RuntimeResult<u64> {
        let [a, b, c, ..] = cpu.x;
        let zero = matches!(
            name,
            "pthread_mutex_init"
                | "pthread_mutex_destroy"
                | "pthread_mutex_lock"
                | "pthread_mutex_trylock"
                | "pthread_mutex_unlock"
                | "pthread_rwlock_init"
                | "pthread_rwlock_destroy"
                | "pthread_rwlock_rdlock"
                | "pthread_rwlock_wrlock"
                | "pthread_rwlock_unlock"
        );
        if zero || matches!(name, "dlclose" | "__cxa_atexit" | "__cxa_finalize") {
            return Ok(0);
        }
        Ok(match name {
            "open" => {
                // O_LARGEFILE is meaningful in the Android ABI even on a host
                // whose native 64-bit libc defines that flag as zero.
                if b & !(3 | 0x40 | 0x80 | 0x200 | 0x400 | 0x8000 | 0x80000 | 0x20000) != 0
                    || b & 3 == 3
                {
                    return self.errno(22);
                }
                let Some(path) = self.path(a)? else {
                    return self.errno(2);
                };
                if self.files.len() >= 32 {
                    return self.errno(24);
                }
                let mut options = OpenOptions::new();
                options
                    .read(b & 3 != 1)
                    .write(b & 3 != 0)
                    .create(b & 0x40 != 0)
                    .create_new(b & 0xc0 == 0xc0)
                    .truncate(b & 0x200 != 0)
                    .append(b & 0x400 != 0);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                }
                match options.open(path) {
                    Ok(mut file) => {
                        match file.metadata() {
                            Ok(metadata)
                                if !metadata.is_file() || metadata.len() > MAX_BUFFER as u64 =>
                            {
                                return self.errno(27);
                            }
                            Err(e) => return self.io_error(e),
                            _ => {}
                        }
                        if b & 0x400 != 0 {
                            if let Err(e) = file.seek(SeekFrom::End(0)) {
                                return self.io_error(e);
                            }
                        }

                        let fd = (3..35).find(|fd| !self.files.contains_key(fd)).unwrap();
                        self.files.insert(
                            fd,
                            GuestFile {
                                file,
                                append: b & 0x400 != 0,
                            },
                        );
                        fd as u64
                    }
                    Err(error) => return self.io_error(error),
                }
            }
            "close" => {
                if self.files.remove(&(a as u32)).is_some() {
                    0
                } else {
                    return self.errno(9);
                }
            }
            "read" => {
                let size = Self::length(c, budget)?;
                if size == 0 {
                    return Ok(0);
                }
                let (region, _) = self.memory.region(b, size).ok_or(Fault::Write)?;
                if !self.memory.regions[region].permissions.write {
                    return Err(Fault::Write.into());
                }
                let Some(file) = self.files.get_mut(&(a as u32)) else {
                    return self.errno(9);
                };
                let mut bytes = vec![0; size];
                match file.file.read(&mut bytes) {
                    Ok(count) => {
                        self.memory.write(b, &bytes[..count])?;
                        count as u64
                    }
                    Err(error) => return self.io_error(error),
                }
            }
            "write" => {
                let size = Self::length(c, budget)?;
                if size == 0 {
                    return Ok(0);
                }
                let bytes = self.memory.read(b, size)?.to_vec();
                let Some(file) = self.files.get_mut(&(a as u32)) else {
                    return self.errno(9);
                };
                let offset = match if file.append {
                    file.file.metadata().map(|m| m.len())
                } else {
                    file.file.stream_position()
                } {
                    Ok(n) => n,
                    Err(e) => return self.io_error(e),
                };
                if offset
                    .checked_add(size as u64)
                    .is_none_or(|end| end > MAX_BUFFER as u64)
                {
                    return self.errno(27);
                }
                match file.file.write(&bytes) {
                    Ok(count) => count as u64,
                    Err(error) => return self.io_error(error),
                }
            }
            "lstat" | "stat" => {
                let Some(path) = (if self.string(a)? == b"/adi" {
                    self.storage.clone()
                } else {
                    self.path(a)?
                }) else {
                    return self.errno(2);
                };
                match fs::metadata(path) {
                    Ok(metadata) => return self.stat(b, &metadata),
                    Err(error) => return self.io_error(error),
                }
            }
            "fstat" => {
                let Some(file) = self.files.get(&(a as u32)) else {
                    return self.errno(9);
                };
                match file.file.metadata() {
                    Ok(metadata) => return self.stat(b, &metadata),
                    Err(error) => return self.io_error(error),
                }
            }
            "ftruncate" => {
                if b > MAX_BUFFER as u64 {
                    return self.errno(22);
                }
                let Some(file) = self.files.get_mut(&(a as u32)) else {
                    return self.errno(9);
                };
                match file.file.set_len(b) {
                    Ok(()) => 0,
                    Err(error) => return self.io_error(error),
                }
            }
            "mkdir" => {
                if self.string(a)? == b"/adi" && self.storage.is_some() {
                    return self.errno(17);
                } else {
                    return self.errno(13);
                }
            }
            "chmod" => {
                let is_root = self.string(a)? == b"/adi";
                let Some(path) = (if is_root {
                    self.storage.clone()
                } else {
                    self.path(a)?
                }) else {
                    return self.errno(2);
                };
                if !path.exists() {
                    return self.errno(2);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) = fs::set_permissions(
                        path,
                        fs::Permissions::from_mode(if is_root { 0o700 } else { 0o600 }),
                    ) {
                        return self.io_error(error);
                    }
                }
                0
            }
            "umask" => 0o077, // never alter the host process's umask
            "__errno" => TLS + 256,
            "pthread_create" => 38,
            "pthread_once" => {
                let state = self.memory.load(a, 4)?;
                if state == 0 {
                    self.memory.store(a, 4, 1)?;
                    self.call_at(
                        b,
                        &[],
                        cpu.sp.checked_sub(256).ok_or(Fault::Write)?,
                        budget,
                        depth + 1,
                        deadline,
                    )?;
                    self.memory.store(a, 4, 2)?;
                } else if state != 2 {
                    return Err(Fault::UnresolvedImport.into());
                }
                0
            }
            "dlopen" => {
                if self.string(a)?.ends_with(b"/libCoreADI.so")
                    || self.string(a)? == b"libCoreADI.so"
                {
                    CORE
                } else {
                    0
                }
            }
            "dlsym" => {
                let symbol = self.string(b)?;
                if a == CORE {
                    std::str::from_utf8(&symbol)
                        .ok()
                        .and_then(|s| self.core_symbols.get(s))
                        .copied()
                        .unwrap_or(0)
                } else {
                    0
                }
            }
            "malloc" | "calloc" => {
                let size = if name == "calloc" {
                    a.checked_mul(b).ok_or(Fault::Mapping)?
                } else {
                    a
                };
                let size = Self::length(size, budget)?;
                let address = self.allocate(size)?;
                if name == "calloc" {
                    self.memory.write(address, &vec![0; size])?;
                }
                address
            }
            "realloc" => {
                let size = Self::length(b, budget)?;
                if size == 0 {
                    self.release(a)?;
                    0
                } else {
                    let old = if a == 0 {
                        0
                    } else {
                        *self.allocated.get(&a).ok_or(Fault::Read)?
                    };
                    let bytes = if old == 0 {
                        Vec::new()
                    } else {
                        self.memory.read(a, old.min(size))?.to_vec()
                    };
                    let address = self.allocate(size)?;
                    self.memory.write(address, &bytes)?;
                    self.release(a)?;
                    address
                }
            }
            "free" => {
                self.release(a)?;
                0
            }
            "memcpy" | "memmove" => {
                let size = Self::length(c, budget)?;
                if size != 0 {
                    let bytes = self.memory.read(b, size)?.to_vec();
                    self.memory.write(a, &bytes)?;
                }
                a
            }
            "memset" => {
                let size = Self::length(c, budget)?;
                if size != 0 {
                    self.memory.write(a, &vec![b as u8; size])?;
                }
                a
            }
            "memcmp" => {
                let size = Self::length(c, budget)?;
                if size == 0 {
                    return Ok(0);
                }
                let x = self.memory.read(a, size)?;
                let y = self.memory.read(b, size)?;
                x.iter()
                    .zip(y)
                    .find_map(|(a, b)| (*a != *b).then_some((*a as i32 - *b as i32) as u32 as u64))
                    .unwrap_or(0)
            }
            "strlen" => self.string(a)?.len() as u64,
            "strcpy" | "strncpy" => {
                let mut bytes = if name == "strcpy" {
                    let mut v = self.string(b)?;
                    v.push(0);
                    v
                } else {
                    let n = Self::length(c, budget)?;
                    let mut v = vec![0; n];
                    for (i, out) in v.iter_mut().enumerate() {
                        *out = self
                            .memory
                            .read(b.checked_add(i as u64).ok_or(Fault::Read)?, 1)?[0];
                        if *out == 0 {
                            break;
                        }
                    }
                    v
                };
                if !bytes.is_empty() {
                    self.memory.write(a, &bytes)?;
                }
                bytes.fill(0);
                a
            }
            "strcmp" | "strncmp" => {
                let limit = if name == "strncmp" {
                    Self::length(c, budget)?
                } else {
                    8192
                };
                let mut comparison = 0;
                for i in 0..limit {
                    let x = self
                        .memory
                        .read(a.checked_add(i as u64).ok_or(Fault::Read)?, 1)?[0];
                    let y = self
                        .memory
                        .read(b.checked_add(i as u64).ok_or(Fault::Read)?, 1)?[0];
                    comparison = x as i32 - y as i32;
                    if comparison != 0 || x == 0 {
                        break;
                    }
                    if i == 8191 && name == "strcmp" {
                        return Err(Fault::Read.into());
                    }
                }
                comparison as u32 as u64
            }
            "__system_property_get" => {
                let v = b"no s/n number\0";
                self.memory.write(b, v)?;
                (v.len() - 1) as u64
            }
            "arc4random" => {
                let bytes = sideload::crypto::random_bytes(4).map_err(|_| Fault::Read)?;
                u32::from_le_bytes(bytes.try_into().unwrap()) as u64
            }
            "gettimeofday" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Fault::Read)?;
                if a != 0 {
                    self.memory.store(a, 8, now.as_secs())?;
                    self.memory.store(a + 8, 8, now.subsec_micros() as u64)?;
                }
                if b != 0 {
                    self.memory.write(b, &[0; 8])?;
                }
                0
            }
            _ => return Err(Fault::UnresolvedImport.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn runtime() -> Runtime {
        let bytes = crate::emulation::elf::tests::fixture();
        Runtime::new(&bytes, &bytes).unwrap()
    }
    fn invoke(runtime: &mut Runtime, name: &str, args: &[u64]) -> RuntimeResult<u64> {
        let mut cpu = Cpu::default();
        cpu.x[..args.len()].copy_from_slice(args);
        runtime.dispatch(
            name,
            &mut cpu,
            &mut 100_000,
            0,
            Instant::now() + Duration::from_secs(20),
        )
    }
    fn temp() -> PathBuf {
        let suffix = sideload::crypto::hex(&sideload::crypto::random_bytes(8).unwrap());
        let path = std::env::temp_dir().join(format!("sideload-guest-test-{suffix}"));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        path
    }
    #[test]
    fn checked_heap_reuses_coalesces_and_rejects_invalid_frees() {
        let mut rt = runtime();
        let a = rt.allocate(5).unwrap();
        let b = rt.allocate(32).unwrap();
        assert_eq!(b - a, 16);
        assert!(rt.release(a + 1).is_err());
        rt.release(a).unwrap();
        assert!(rt.release(a).is_err());
        rt.release(b).unwrap();
        assert_eq!(rt.free.len(), 1);
        assert_eq!(rt.allocate(48).unwrap(), a);
        assert!(rt.allocate(MAX_BUFFER + 1).is_err());
        assert!(invoke(&mut rt, "calloc", &[u64::MAX, 2]).is_err());
    }
    #[test]
    fn guest_memory_copy_strings_and_resize() {
        let mut rt = runtime();
        let a = rt.buffer(b"original\0").unwrap();
        let b = rt.allocate(64).unwrap();
        assert_eq!(invoke(&mut rt, "strlen", &[a]).unwrap(), 8);
        invoke(&mut rt, "strncpy", &[b, a, 16]).unwrap();
        assert_eq!(rt.memory.read(b, 16).unwrap(), b"original\0\0\0\0\0\0\0\0");
        invoke(&mut rt, "memmove", &[b + 1, b, 8]).unwrap();
        assert_eq!(rt.memory.read(b, 9).unwrap(), b"ooriginal");
        let resized = invoke(&mut rt, "realloc", &[b, 128]).unwrap();
        assert_eq!(rt.memory.read(resized, 9).unwrap(), b"ooriginal");
        assert!(invoke(&mut rt, "memcpy", &[0x1234, a, 9]).is_err());
        assert!(invoke(&mut rt, "realloc", &[0x1234, 20]).is_err());
        assert!(invoke(&mut rt, "memset", &[a, 0, MAX_BUFFER as u64 + 1]).is_err());
    }
    #[test]
    fn files_are_confined_and_stat_uses_android_layout() {
        let path = temp();
        let mut rt = runtime();
        rt.set_storage(&path).unwrap();
        let filename = rt.c_string("/adi/adi.pb").unwrap();
        let bytes = rt.buffer(b"test provisioning state").unwrap();
        let fd = invoke(&mut rt, "open", &[filename, 2 | 0x40 | 0x8000, 0o666]).unwrap();
        assert!((3..35).contains(&fd));
        assert_eq!(invoke(&mut rt, "write", &[fd, bytes, 23]).unwrap(), 23);
        let output = rt.allocate(128).unwrap();
        assert_eq!(invoke(&mut rt, "fstat", &[fd, output]).unwrap(), 0);
        assert_eq!(rt.memory.load(output + 48, 8).unwrap(), 23);
        assert_eq!(rt.memory.load(output + 16, 4).unwrap(), 0o100600);
        assert_eq!(invoke(&mut rt, "close", &[fd]).unwrap(), 0);
        assert_eq!(
            fs::read(path.join("adi.pb")).unwrap(),
            b"test provisioning state"
        );
        let fd = invoke(&mut rt, "open", &[filename, 0]).unwrap();
        assert_eq!(invoke(&mut rt, "read", &[fd, output, 128]).unwrap(), 23);
        assert_eq!(
            rt.memory.read(output, 23).unwrap(),
            b"test provisioning state"
        );
        invoke(&mut rt, "close", &[fd]).unwrap();
        for filename in [
            "/etc/passwd",
            "../outside",
            "/adi/../outside",
            "/adi/nested/file",
            ".",
            "..",
        ] {
            let name = rt.c_string(filename).unwrap();
            assert!(invoke(&mut rt, "open", &[name, 2 | 0x40]).is_err());
        }
        let name = rt.c_string("missing").unwrap();
        assert_eq!(invoke(&mut rt, "open", &[name, 0]).unwrap(), u64::MAX);
        assert_eq!(rt.memory.load(TLS + 256, 4).unwrap(), 2);
        let fd = invoke(&mut rt, "open", &[filename, 1 | 0x400]).unwrap();
        invoke(&mut rt, "ftruncate", &[fd, MAX_BUFFER as u64]).unwrap();
        assert_eq!(invoke(&mut rt, "write", &[fd, bytes, 1]).unwrap(), u64::MAX);
        assert_eq!(
            fs::metadata(path.join("adi.pb")).unwrap().len(),
            MAX_BUFFER as u64
        );
        invoke(&mut rt, "close", &[fd]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            assert_eq!(
                fs::metadata(path.join("adi.pb"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            symlink("/etc/passwd", path.join("link")).unwrap();
            let name = rt.c_string("link").unwrap();
            assert!(invoke(&mut rt, "open", &[name, 0]).is_err());
        }
        drop(rt);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn virtual_import_executes_and_unknown_imports_trap() {
        let mut bytes = crate::emulation::elf::tests::fixture();
        bytes[96..104].copy_from_slice(&0x100cu64.to_le_bytes()); // segment file size
        bytes[104..112].copy_from_slice(&0x100cu64.to_le_bytes()); // segment memory size
        bytes[0x428..0x430].copy_from_slice(&12u64.to_le_bytes()); // symbol size
        for (i, word) in [0xaa0003e8u32, 0xaa0103e0, 0xd61f0100]
            .into_iter()
            .enumerate()
        {
            bytes[0x1000 + 4 * i..0x1004 + 4 * i].copy_from_slice(&word.to_le_bytes());
        }
        let mut rt = Runtime::new(&bytes, &bytes).unwrap();
        rt.traps.insert(TRAPS, "strlen".into());
        let string = rt.c_string("hello").unwrap();
        assert_eq!(rt.call("answer", &[TRAPS, string], 10).unwrap(), 5);
        rt.traps.insert(TRAPS, "unsupported".into());
        assert_eq!(
            rt.call("answer", &[TRAPS, string], 10).unwrap_err().fault,
            Fault::UnresolvedImport
        );
        assert_eq!(
            rt.call("answer", &[TRAPS, string], 2).unwrap_err().fault,
            Fault::BudgetExhausted
        );
        assert!(invoke(&mut rt, "pthread_mutex_unknown", &[]).is_err());
        let mut budget = 10;
        assert_eq!(
            rt.call_at(
                STORE + 0x1000,
                &[],
                STACK + STACK_SIZE as u64,
                &mut budget,
                0,
                Instant::now() - Duration::from_secs(1)
            )
            .unwrap_err()
            .fault,
            Fault::BudgetExhausted
        );
    }
}
