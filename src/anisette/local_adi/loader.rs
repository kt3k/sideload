//! Private executable mappings and ELF relocation. No ELF constructors run:
//! only the ADI entry points and their explicit initialization are supported.
use super::{AdiResult, elf::Elf, fail, hooks};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc};
pub struct Library {
    memory: *mut libc::c_void,
    length: usize,
    exports: BTreeMap<String, usize>,
    _single_thread: PhantomData<Rc<()>>,
}
impl Library {
    pub fn load(bytes: &[u8], dependencies: &[&Library]) -> AdiResult<Self> {
        let elf = Elf::parse(bytes)?;
        let expected = if cfg!(target_arch = "x86_64") {
            62
        } else {
            183
        };
        if elf.machine != expected {
            return Err(fail("ADI ELF architecture does not match host"));
        }
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page < 4096 || !(page as usize).is_power_of_two() {
            return Err(fail("unsupported host page size"));
        }
        let page = page as usize;
        let length = (elf.span + page - 1) & !(page - 1);
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if memory == libc::MAP_FAILED {
            return Err(fail("cannot map ADI library"));
        }
        let mut library = Self {
            memory,
            length,
            exports: BTreeMap::new(),
            _single_thread: PhantomData,
        };
        let base = memory as usize;
        let mut protections = vec![0; length / page];
        for s in &elf.segments {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(s.offset),
                    (base + s.address) as *mut u8,
                    s.file_size,
                );
            }
            let prot = if s.flags & 4 != 0 { libc::PROT_READ } else { 0 }
                | if s.flags & 2 != 0 {
                    libc::PROT_WRITE
                } else {
                    0
                }
                | if s.flags & 1 != 0 { libc::PROT_EXEC } else { 0 };
            if s.memory_size > 0 {
                for protection in
                    &mut protections[s.address / page..(s.address + s.memory_size).div_ceil(page)]
                {
                    *protection |= prot;
                }
            }
        }
        let mut addresses = Vec::new();
        for s in &elf.symbols {
            let address = if s.defined {
                if s.absolute {
                    s.address
                } else {
                    if s.address.checked_add(s.size).is_none_or(|e| e > elf.span) {
                        return Err(fail("ELF defined symbol outside mapping"));
                    }
                    base + s.address
                }
            } else if s.name.is_empty() {
                0
            } else {
                hooks::resolve(&s.name)
                    .or_else(|| dependencies.iter().find_map(|l| l.symbol(&s.name)))
                    .unwrap_or(if s.weak {
                        0
                    } else {
                        hooks::unresolved_address()
                    })
            };
            addresses.push(address);
            if s.defined && !s.name.is_empty() {
                library.exports.insert(s.name.clone(), address);
            }
        }
        for r in &elf.relocations {
            let target = (base + r.address) as *mut usize;
            let addend = r
                .addend
                .unwrap_or_else(|| unsafe { target.read_unaligned() } as i64)
                as usize;
            let value = match (elf.machine, r.kind) {
                (_, 0) => continue,
                (62, 8) | (183, 1027) => base.wrapping_add(addend),
                (62, 1) | (183, 257) => addresses[r.symbol].wrapping_add(addend),
                (62, 6 | 7) | (183, 1025 | 1026) => {
                    addresses[r.symbol].wrapping_add(if elf.machine == 183 { addend } else { 0 })
                }
                _ => return Err(fail(format!("unsupported ADI relocation {}", r.kind))),
            };
            unsafe {
                target.write_unaligned(value);
            }
        }
        for (i, &prot) in protections.iter().enumerate() {
            if prot & libc::PROT_EXEC != 0 && prot & libc::PROT_WRITE != 0 {
                return Err(fail(
                    "host pages combine writable and executable ADI segments",
                ));
            }
            if unsafe { libc::mprotect((base + i * page) as *mut _, page, prot) } != 0 {
                return Err(fail("cannot protect ADI mapping"));
            }
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // Synchronize freshly generated executable pages with the I-cache.
            let ctr: u64;
            core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr);
            let dline = 4usize << ((ctr >> 16) & 15);
            let iline = 4usize << (ctr & 15);
            for (i, &p) in protections.iter().enumerate() {
                if p & libc::PROT_EXEC != 0 {
                    for a in (base + i * page..base + (i + 1) * page).step_by(dline) {
                        core::arch::asm!("dc cvau, {}",in(reg)a);
                    }
                    core::arch::asm!("dsb ish");
                    for a in (base + i * page..base + (i + 1) * page).step_by(iline) {
                        core::arch::asm!("ic ivau, {}",in(reg)a);
                    }
                }
            }
            core::arch::asm!("dsb ish", "isb");
        }
        Ok(library)
    }
    pub fn symbol(&self, name: &str) -> Option<usize> {
        self.exports.get(name).copied()
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.memory, self.length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_code_and_relative_relocation() {
        let lib = Library::load(&super::super::elf::tests::fixture(), &[]).unwrap();
        let answer = lib.symbol("answer").unwrap();
        let function: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(answer) };
        assert_eq!(unsafe { function() }, 42);
        let pointer = lib.symbol("relocated").unwrap();
        assert_eq!(unsafe { (pointer as *const usize).read() }, answer);
    }
    #[test]
    fn unsupported_relocation_rejected() {
        let mut b = super::super::elf::tests::fixture();
        b[0x508..0x510].copy_from_slice(&99999u64.to_le_bytes());
        assert!(Library::load(&b, &[]).is_err());
    }
}
