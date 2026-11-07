//! Checked thin/fat Mach-O parsing and embedded signature placement.
//! Load commands are never shifted into executable code: a new command needs
//! existing header padding. Encrypted App Store binaries must be decrypted first.
use super::{SignResult, fail};
fn read32(b: &[u8], p: usize, be: bool) -> SignResult<u32> {
    let a = b
        .get(p..p + 4)
        .ok_or_else(|| fail("truncated Mach-O"))?
        .try_into()
        .unwrap();
    Ok(if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    })
}
fn read64(b: &[u8], p: usize, be: bool) -> SignResult<u64> {
    let a = b
        .get(p..p + 8)
        .ok_or_else(|| fail("truncated Mach-O"))?
        .try_into()
        .unwrap();
    Ok(if be {
        u64::from_be_bytes(a)
    } else {
        u64::from_le_bytes(a)
    })
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn aligned(n: usize, a: usize) -> SignResult<usize> {
    n.checked_add(a - 1)
        .map(|n| n & !(a - 1))
        .ok_or_else(|| fail("Mach-O size overflow"))
}
#[derive(Debug)]
pub struct Prepared {
    pub code: Vec<u8>,
    pub signature_offset: usize,
    pub executable_segment: (u64, u64, u64),
    signature_command: usize,
    linkedit: usize,
    wide: bool,
}
impl Prepared {
    /// Finalize load commands before hashing. Signature capacity may exceed the
    /// actual SuperBlob size; its trailing bytes are zero-filled.
    pub fn reserve(&mut self, capacity: usize) -> SignResult<()> {
        let end = self
            .signature_offset
            .checked_add(capacity)
            .ok_or_else(|| fail("signature size overflow"))?;
        let size = u32::try_from(capacity).map_err(|_| fail("signature too large"))?;
        let end32 = u32::try_from(end).map_err(|_| fail("Mach-O slice exceeds 4 GiB"))?;
        put32(&mut self.code, self.signature_command + 12, size);
        let p = self.linkedit;
        let start = if self.wide {
            read64(&self.code, p + 40, false)?
        } else {
            read32(&self.code, p + 32, false)? as u64
        };
        let filesize = (end32 as u64)
            .checked_sub(start)
            .ok_or_else(|| fail("invalid __LINKEDIT file offset"))?;
        let vmsize = aligned(filesize as usize, 16384)? as u64;
        if self.wide {
            put64(&mut self.code, p + 32, vmsize);
            put64(&mut self.code, p + 48, filesize);
        } else {
            put32(
                &mut self.code,
                p + 28,
                u32::try_from(vmsize).map_err(|_| fail("segment too large"))?,
            );
            put32(&mut self.code, p + 36, filesize as u32);
        }
        Ok(())
    }
    pub fn finish(mut self, signature: &[u8], capacity: usize) -> SignResult<Vec<u8>> {
        if signature.len() > capacity {
            return Err(fail("signature exceeds reserved capacity"));
        }
        self.code.extend(signature);
        self.code.resize(self.signature_offset + capacity, 0);
        Ok(self.code)
    }
}
/// Thin 32/64-bit little-endian Mach-O magic.
pub fn is_thin_macho(data: &[u8]) -> bool {
    matches!(data.get(..4), Some([0xce | 0xcf, 0xfa, 0xed, 0xfe]))
}

/// A fat header magic. `0xCAFEBABE` is also the Java class file magic, so a
/// match alone does not identify a Mach-O; see `looks_like_fat_macho`.
pub fn is_fat_magic(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some([0xca, 0xfe, 0xba, 0xbe | 0xbf] | [0xbe | 0xbf, 0xba, 0xfe, 0xca])
    )
}

/// Real universal binaries have a small architecture table whose entries
/// point at thin Mach-O slices inside the file.
pub fn looks_like_fat_macho(data: &[u8]) -> bool {
    let (be, wide) = match data.get(..4) {
        Some([0xca, 0xfe, 0xba, 0xbe]) => (true, false),
        Some([0xbe, 0xba, 0xfe, 0xca]) => (false, false),
        Some([0xca, 0xfe, 0xba, 0xbf]) => (true, true),
        Some([0xbf, 0xba, 0xfe, 0xca]) => (false, true),
        _ => return false,
    };
    let Ok(n) = read32(data, 4, be) else {
        return false;
    };
    let stride = if wide { 32 } else { 20 };
    if n == 0 || n > 16 {
        return false;
    }
    (0..n as usize).all(|i| {
        let p = 8 + i * stride;
        let off = if wide {
            read64(data, p + 8, be)
        } else {
            read32(data, p + 8, be).map(u64::from)
        };
        let size = if wide {
            read64(data, p + 16, be)
        } else {
            read32(data, p + 12, be).map(u64::from)
        };
        match (off, size) {
            (Ok(off), Ok(size)) => {
                off.checked_add(size)
                    .is_some_and(|end| end <= data.len() as u64)
                    && usize::try_from(off).is_ok_and(|o| is_thin_macho(&data[o..]))
            }
            _ => false,
        }
    })
}

pub fn prepare(data: &[u8]) -> SignResult<Prepared> {
    let wide = match data.get(..4) {
        Some([0xcf, 0xfa, 0xed, 0xfe]) => true,
        Some([0xce, 0xfa, 0xed, 0xfe]) => false,
        _ => return Err(fail("unsupported thin Mach-O byte order or magic")),
    };
    let header: usize = if wide { 32 } else { 28 };
    let n = read32(data, 16, false)? as usize;
    let commands = read32(data, 20, false)? as usize;
    let end = header
        .checked_add(commands)
        .filter(|&x| x <= data.len())
        .ok_or_else(|| fail("invalid load command size"))?;
    if n > commands / 8 {
        return Err(fail("invalid load command count"));
    }
    let mut p = header;
    let mut signature = None;
    let mut linkedit = None;
    let mut first_section = data.len();
    let mut exec = (0, 0, u64::from(read32(data, 12, false)? == 2));
    for _ in 0..n {
        let cmd = read32(data, p, false)?;
        let len = read32(data, p + 4, false)? as usize;
        if len < 8 || len % 4 != 0 || p.checked_add(len).is_none_or(|x| x > end) {
            return Err(fail("invalid load command"));
        }
        match cmd {
            0x1d => {
                if len != 16 || signature.is_some() {
                    return Err(fail("invalid code signature command"));
                }
                signature = Some(p);
            }
            0x21 | 0x2c => {
                if len < 20 {
                    return Err(fail("truncated encryption command"));
                }
                if read32(data, p + 16, false)? != 0 {
                    return Err(fail("encrypted Mach-O cannot be re-signed"));
                }
            }
            1 | 0x19 => {
                let w = cmd == 0x19;
                let base = if w { 72 } else { 56 };
                let section_size = if w { 80 } else { 68 };
                if w != wide || len < base {
                    return Err(fail("invalid segment command"));
                }
                let sections = read32(data, p + if w { 64 } else { 48 }, false)? as usize;
                if sections > (len - base) / section_size {
                    return Err(fail("truncated section table"));
                }
                let name = &data[p + 8..p + 24];
                let offset = if w {
                    read64(data, p + 40, false)?
                } else {
                    read32(data, p + 32, false)? as u64
                };
                let filesize = if w {
                    read64(data, p + 48, false)?
                } else {
                    read32(data, p + 36, false)? as u64
                };
                if offset
                    .checked_add(filesize)
                    .is_none_or(|x| x > data.len() as u64)
                {
                    return Err(fail("segment extends past file"));
                }
                if offset > 0 {
                    first_section = first_section.min(offset as usize);
                }
                if name.starts_with(b"__LINKEDIT\0") {
                    if linkedit.replace(p).is_some() {
                        return Err(fail("duplicate __LINKEDIT"));
                    }
                    if offset + filesize != data.len() as u64 {
                        return Err(fail("__LINKEDIT must be the final segment"));
                    }
                }
                if name.starts_with(b"__TEXT\0") {
                    exec.0 = offset;
                    exec.1 = filesize;
                }
                for i in 0..sections {
                    let s = p + base + i * section_size;
                    let flags = read32(data, s + if w { 64 } else { 56 }, false)? & 0xff;
                    if !matches!(flags, 1 | 0xc | 0x12) {
                        let off = read32(data, s + if w { 48 } else { 40 }, false)? as usize;
                        if off > 0 {
                            first_section = first_section.min(off);
                        }
                    }
                }
            }
            _ => {}
        }
        p += len;
    }
    if p != end {
        return Err(fail("load commands do not fill sizeofcmds"));
    }
    let linkedit = linkedit.ok_or_else(|| fail("missing __LINKEDIT segment"))?;
    let mut code = data.to_vec();
    let (command, offset) = if let Some(s) = signature {
        let off = read32(data, s + 8, false)? as usize;
        let size = read32(data, s + 12, false)? as usize;
        let linkstart = if wide {
            read64(data, linkedit + 40, false)? as usize
        } else {
            read32(data, linkedit + 32, false)? as usize
        };
        if off < end || off < linkstart || off.checked_add(size) != Some(data.len()) {
            return Err(fail("existing signature is not at end of __LINKEDIT"));
        }
        code.truncate(off);
        (s, off)
    } else {
        if end + 16 > first_section
            || data
                .get(end..end + 16)
                .is_none_or(|b| b.iter().any(|&x| x != 0))
        {
            return Err(fail("no header padding for LC_CODE_SIGNATURE"));
        }
        put32(&mut code, 16, (n + 1) as u32);
        put32(&mut code, 20, (commands + 16) as u32);
        put32(&mut code, end, 0x1d);
        put32(&mut code, end + 4, 16);
        let off = aligned(data.len(), 16)?;
        code.resize(off, 0);
        (end, off)
    };
    put32(
        &mut code,
        command + 8,
        u32::try_from(offset).map_err(|_| fail("Mach-O slice too large"))?,
    );
    Ok(Prepared {
        code,
        signature_offset: offset,
        executable_segment: exec,
        signature_command: command,
        linkedit,
        wide,
    })
}
/// Sign each architecture independently and rebuild fat offsets and sizes.
pub fn sign_slices<F>(data: &[u8], mut sign: F) -> SignResult<Vec<u8>>
where
    F: FnMut(Prepared) -> SignResult<Vec<u8>>,
{
    let (be, wide) = match data.get(..4) {
        Some([0xca, 0xfe, 0xba, 0xbe]) => (true, false),
        Some([0xbe, 0xba, 0xfe, 0xca]) => (false, false),
        Some([0xca, 0xfe, 0xba, 0xbf]) => (true, true),
        Some([0xbf, 0xba, 0xfe, 0xca]) => (false, true),
        _ => return sign(prepare(data)?),
    };
    let n = read32(data, 4, be)? as usize;
    let stride = if wide { 32 } else { 20 };
    if n == 0 || n > (data.len().saturating_sub(8)) / stride {
        return Err(fail("invalid fat architecture table"));
    }
    let table_end = 8 + n * stride;
    let mut out = data[..table_end].to_vec();
    let mut ranges = Vec::new();
    for i in 0..n {
        let p = 8 + i * stride;
        let off = if wide {
            read64(data, p + 8, be)?
        } else {
            read32(data, p + 8, be)? as u64
        };
        let size = if wide {
            read64(data, p + 16, be)?
        } else {
            read32(data, p + 12, be)? as u64
        };
        let align = read32(data, p + if wide { 24 } else { 16 }, be)?;
        if align > 20 {
            return Err(fail("fat alignment exceeds 1 MiB"));
        }
        let end = off
            .checked_add(size)
            .filter(|&x| x <= data.len() as u64)
            .ok_or_else(|| fail("fat slice outside file"))?;
        if off < table_end as u64
            || off % (1u64 << align) != 0
            || ranges.iter().any(|&(a, b)| off < b && end > a)
        {
            return Err(fail("overlapping or unaligned fat slice"));
        }
        ranges.push((off, end));
        let slice = &data[off as usize..end as usize];
        if read32(slice, 4, false)? != read32(data, p, be)?
            || read32(slice, 8, false)? != read32(data, p + 4, be)?
        {
            return Err(fail("fat architecture does not match slice"));
        }
        let signed = sign(prepare(slice)?)?;
        let newoff = aligned(out.len(), 1usize << align)?;
        out.resize(newoff, 0);
        out.extend(&signed);
        let write = |out: &mut Vec<u8>, at: usize, v: u64, w: bool| -> SignResult<()> {
            let bytes = if w {
                if be {
                    v.to_be_bytes().to_vec()
                } else {
                    v.to_le_bytes().to_vec()
                }
            } else {
                let v = u32::try_from(v).map_err(|_| fail("fat offset exceeds u32"))?;
                if be {
                    v.to_be_bytes().to_vec()
                } else {
                    v.to_le_bytes().to_vec()
                }
            };
            out[at..at + bytes.len()].copy_from_slice(&bytes);
            Ok(())
        };
        write(&mut out, p + 8, newoff as u64, wide)?;
        write(
            &mut out,
            p + if wide { 16 } else { 12 },
            signed.len() as u64,
            wide,
        )?;
    }
    Ok(out)
}
