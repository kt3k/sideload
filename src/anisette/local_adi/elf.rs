//! Checked ELF64 little-endian shared-object metadata, from the ELF ABI.
use super::{AdiResult, fail};
use std::collections::BTreeMap;
fn word<const N: usize>(b: &[u8], p: usize) -> AdiResult<[u8; N]> {
    b.get(p..p.checked_add(N).ok_or_else(|| fail("ELF overflow"))?)
        .ok_or_else(|| fail("truncated ELF"))?
        .try_into()
        .map_err(|_| fail("ELF word"))
}
fn u16le(b: &[u8], p: usize) -> AdiResult<u16> {
    Ok(u16::from_le_bytes(word(b, p)?))
}
fn u32le(b: &[u8], p: usize) -> AdiResult<u32> {
    Ok(u32::from_le_bytes(word(b, p)?))
}
fn u64le(b: &[u8], p: usize) -> AdiResult<u64> {
    Ok(u64::from_le_bytes(word(b, p)?))
}
#[derive(Debug, Clone)]
pub struct Segment {
    pub offset: usize,
    pub address: usize,
    pub file_size: usize,
    pub memory_size: usize,
    pub flags: u32,
}
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: usize,
    pub size: usize,
    pub defined: bool,
    pub absolute: bool,
    pub weak: bool,
}
#[derive(Debug, Clone)]
pub struct Relocation {
    pub address: usize,
    pub symbol: usize,
    pub kind: u32,
    pub addend: Option<i64>,
}
#[derive(Debug)]
pub struct Elf {
    pub machine: u16,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub span: usize,
}
impl Elf {
    pub fn parse(b: &[u8]) -> AdiResult<Self> {
        if b.get(..7) != Some(b"\x7fELF\x02\x01\x01") || u16le(b, 16)? != 3 || u32le(b, 20)? != 1 {
            return Err(fail("expected ELF64 little-endian shared object"));
        }
        let machine = u16le(b, 18)?;
        if !matches!(machine, 62 | 183) {
            return Err(fail("unsupported ELF machine"));
        }
        let off = usize::try_from(u64le(b, 32)?).map_err(|_| fail("ELF header overflow"))?;
        let size = u16le(b, 54)? as usize;
        let count = u16le(b, 56)? as usize;
        if size != 56
            || count == 0
            || count > 128
            || off.checked_add(size * count).is_none_or(|e| e > b.len())
        {
            return Err(fail("invalid ELF program headers"));
        }
        let mut segments = Vec::new();
        let mut dynamic = None;
        let mut span = 0;
        for i in 0..count {
            let p = off + i * size;
            let kind = u32le(b, p)?;
            if kind == 7 {
                return Err(fail("ELF PT_TLS is unsupported"));
            }
            if kind != 1 && kind != 2 {
                continue;
            }
            let offset = usize::try_from(u64le(b, p + 8)?).map_err(|_| fail("ELF file offset"))?;
            let address =
                usize::try_from(u64le(b, p + 16)?).map_err(|_| fail("ELF virtual address"))?;
            let file_size =
                usize::try_from(u64le(b, p + 32)?).map_err(|_| fail("ELF file size"))?;
            let memory_size =
                usize::try_from(u64le(b, p + 40)?).map_err(|_| fail("ELF memory size"))?;
            if file_size > memory_size
                || offset.checked_add(file_size).is_none_or(|e| e > b.len())
                || address
                    .checked_add(memory_size)
                    .is_none_or(|e| e > 128 * 1024 * 1024)
            {
                return Err(fail("ELF segment out of bounds"));
            }
            if kind == 2 {
                dynamic = Some((offset, file_size));
            } else {
                span = span.max(address + memory_size);
                segments.push(Segment {
                    offset,
                    address,
                    file_size,
                    memory_size,
                    flags: u32le(b, p + 4)?,
                });
            }
        }
        if segments.is_empty() || span == 0 {
            return Err(fail("ELF has no load segments"));
        }
        for (i, a) in segments.iter().enumerate() {
            for b in &segments[..i] {
                if a.address < b.address + b.memory_size && b.address < a.address + a.memory_size {
                    return Err(fail("overlapping ELF load segments"));
                }
            }
        }
        let range = |address: usize, size: usize| -> AdiResult<&[u8]> {
            let end = address
                .checked_add(size)
                .ok_or_else(|| fail("ELF address overflow"))?;
            let s = segments
                .iter()
                .find(|s| address >= s.address && end <= s.address + s.file_size)
                .ok_or_else(|| fail("ELF dynamic address outside file-backed segment"))?;
            let off = s.offset + address - s.address;
            Ok(&b[off..off + size])
        };
        let (d, ds) = dynamic.ok_or_else(|| fail("ELF missing dynamic section"))?;
        if ds % 16 != 0 {
            return Err(fail("invalid ELF dynamic size"));
        }
        let mut tags = BTreeMap::new();
        for p in (d..d + ds).step_by(16) {
            let tag = u64le(b, p)?;
            if tag == 0 {
                break;
            }
            if matches!(tag,35..=37|0x6000000f..=0x60000012) {
                return Err(fail("packed ELF relocations are unsupported"));
            }
            tags.insert(tag, u64le(b, p + 8)? as usize);
        }
        let tag = |t| {
            tags.get(&t)
                .copied()
                .ok_or_else(|| fail(format!("ELF missing dynamic tag {t}")))
        };
        if tag(11)? != 24 {
            return Err(fail("invalid ELF symbol entry size"));
        }
        let hash = range(tag(4)?, 8)?;
        let ns = u32le(hash, 4)? as usize;
        if ns > 100_000 {
            return Err(fail("ELF symbol count too large"));
        }
        let strings = range(tag(5)?, tag(10)?)?;
        let table = range(tag(6)?, ns * 24)?;
        let mut symbols = Vec::new();
        for i in 0..ns {
            let p = i * 24;
            let name_off = u32le(table, p)? as usize;
            let name = strings
                .get(name_off..)
                .and_then(|s| s.split(|&b| b == 0).next())
                .ok_or_else(|| fail("invalid ELF symbol string"))?;
            let name = std::str::from_utf8(name)
                .map_err(|_| fail("non-UTF8 ELF symbol"))?
                .to_owned();
            let section = u16le(table, p + 6)?;
            symbols.push(Symbol {
                name,
                address: u64le(table, p + 8)? as usize,
                size: u64le(table, p + 16)? as usize,
                defined: section != 0,
                absolute: section == 0xfff1,
                weak: table[p + 4] >> 4 == 2,
            });
        }
        let mut relocations = Vec::new();
        for (addr_tag, size_tag, rela) in [
            (7, 8, true),
            (17, 18, false),
            (23, 2, tags.get(&20).copied().unwrap_or(7) == 7),
        ] {
            let Some(&addr) = tags.get(&addr_tag) else {
                continue;
            };
            let size = tag(size_tag)?;
            let stride = if rela { 24 } else { 16 };
            if size % stride != 0 {
                return Err(fail("invalid ELF relocation table size"));
            }
            let table = range(addr, size)?;
            for p in (0..size).step_by(stride) {
                let info = u64le(table, p + 8)?;
                let symbol = (info >> 32) as usize;
                let address = u64le(table, p)? as usize;
                if symbol >= ns
                    || address.checked_add(8).is_none_or(|e| e > span)
                    || !segments
                        .iter()
                        .any(|s| address >= s.address && address + 8 <= s.address + s.memory_size)
                {
                    return Err(fail("invalid ELF relocation target"));
                }
                relocations.push(Relocation {
                    address,
                    symbol,
                    kind: info as u32,
                    addend: if rela {
                        Some(u64le(table, p + 16)? as i64)
                    } else {
                        None
                    },
                });
            }
        }
        Ok(Self {
            machine,
            segments,
            symbols,
            relocations,
            span,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0x3000];
        fn u16(b: &mut [u8], p: usize, v: u16) {
            b[p..p + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn u32(b: &mut [u8], p: usize, v: u32) {
            b[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn u64(b: &mut [u8], p: usize, v: u64) {
            b[p..p + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        u16(&mut b, 16, 3);
        u16(
            &mut b,
            18,
            if cfg!(target_arch = "aarch64") {
                183
            } else {
                62
            },
        );
        u32(&mut b, 20, 1);
        u64(&mut b, 32, 64);
        u16(&mut b, 54, 56);
        u16(&mut b, 56, 4);
        for (i, (kind, off, size, flags)) in [
            (1, 0, 0x1000, 4),
            (1, 0x1000, 0x1000, 5),
            (1, 0x2000, 0x1000, 6),
            (2, 0x200, 144, 6),
        ]
        .into_iter()
        .enumerate()
        {
            let p = 64 + i * 56;
            u32(&mut b, p, kind);
            u32(&mut b, p + 4, flags);
            u64(&mut b, p + 8, off);
            u64(&mut b, p + 16, off);
            u64(&mut b, p + 32, size);
            u64(&mut b, p + 40, size);
            u64(&mut b, p + 48, 4096);
        }
        for (i, (tag, value)) in [
            (4, 0x300),
            (5, 0x350),
            (10, 18),
            (6, 0x400),
            (11, 24),
            (7, 0x500),
            (8, 24),
            (9, 24),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            u64(&mut b, 0x200 + i * 16, tag);
            u64(&mut b, 0x208 + i * 16, value);
        }
        u32(&mut b, 0x300, 1);
        u32(&mut b, 0x304, 3);
        b[0x350..0x362].copy_from_slice(b"\0answer\0relocated\0");
        for (i, name, addr, size) in [(1, 1, 0x1000, 8), (2, 8, 0x2000, 8)] {
            let p = 0x400 + i * 24;
            u32(&mut b, p, name);
            b[p + 4] = 0x12;
            u16(&mut b, p + 6, 1);
            u64(&mut b, p + 8, addr);
            u64(&mut b, p + 16, size);
        }
        u64(&mut b, 0x500, 0x2000);
        u64(
            &mut b,
            0x508,
            if cfg!(target_arch = "aarch64") {
                1027
            } else {
                8
            },
        );
        u64(&mut b, 0x510, 0x1000);
        if cfg!(target_arch = "aarch64") {
            b[0x1000..0x1008].copy_from_slice(&[0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]);
        } else {
            b[0x1000..0x1006].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
        }
        b
    }
    #[test]
    fn checked_tables_and_malformed_inputs() {
        let b = fixture();
        let p = Elf::parse(&b).unwrap();
        assert_eq!(p.span, 0x3000);
        assert_eq!(p.symbols[1].name, "answer");
        assert_eq!(p.relocations[0].address, 0x2000);
        for n in 0..256 {
            assert!(Elf::parse(&b[..n]).is_err());
        }
        let mut bad = b.clone();
        bad[64 + 40..64 + 48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Elf::parse(&bad).is_err());
        let mut bad = b;
        bad[0x500..0x508].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Elf::parse(&bad).is_err());
    }
}
