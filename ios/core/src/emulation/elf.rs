//! AArch64 ELF loading into guest bytes, reusing our MIT ELF metadata parser.
//! No host pointers, native execution, or implicit constructors.
use super::{Fault, Memory, Permissions, Result};
use sideload::anisette::local_adi::elf::Elf;
use std::collections::BTreeMap;

pub struct Image {
    pub memory: Memory,
    exports: BTreeMap<String, u64>,
}
impl Image {
    /// Imports must be explicit guest addresses. Android runtime shims and
    /// DT_INIT/INIT_ARRAY execution are not implemented by this loader.
    pub fn load(bytes: &[u8], base: u64, imports: &BTreeMap<String, u64>) -> Result<Self> {
        let elf = Elf::parse(bytes).map_err(|_| Fault::InvalidElf)?;
        if elf.machine != 183 || base & 4095 != 0 {
            return Err(Fault::InvalidElf);
        }
        base.checked_add(elf.span as u64).ok_or(Fault::InvalidElf)?;
        let mut memory = Memory::default();
        for s in &elf.segments {
            if s.memory_size == 0 {
                continue;
            }
            let permissions = Permissions {
                read: s.flags & 4 != 0,
                write: s.flags & 2 != 0,
                execute: s.flags & 1 != 0,
            };
            if permissions.write && permissions.execute {
                return Err(Fault::InvalidElf);
            }
            memory.map(
                base + s.address as u64,
                s.memory_size,
                &bytes[s.offset..s.offset + s.file_size],
                permissions,
            )?;
        }
        let mut exports = BTreeMap::new();
        let mut addresses = Vec::new();
        for s in &elf.symbols {
            let address = if s.defined {
                if s.absolute {
                    s.address as u64
                } else {
                    let address = base
                        .checked_add(s.address as u64)
                        .ok_or(Fault::InvalidElf)?;
                    if memory.region(address, s.size.max(1)).is_none() {
                        return Err(Fault::InvalidElf);
                    }
                    address
                }
            } else if s.name.is_empty() {
                0
            } else {
                match imports.get(&s.name) {
                    Some(address) => *address,
                    None if s.weak => 0,
                    None => return Err(Fault::UnresolvedImport),
                }
            };
            if s.defined && !s.name.is_empty() {
                exports.insert(s.name.clone(), address);
            }
            addresses.push(address);
        }
        for r in &elf.relocations {
            if r.kind == 0 {
                continue;
            }
            let address = base
                .checked_add(r.address as u64)
                .ok_or(Fault::InvalidElf)?;
            let (i, offset) = memory.region(address, 8).ok_or(Fault::InvalidElf)?;
            let region = &mut memory.regions[i];
            let addend = r.addend.map(|v| v as u64).unwrap_or_else(|| {
                u64::from_le_bytes(region.bytes[offset..offset + 8].try_into().unwrap())
            });
            let value = match r.kind {
                1027 => base.wrapping_add(addend), // RELATIVE
                257 | 1025 | 1026 => addresses
                    .get(r.symbol)
                    .ok_or(Fault::InvalidElf)?
                    .wrapping_add(addend), // ABS64/GLOB_DAT/JUMP_SLOT
                kind => return Err(Fault::UnsupportedRelocation(kind)),
            };
            // Initial relocation is allowed even for a read-only guest segment.
            region.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(Self { memory, exports })
    }
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.exports.get(name).copied()
    }
    pub fn exports(&self) -> impl Iterator<Item = (&str, u64)> {
        self.exports.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::emulation::Cpu;
    // ELF ABI fixture: code + data/BSS, symbols, one RELATIVE relocation.
    pub(crate) fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0x2010];
        fn h(b: &mut [u8], p: usize, n: u16) {
            b[p..p + 2].copy_from_slice(&n.to_le_bytes());
        }
        fn w(b: &mut [u8], p: usize, n: u32) {
            b[p..p + 4].copy_from_slice(&n.to_le_bytes());
        }
        fn d(b: &mut [u8], p: usize, n: u64) {
            b[p..p + 8].copy_from_slice(&n.to_le_bytes());
        }
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        h(&mut b, 16, 3);
        h(&mut b, 18, 183);
        w(&mut b, 20, 1);
        d(&mut b, 32, 64);
        h(&mut b, 52, 64);
        h(&mut b, 54, 56);
        h(&mut b, 56, 3);
        for (i, kind, flags, offset, size, mem) in [
            (0, 1, 5, 0, 0x1008, 0x1008),
            (1, 1, 6, 0x2000, 16, 32),
            (2, 2, 4, 0x200, 144, 144),
        ] {
            let p = 64 + i * 56;
            w(&mut b, p, kind);
            w(&mut b, p + 4, flags);
            d(&mut b, p + 8, offset);
            d(&mut b, p + 16, offset);
            d(&mut b, p + 32, size);
            d(&mut b, p + 40, mem);
            d(&mut b, p + 48, 8);
        }
        for (i, (tag, value)) in [
            (4, 0x300),
            (5, 0x350),
            (10, 8),
            (6, 0x400),
            (11, 24),
            (7, 0x500),
            (8, 24),
            (9, 24),
        ]
        .into_iter()
        .enumerate()
        {
            d(&mut b, 0x200 + i * 16, tag);
            d(&mut b, 0x208 + i * 16, value);
        }
        w(&mut b, 0x300, 1);
        w(&mut b, 0x304, 2);
        b[0x350..0x358].copy_from_slice(b"\0answer\0");
        w(&mut b, 0x418, 1);
        b[0x41c] = 0x12;
        h(&mut b, 0x41e, 1);
        d(&mut b, 0x420, 0x1000);
        d(&mut b, 0x428, 8);
        d(&mut b, 0x500, 0x2000);
        d(&mut b, 0x508, 1027);
        d(&mut b, 0x510, 0x1000);
        w(&mut b, 0x1000, 0x52800540);
        w(&mut b, 0x1004, 0xd65f03c0); // mov w0,#42; ret
        b
    }
    #[test]
    fn loads_relocates_and_interprets_without_host_execution() {
        let mut image = Image::load(&fixture(), 0x10000, &BTreeMap::new()).unwrap();
        let answer = image.symbol("answer").unwrap();
        assert_eq!(answer, 0x11000);
        assert_eq!(image.memory.load(0x12000, 8).unwrap(), answer);
        assert_eq!(image.memory.load(0x12010, 8).unwrap(), 0);
        let mut cpu = Cpu {
            pc: answer,
            ..Cpu::default()
        };
        cpu.x[30] = 0x8000;
        cpu.run(&mut image.memory, 0x8000, 2).unwrap();
        assert_eq!(cpu.x[0], 42);
        assert_eq!(image.memory.write(answer, &[0]), Err(Fault::Write));
    }
    #[test]
    fn rejects_unknown_relocations_architecture_and_imports() {
        let mut b = fixture();
        b[0x508..0x510].copy_from_slice(&9999u64.to_le_bytes());
        assert!(matches!(
            Image::load(&b, 0x10000, &BTreeMap::new()),
            Err(Fault::UnsupportedRelocation(9999))
        ));
        let mut b = fixture();
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(matches!(
            Image::load(&b, 0x10000, &BTreeMap::new()),
            Err(Fault::InvalidElf)
        ));
        let mut b = fixture();
        b[0x41e..0x420].fill(0);
        assert!(matches!(
            Image::load(&b, 0x10000, &BTreeMap::new()),
            Err(Fault::UnresolvedImport)
        ));
        assert!(Image::load(&fixture(), u64::MAX - 4095, &BTreeMap::new()).is_err());
    }
}
