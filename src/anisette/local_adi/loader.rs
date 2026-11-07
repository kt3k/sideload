//! Private executable mappings and ELF relocation. No ELF constructors run:
//! only the ADI entry points and their explicit initialization are supported.
use super::{
    AdiResult,
    elf::Elf,
    fail, hooks,
    memory::{EXEC, Mapping, WRITE},
};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc};
pub struct Library {
    memory: Mapping,
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
        let memory = Mapping::new(elf.span)?;
        let page = memory.page;
        let length = memory.length;
        let base = memory.pointer as usize;
        let mut library = Self {
            memory,
            exports: BTreeMap::new(),
            _single_thread: PhantomData,
        };
        let mut protections = vec![0; length / page];
        for segment in &elf.segments {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(segment.offset),
                    (base + segment.address) as *mut u8,
                    segment.file_size,
                );
            }
            if segment.memory_size > 0 {
                for protection in &mut protections
                    [segment.address / page..(segment.address + segment.memory_size).div_ceil(page)]
                {
                    *protection |= segment.flags & 7;
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
            if prot & EXEC != 0 && prot & WRITE != 0 {
                return Err(fail(
                    "host pages combine writable and executable ADI segments",
                ));
            }
            library.memory.protect(i * page, page, prot)?;
            if prot & EXEC != 0 {
                library.memory.flush_code(i * page, page)?;
            }
        }
        Ok(library)
    }
    pub fn symbol(&self, name: &str) -> Option<usize> {
        self.exports.get(name).copied()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_code_and_relative_relocation() {
        let lib = Library::load(&super::super::elf::tests::fixture(), &[]).unwrap();
        let answer = lib.symbol("answer").unwrap();
        super::super::abi::native_type!(Function() -> u32);
        let function: Function = unsafe { std::mem::transmute(answer) };
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
