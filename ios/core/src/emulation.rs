//! MIT AArch64 interpreter foundation for on-device ADI. This is deliberately
//! incomplete: unknown instructions trap; it cannot yet run Apple's libraries.
//! Guest bytes are ordinary Rust data, never host executable memory.

use std::ops::Range;

pub mod elf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    InvalidElf,
    UnresolvedImport,
    UnsupportedRelocation(u32),
    Mapping,
    Read,
    Write,
    Execute,
    Alignment,
    UnsupportedInstruction(u32),
    BudgetExhausted,
}
type Result<T> = std::result::Result<T, Fault>;

#[derive(Clone, Copy)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
impl Permissions {
    pub const CODE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const DATA: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
}
struct Region {
    range: Range<u64>,
    bytes: Vec<u8>,
    permissions: Permissions,
}
#[derive(Default)]
pub struct Memory {
    regions: Vec<Region>,
    allocated: usize,
}
impl Memory {
    /// Fixed total allocation ceiling; guest pointers never become host pointers.
    pub const LIMIT: usize = 128 * 1024 * 1024;
    pub fn map(
        &mut self,
        base: u64,
        size: usize,
        initial: &[u8],
        permissions: Permissions,
    ) -> Result<()> {
        let end = base.checked_add(size as u64).ok_or(Fault::Mapping)?;
        if size == 0
            || initial.len() > size
            || size > Self::LIMIT - self.allocated
            || self
                .regions
                .iter()
                .any(|r| base < r.range.end && r.range.start < end)
        {
            return Err(Fault::Mapping);
        }
        let mut bytes = vec![0; size];
        bytes[..initial.len()].copy_from_slice(initial);
        self.regions.push(Region {
            range: base..end,
            bytes,
            permissions,
        });
        self.allocated += size;
        Ok(())
    }
    fn region(&self, address: u64, size: usize) -> Option<(usize, usize)> {
        let end = address.checked_add(size as u64)?;
        self.regions.iter().enumerate().find_map(|(i, r)| {
            (address >= r.range.start && end <= r.range.end)
                .then_some((i, address.wrapping_sub(r.range.start) as usize))
        })
    }
    pub fn read(&self, address: u64, size: usize) -> Result<&[u8]> {
        let (i, offset) = self.region(address, size).ok_or(Fault::Read)?;
        let r = &self.regions[i];
        if !r.permissions.read {
            return Err(Fault::Read);
        }
        Ok(&r.bytes[offset..offset + size])
    }
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        let (i, offset) = self.region(address, bytes.len()).ok_or(Fault::Write)?;
        let r = &mut self.regions[i];
        if !r.permissions.write {
            return Err(Fault::Write);
        }
        r.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn instruction(&self, address: u64) -> Result<u32> {
        if address & 3 != 0 {
            return Err(Fault::Alignment);
        }
        let (i, offset) = self.region(address, 4).ok_or(Fault::Execute)?;
        let r = &self.regions[i];
        if !r.permissions.execute {
            return Err(Fault::Execute);
        }
        Ok(u32::from_le_bytes(
            r.bytes[offset..offset + 4].try_into().unwrap(),
        ))
    }
    fn load(&self, address: u64, size: usize) -> Result<u64> {
        let mut word = [0; 8];
        word[..size].copy_from_slice(self.read(address, size)?);
        Ok(u64::from_le_bytes(word))
    }
    fn store(&mut self, address: u64, size: usize, value: u64) -> Result<()> {
        self.write(address, &value.to_le_bytes()[..size])
    }
}

#[derive(Default)]
pub struct Cpu {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    /// N,Z,C,V, in bits 3..0.
    pub nzcv: u8,
}
fn signed(value: u32, bits: u32) -> u64 {
    (((value as i32) << (32 - bits)) >> (32 - bits)) as i64 as u64
}
fn mask(wide: bool) -> u64 {
    if wide { u64::MAX } else { u32::MAX as u64 }
}
impl Cpu {
    fn reg(&self, index: usize, stack: bool) -> u64 {
        if index == 31 {
            if stack { self.sp } else { 0 }
        } else {
            self.x[index]
        }
    }
    fn set(&mut self, index: usize, value: u64, stack: bool, wide: bool) {
        let value = value & mask(wide);
        if index != 31 {
            self.x[index] = value;
        } else if stack {
            self.sp = value;
        }
    }
    fn condition(&self, condition: u32) -> bool {
        let n = self.nzcv & 8 != 0;
        let z = self.nzcv & 4 != 0;
        let c = self.nzcv & 2 != 0;
        let v = self.nzcv & 1 != 0;
        let yes = match condition >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => c && !z,
            5 => n == v,
            6 => n == v && !z,
            _ => true,
        };
        if condition & 1 != 0 && condition != 15 {
            !yes
        } else {
            yes
        }
    }
    fn arithmetic(&mut self, a: u64, b: u64, subtract: bool, flags: bool, wide: bool) -> u64 {
        let m = mask(wide);
        let a = a & m;
        let b = b & m;
        let result = if subtract {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        } & m;
        if flags {
            let sign = if wide { 1 << 63 } else { 1 << 31 };
            let carry = if subtract {
                a >= b
            } else {
                (a as u128 + b as u128) > m as u128
            };
            let overflow = (if subtract {
                (a ^ b) & (a ^ result)
            } else {
                !(a ^ b) & (a ^ result)
            }) & sign
                != 0;
            self.nzcv = ((result & sign != 0) as u8) << 3
                | ((result == 0) as u8) << 2
                | (carry as u8) << 1
                | overflow as u8;
        }
        result
    }
    /// Stops before fetching `return_pc`; every guest instruction consumes budget.
    /// SVC/system registers and unsupported opcodes fail closed, without host calls.
    pub fn run(&mut self, memory: &mut Memory, return_pc: u64, budget: usize) -> Result<()> {
        for _ in 0..budget {
            if self.pc == return_pc {
                return Ok(());
            }
            self.step(memory)?;
        }
        if self.pc == return_pc {
            Ok(())
        } else {
            Err(Fault::BudgetExhausted)
        }
    }
    pub fn step(&mut self, memory: &mut Memory) -> Result<()> {
        let op = memory.instruction(self.pc)?;
        let mut next = self.pc.wrapping_add(4);
        let wide = op >> 31 != 0;
        let rd = (op & 31) as usize;
        let rn = ((op >> 5) & 31) as usize;
        let rm = ((op >> 16) & 31) as usize;
        if op == 0xd503201f { // NOP
        } else if op & 0x7c000000 == 0x14000000 {
            // B, BL
            if wide {
                self.x[30] = next;
            }
            next = self
                .pc
                .wrapping_add(signed(op & 0x03ffffff, 26).wrapping_mul(4));
        } else if matches!(op & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000) {
            // BR, BLR, RET
            next = self.reg(rn, false);
            if op & 0xfffffc1f == 0xd63f0000 {
                self.x[30] = self.pc.wrapping_add(4);
            }
        } else if op & 0xff000010 == 0x54000000 {
            // B.cond
            if self.condition(op & 15) {
                next = self
                    .pc
                    .wrapping_add(signed((op >> 5) & 0x7ffff, 19).wrapping_mul(4));
            }
        } else if op & 0x7e000000 == 0x34000000 {
            // CBZ, CBNZ
            let zero = self.reg(rd, false) & mask(wide) == 0;
            if zero != (op & (1 << 24) != 0) {
                next = self
                    .pc
                    .wrapping_add(signed((op >> 5) & 0x7ffff, 19).wrapping_mul(4));
            }
        } else if op & 0x7e000000 == 0x36000000 {
            // TBZ, TBNZ
            let bit = ((op >> 19) & 31) | ((op >> 26) & 32);
            let zero = self.reg(rd, false) & (1u64 << bit) == 0;
            if zero != (op & (1 << 24) != 0) {
                next = self
                    .pc
                    .wrapping_add(signed((op >> 5) & 0x3fff, 14).wrapping_mul(4));
            }
        } else if op & 0x1f000000 == 0x10000000 {
            // ADR, ADRP
            let offset = signed(((op >> 5) & 0x7ffff) << 2 | ((op >> 29) & 3), 21);
            let value = if wide {
                (self.pc & !4095).wrapping_add(offset.wrapping_mul(4096))
            } else {
                self.pc.wrapping_add(offset)
            };
            self.set(rd, value, false, true);
        } else if op & 0x1f800000 == 0x12800000 {
            // MOVN, MOVZ, MOVK
            let kind = (op >> 29) & 3;
            let shift = ((op >> 21) & 3) * 16;
            if kind == 1 || (!wide && shift >= 32) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let imm = (((op >> 5) & 0xffff) as u64) << shift;
            let value = match kind {
                0 => !imm,
                2 => imm,
                _ => self.reg(rd, false) & !(0xffffu64 << shift) | imm,
            };
            self.set(rd, value, false, wide);
        } else if op & 0x1f800000 == 0x11000000 {
            // ADD/SUB immediate
            let flags = op & (1 << 29) != 0;
            let imm = (((op >> 10) & 0xfff) as u64) << (if op & (1 << 22) != 0 { 12 } else { 0 });
            let value = self.arithmetic(self.reg(rn, true), imm, op & (1 << 30) != 0, flags, wide);
            self.set(rd, value, !flags, wide);
        } else if op & 0x1f200000 == 0x0b000000 || op & 0x1f000000 == 0x0a000000 {
            // shifted arithmetic/logical
            let amount = (op >> 10) & 63;
            let shift = (op >> 22) & 3;
            let logical = op & 0x01000000 == 0;
            if (!wide && amount >= 32) || (!logical && shift == 3) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let mut b = self.reg(rm, false) & mask(wide);
            b = match shift {
                0 => b << amount,
                1 => b >> amount,
                2 => {
                    if wide {
                        ((b as i64) >> amount) as u64
                    } else {
                        ((b as i32) >> amount) as u32 as u64
                    }
                }
                _ => {
                    if wide {
                        b.rotate_right(amount)
                    } else {
                        (b as u32).rotate_right(amount) as u64
                    }
                }
            };
            let a = self.reg(rn, false);
            let value = if logical {
                if op & (1 << 21) != 0 {
                    b = !b;
                }
                let kind = (op >> 29) & 3;
                let value = (match kind {
                    0 | 3 => a & b,
                    1 => a | b,
                    _ => a ^ b,
                }) & mask(wide);
                if kind == 3 {
                    self.nzcv = ((value >> (if wide { 63 } else { 31 })) as u8) << 3
                        | ((value == 0) as u8) << 2;
                }
                value
            } else {
                self.arithmetic(a, b, op & (1 << 30) != 0, op & (1 << 29) != 0, wide)
            };
            self.set(rd, value, false, wide);
        } else if op & 0x3f000000 == 0x39000000 {
            // integer LDR/STR unsigned immediate
            let size = 1usize << (op >> 30);
            let kind = (op >> 22) & 3;
            if kind > 1 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let address = self
                .reg(rn, true)
                .wrapping_add((((op >> 10) & 0xfff) as u64) * size as u64);
            if kind == 0 {
                memory.store(address, size, self.reg(rd, false))?;
            } else {
                let value = memory.load(address, size)?;
                self.set(rd, value, false, size == 8);
            }
        } else {
            return Err(Fault::UnsupportedInstruction(op));
        }
        self.pc = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn program(words: &[u32]) -> (Cpu, Memory) {
        let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut memory = Memory::default();
        memory
            .map(0x1000, bytes.len(), &bytes, Permissions::CODE)
            .unwrap();
        let mut cpu = Cpu {
            pc: 0x1000,
            ..Cpu::default()
        };
        cpu.x[30] = 0x8000;
        (cpu, memory)
    }
    #[test]
    fn function_and_loop() {
        // mov x0,#0; mov x1,#10; add x0,x0,x1; subs x1,x1,#1; b.ne -8; ret
        let (mut cpu, mut memory) = program(&[
            0xd2800000, 0xd2800141, 0x8b010000, 0xf1000421, 0x54ffffc1, 0xd65f03c0,
        ]);
        cpu.run(&mut memory, 0x8000, 33).unwrap();
        assert_eq!(cpu.x[0], 55);
        assert_eq!(cpu.nzcv, 6);
    }
    #[test]
    fn guest_data_and_zero_extension() {
        // str x0,[x1,#8]; ldr w2,[x1,#8]; mov w3,w2; ret
        let (mut cpu, mut memory) = program(&[0xf9000420, 0xb9400822, 0x2a0203e3, 0xd65f03c0]);
        memory.map(0x2000, 16, &[], Permissions::DATA).unwrap();
        cpu.x[0] = 0x1234567887654321;
        cpu.x[1] = 0x2000;
        cpu.x[2] = u64::MAX;
        cpu.run(&mut memory, 0x8000, 4).unwrap();
        assert_eq!(cpu.x[2], 0x87654321);
        assert_eq!(cpu.x[3], 0x87654321);
        assert_eq!(memory.load(0x2008, 8).unwrap(), cpu.x[0]);
    }
    #[test]
    fn nested_call_preserves_link_and_stack() {
        // Assembled from tests/fixtures/aarch64.S, call_and_stack + increment.
        let (mut cpu, mut memory) = program(&[
            0xd10043ff, 0xf90007fe, 0x94000004, 0xf94007fe, 0x910043ff, 0xd65f03c0, 0x11000400,
            0xd65f03c0,
        ]);
        memory.map(0x2000, 256, &[], Permissions::DATA).unwrap();
        cpu.sp = 0x2100;
        cpu.x[0] = u32::MAX as u64;
        cpu.run(&mut memory, 0x8000, 8).unwrap();
        assert_eq!(cpu.x[0], 0);
        assert_eq!(cpu.x[30], 0x8000);
        assert_eq!(cpu.sp, 0x2100);
    }
    #[test]
    fn wide_constants_rotate_and_pc_relative_address() {
        let (mut cpu, mut memory) = program(&[
            0xd2e24680, 0xf2b579a0, 0x12800001, 0xcac12002, 0x10ffff83, 0xd65f03c0,
        ]);
        cpu.run(&mut memory, 0x8000, 6).unwrap();
        assert_eq!(cpu.x[0], 0x12340000abcd0000);
        assert_eq!(cpu.x[1], 0xffffffff);
        assert_eq!(cpu.x[2], 0xed340000ab32ffff);
        assert_eq!(cpu.x[3], 0x1000);
    }
    #[test]
    fn flags_for_signed_overflow_and_borrow() {
        let mut cpu = Cpu::default();
        assert_eq!(
            cpu.arithmetic(0x7fffffff, 1, false, true, false),
            0x80000000
        );
        assert_eq!(cpu.nzcv, 9);
        assert!(cpu.condition(6)); // VS
        assert!(cpu.condition(10)); // GE: signed comparison uses N == V
        assert_eq!(cpu.arithmetic(0, 1, true, true, true), u64::MAX);
        assert_eq!(cpu.nzcv, 8);
        assert!(cpu.condition(3)); // CC
    }
    #[test]
    fn faults_do_not_escape_guest_memory() {
        let (mut cpu, mut memory) = program(&[0x14000000]); // infinite B .
        assert_eq!(
            cpu.run(&mut memory, 0x8000, 10),
            Err(Fault::BudgetExhausted)
        );
        assert_eq!(memory.write(0x1000, &[0]), Err(Fault::Write));
        assert_eq!(memory.read(u64::MAX, 8), Err(Fault::Read));
        assert_eq!(
            memory.map(0x1000, 8, &[], Permissions::DATA),
            Err(Fault::Mapping)
        );
        assert_eq!(
            memory.map(0, Memory::LIMIT, &[], Permissions::DATA),
            Err(Fault::Mapping)
        );
        memory.map(0x2000, 8, &[], Permissions::DATA).unwrap();
        cpu.pc = 0x2000;
        assert_eq!(cpu.step(&mut memory), Err(Fault::Execute));
        cpu.pc = 0x1001;
        assert_eq!(cpu.step(&mut memory), Err(Fault::Alignment));
    }
    #[test]
    fn unsupported_instructions_trap() {
        for op in [0xd4000001, 0, 0x4e20d400, 0x52c00000] {
            // SVC, UDF, SIMD, invalid 32-bit MOV
            let (mut cpu, mut memory) = program(&[op]);
            assert_eq!(
                cpu.step(&mut memory),
                Err(Fault::UnsupportedInstruction(op))
            );
            assert_eq!(cpu.pc, 0x1000);
        }
    }
}
