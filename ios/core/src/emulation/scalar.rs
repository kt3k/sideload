//! Scalar ISA and memory transfers, implemented from architectural semantics.
use super::{Cpu, Fault, Memory, Result, mask, signed};

fn ones(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
fn rotate(value: u64, shift: u32, width: u32) -> u64 {
    let shift = shift % width;
    if shift == 0 {
        value & ones(width)
    } else {
        (value >> shift | value << (width - shift)) & ones(width)
    }
}
fn extend(value: u64, option: u32) -> u64 {
    let width = 8 << (option & 3);
    let value = value & ones(width);
    if option & 4 != 0 {
        ((value << (64 - width)) as i64 >> (64 - width)) as u64
    } else {
        value
    }
}
pub(super) fn transfer_size(op: u32) -> Result<usize> {
    let scale = (op >> 30)
        | (if op & (1 << 26) != 0 {
            ((op >> 23) & 1) << 2
        } else {
            0
        });
    if scale > 4 {
        return Err(Fault::UnsupportedInstruction(op));
    }
    Ok(1 << scale)
}
impl Cpu {
    pub(super) fn transfer(&mut self, memory: &mut Memory, op: u32, address: u64) -> Result<()> {
        let rd = (op & 31) as usize;
        let kind = (op >> 22) & 3;
        let size = transfer_size(op)?;
        if op & (1 << 26) != 0 {
            if kind & 1 == 0 {
                memory.write(address, &self.v[rd].to_le_bytes()[..size])?;
            } else {
                let mut bytes = [0; 16];
                bytes[..size].copy_from_slice(memory.read(address, size)?);
                self.v[rd] = u128::from_le_bytes(bytes);
            }
        } else if kind == 0 {
            memory.store(address, size, self.reg(rd, false))?;
        } else {
            if (kind == 2 && size == 8) || (kind == 3 && size >= 4) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let value = memory.load(address, size)?;
            let value = if kind >= 2 {
                extend(value, 4 | (op >> 30))
            } else {
                value
            };
            self.set(rd, value, false, kind == 2 || size == 8);
        }
        Ok(())
    }
    pub(super) fn scalar(&mut self, memory: &mut Memory, op: u32) -> Result<bool> {
        let wide = op >> 31 != 0;
        let width = if wide { 64 } else { 32 };
        let rd = (op & 31) as usize;
        let rn = ((op >> 5) & 31) as usize;
        let rm = ((op >> 16) & 31) as usize;
        if op & 0x3a000000 == 0x28000000 {
            // LDP/STP, integer and SIMD
            let vector = op & (1 << 26) != 0;
            let kind = op >> 30;
            let load = op & (1 << 22) != 0;
            if kind == 3 || (!vector && (kind == 1 && !load)) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let size = if vector {
                4 << kind
            } else if kind == 2 {
                8
            } else {
                4
            };
            let rt2 = ((op >> 10) & 31) as usize;
            let mode = (op >> 23) & 3;
            let base = self.reg(rn, true);
            let updated = base.wrapping_add(signed((op >> 15) & 127, 7).wrapping_mul(size as u64));
            let address = if mode == 1 { base } else { updated };
            if (mode == 1 || mode == 3) && rn != 31 && !vector && (rn == rd || rn == rt2) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            if load {
                let first = memory.read(address, size)?.to_vec();
                let second = memory
                    .read(address.wrapping_add(size as u64), size)?
                    .to_vec();
                for (reg, bytes) in [(rd, first), (rt2, second)] {
                    if vector {
                        let mut value = [0; 16];
                        value[..size].copy_from_slice(&bytes);
                        self.v[reg] = u128::from_le_bytes(value);
                    } else {
                        let mut value = [0; 8];
                        value[..size].copy_from_slice(&bytes);
                        let value = u64::from_le_bytes(value);
                        self.set(
                            reg,
                            if kind == 1 {
                                value as u32 as i32 as i64 as u64
                            } else {
                                value
                            },
                            false,
                            kind != 0,
                        );
                    }
                }
            } else {
                let mut bytes = Vec::with_capacity(2 * size);
                for reg in [rd, rt2] {
                    if vector {
                        bytes.extend_from_slice(&self.v[reg].to_le_bytes()[..size]);
                    } else {
                        bytes.extend_from_slice(&self.reg(reg, false).to_le_bytes()[..size]);
                    }
                }
                memory.write(address, &bytes)?;
            }
            if mode == 1 || mode == 3 {
                self.set(rn, updated, true, true);
            }
        } else if op & 0x3b200000 == 0x38000000 {
            // LDUR/STUR, pre/post indexing
            let mode = (op >> 10) & 3;
            if mode == 2 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            if mode != 0 && rn != 31 && rn == rd && op & (1 << 26) == 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let base = self.reg(rn, true);
            let updated = base.wrapping_add(signed((op >> 12) & 511, 9));
            self.transfer(memory, op, if mode == 1 { base } else { updated })?;
            if mode != 0 {
                self.set(rn, updated, true, true);
            }
        } else if op & 0x3b200c00 == 0x38200800 {
            // register-offset load/store
            let option = (op >> 13) & 7;
            if option & 2 == 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let mut offset = extend(self.reg(rm, false), option);
            if op & (1 << 12) != 0 {
                offset = offset.wrapping_mul(transfer_size(op)? as u64);
            }
            self.transfer(memory, op, self.reg(rn, true).wrapping_add(offset))?;
        } else if op & 0x3b000000 == 0x18000000 {
            // literal loads
            let address = self
                .pc
                .wrapping_add(signed((op >> 5) & 0x7ffff, 19).wrapping_mul(4));
            let kind = op >> 30;
            if kind == 3 {
                return Ok(true);
            } // PRFM has no observable guest data effect
            if op & (1 << 26) != 0 {
                let mut bytes = [0; 16];
                let size = 4 << kind;
                bytes[..size].copy_from_slice(memory.read(address, size)?);
                self.v[rd] = u128::from_le_bytes(bytes);
            } else {
                let value = memory.load(address, if kind == 1 { 8 } else { 4 })?;
                self.set(
                    rd,
                    if kind == 2 {
                        value as u32 as i32 as i64 as u64
                    } else {
                        value
                    },
                    false,
                    kind != 0,
                );
            }
        } else if op & 0x1f800000 == 0x12000000 {
            // logical immediate
            let n = (op >> 22) & 1;
            let s = (op >> 10) & 63;
            let r = (op >> 16) & 63;
            let encoded = n << 6 | (!s & 63);
            if encoded < 2 || (!wide && n != 0) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let len = 31 - encoded.leading_zeros();
            let size = 1 << len;
            let levels = size - 1;
            if size > width || s & levels == levels {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let part = rotate(ones((s & levels) + 1), r & levels, size);
            let mut immediate = 0;
            for shift in (0..width).step_by(size as usize) {
                immediate |= part << shift;
            }
            let a = self.reg(rn, false);
            let kind = (op >> 29) & 3;
            let value = match kind {
                0 | 3 => a & immediate,
                1 => a | immediate,
                _ => a ^ immediate,
            } & mask(wide);
            if kind == 3 {
                self.nzcv = ((value >> (width - 1)) as u8) << 3 | ((value == 0) as u8) << 2;
            }
            self.set(rd, value, kind != 3, wide);
        } else if op & 0x1f800000 == 0x13000000 {
            // SBFM/BFM/UBFM
            let r = (op >> 16) & 63;
            let s = (op >> 10) & 63;
            let kind = (op >> 29) & 3;
            if kind == 3 || (op >> 22) & 1 != wide as u32 || r >= width || s >= width {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let wmask = rotate(ones(s + 1), r, width);
            let tmask = ones((s.wrapping_sub(r) & (width - 1)) + 1);
            let source = self.reg(rn, false) & mask(wide);
            let old = self.reg(rd, false);
            let rotated = rotate(source, r, width);
            let bottom = if kind == 1 {
                old & !wmask | rotated & wmask
            } else {
                rotated & wmask
            };
            let top = if kind == 0 {
                if source & (1 << s) != 0 {
                    mask(wide)
                } else {
                    0
                }
            } else if kind == 1 {
                old
            } else {
                0
            };
            self.set(rd, top & !tmask | bottom & tmask, false, wide);
        } else if op & 0x1f800000 == 0x13800000 {
            // EXTR
            let amount = (op >> 10) & 63;
            if amount >= width || (op >> 22) & 1 != wide as u32 || op & 0x60000000 != 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let low = self.reg(rm, false) & mask(wide);
            let high = self.reg(rn, false) & mask(wide);
            self.set(
                rd,
                if amount == 0 {
                    low
                } else {
                    low >> amount | high << (width - amount)
                },
                false,
                wide,
            );
        } else if op & 0x1f200000 == 0x0b200000 {
            // ADD/SUB extended register
            let shift = (op >> 10) & 7;
            if shift > 4 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let b = extend(self.reg(rm, false), (op >> 13) & 7) << shift;
            let flags = op & (1 << 29) != 0;
            let value = self.arithmetic(self.reg(rn, true), b, op & (1 << 30) != 0, flags, wide);
            self.set(rd, value, !flags, wide);
        } else if op & 0x1fe00800 == 0x1a800000 {
            // CSEL/CSINC/CSINV/CSNEG
            if op & (1 << 29) != 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let value = if self.condition((op >> 12) & 15) {
                self.reg(rn, false)
            } else {
                let mut value = self.reg(rm, false);
                if op & (1 << 30) != 0 {
                    value = !value;
                }
                value.wrapping_add(((op >> 10) & 1) as u64)
            };
            self.set(rd, value, false, wide);
        } else if op & 0x1fe00410 == 0x1a400000 && op & (1 << 29) != 0 {
            // CCMP/CCMN
            if self.condition((op >> 12) & 15) {
                let b = if op & (1 << 11) != 0 {
                    rm as u64
                } else {
                    self.reg(rm, false)
                };
                self.arithmetic(self.reg(rn, false), b, op & (1 << 30) != 0, true, wide);
            } else {
                self.nzcv = (op & 15) as u8;
            }
        } else if op & 0x7fe00000 == 0x1b000000 {
            // MADD/MSUB, includes MUL
            let a = self.reg(((op >> 10) & 31) as usize, false);
            let product = self.reg(rn, false).wrapping_mul(self.reg(rm, false));
            let value = if op & (1 << 15) != 0 {
                a.wrapping_sub(product)
            } else {
                a.wrapping_add(product)
            };
            self.set(rd, value, false, wide);
        } else if op & 0xff600000 == 0x9b200000 {
            // SMADDL/UMADDL
            let unsigned = op & (1 << 23) != 0;
            let convert = |x: u64| {
                if unsigned {
                    x as u32 as u64
                } else {
                    x as u32 as i32 as i64 as u64
                }
            };
            let product = convert(self.reg(rn, false)).wrapping_mul(convert(self.reg(rm, false)));
            let a = self.reg(((op >> 10) & 31) as usize, false);
            self.set(
                rd,
                if op & (1 << 15) != 0 {
                    a.wrapping_sub(product)
                } else {
                    a.wrapping_add(product)
                },
                false,
                true,
            );
        } else if op & 0xff607c00 == 0x9b407c00 {
            // SMULH/UMULH
            let a = self.reg(rn, false);
            let b = self.reg(rm, false);
            let high = if op & (1 << 23) != 0 {
                ((a as u128 * b as u128) >> 64) as u64
            } else {
                ((a as i64 as i128 * b as i64 as i128) >> 64) as u64
            };
            self.set(rd, high, false, true);
        } else if op & 0x7fe0f800 == 0x1ac00800 {
            // UDIV/SDIV
            let a = self.reg(rn, false) & mask(wide);
            let b = self.reg(rm, false) & mask(wide);
            let value = if b == 0 {
                0
            } else if op & (1 << 10) == 0 {
                a / b
            } else if wide {
                (a as i64).wrapping_div(b as i64) as u64
            } else {
                (a as i32).wrapping_div(b as i32) as u32 as u64
            };
            self.set(rd, value, false, wide);
        } else if op & 0x7fe0f000 == 0x1ac02000 {
            // LSLV/LSRV/ASRV/RORV
            let a = self.reg(rn, false) & mask(wide);
            let amount = (self.reg(rm, false) as u32) & (width - 1);
            let value = match (op >> 10) & 3 {
                0 => a << amount,
                1 => a >> amount,
                2 => {
                    if wide {
                        ((a as i64) >> amount) as u64
                    } else {
                        ((a as i32) >> amount) as u32 as u64
                    }
                }
                _ => rotate(a, amount, width),
            };
            self.set(rd, value, false, wide);
        } else if op & 0x7ffffc00 >= 0x5ac00000 && op & 0x7ffffc00 <= 0x5ac01400 {
            // RBIT/REV/CLZ/CLS
            let a = self.reg(rn, false) & mask(wide);
            let kind = (op >> 10) & 63;
            let value = match kind {
                0 => {
                    if wide {
                        a.reverse_bits()
                    } else {
                        (a as u32).reverse_bits() as u64
                    }
                }
                1 => (a & 0x00ff00ff00ff00ff) << 8 | (a >> 8) & 0x00ff00ff00ff00ff,
                2 => {
                    ((a as u32).swap_bytes() as u64)
                        | (((a >> 32) as u32).swap_bytes() as u64) << 32
                }
                3 if wide => a.swap_bytes(),
                4 => {
                    if wide {
                        a.leading_zeros() as u64
                    } else {
                        (a as u32).leading_zeros() as u64
                    }
                }
                5 => {
                    let a = if a & (1 << (width - 1)) != 0 {
                        !a & mask(wide)
                    } else {
                        a
                    };
                    (if wide {
                        a.leading_zeros()
                    } else {
                        (a as u32).leading_zeros()
                    }) as u64
                        - 1
                }
                _ => return Err(Fault::UnsupportedInstruction(op)),
            };
            self.set(rd, value, false, wide);
        } else if op & 0xffffffe0 == 0xd53bd040 {
            self.set(rd, self.tpidr, false, true);
        } else if op & 0xffffffe0 == 0xd53b4200 {
            self.set(rd, (self.nzcv as u64) << 28, false, true);
        } else if op & 0xffffffe0 == 0xd51b4200 {
            self.nzcv = ((self.reg(rd, false) >> 28) & 15) as u8;
        } else if matches!(op, 0xd5033bbf | 0xd5033abf | 0xd50339bf | 0xd5033fdf) { /* barriers: single guest thread */
        } else {
            return Ok(false);
        }
        Ok(true)
    }
}
