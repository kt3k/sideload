//! Integer Advanced SIMD operations and structure transfers. Floating point traps.
use super::{Cpu, Fault, Memory, Result};
fn bits(width: u32) -> u128 {
    if width == 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    }
}
fn lane(value: u128, index: u32, width: u32) -> u128 {
    value >> (index * width) & bits(width)
}
fn signed(value: u128, width: u32) -> i128 {
    ((value << (128 - width)) as i128) >> (128 - width)
}
impl Cpu {
    pub(super) fn vector(&mut self, memory: &mut Memory, op: u32) -> Result<bool> {
        let rd = (op & 31) as usize;
        let rn = ((op >> 5) & 31) as usize;
        let rm = ((op >> 16) & 31) as usize;
        let q = (op >> 30) & 1;
        let u = (op >> 29) & 1;
        let width = 64 << q;
        let a = self.v[rn];
        let b = self.v[rm];
        let old = self.v[rd];
        let mut result = 0;
        if matches!(op & 0xfffffc00, 0x9e660000 | 0x1e260000 | 0x9eae0000) {
            // FMOV bits to general register
            let high = op & 0xfffffc00 == 0x9eae0000;
            self.set(
                rd,
                (a >> if high { 64 } else { 0 }) as u64,
                false,
                op >> 31 != 0,
            );
            return Ok(true);
        } else if matches!(op & 0xfffffc00, 0x9e670000 | 0x1e270000 | 0x9eaf0000) {
            // FMOV bits from general register
            let high = op & 0xfffffc00 == 0x9eaf0000;
            result = if high {
                old & bits(64) | (self.reg(rn, false) as u128) << 64
            } else {
                self.reg(rn, false) as u128 & bits(if op >> 31 != 0 { 64 } else { 32 })
            };
        } else if op & 0x9f20fc00 == 0x0e201c00 {
            // bitwise
            result = match (u, (op >> 22) & 3) {
                (0, 0) => a & b,
                (0, 1) => a & !b,
                (0, 2) => a | b,
                (0, 3) => a | !b,
                (1, 0) => a ^ b,
                (1, 1) => old & a | !old & b,
                (1, 2) => old & !b | a & b,
                (1, 3) => old & b | a & !b,
                _ => unreachable!(),
            } & bits(width);
        } else if matches!(op & 0x9f20fc00, 0x0e208c00 | 0x0e203400 | 0x0e203c00) {
            // vector comparisons
            let size = 8 << ((op >> 22) & 3);
            for i in 0..width / size {
                let x = lane(a, i, size);
                let y = lane(b, i, size);
                let yes = match op & 0xfc00 {
                    0x8c00 => {
                        if u == 1 {
                            x == y
                        } else {
                            x & y != 0
                        }
                    }
                    0x3400 => {
                        if u == 1 {
                            x > y
                        } else {
                            signed(x, size) > signed(y, size)
                        }
                    }
                    _ => {
                        if u == 1 {
                            x >= y
                        } else {
                            signed(x, size) >= signed(y, size)
                        }
                    }
                };
                if yes {
                    result |= bits(size) << (i * size);
                }
            }
        } else if matches!(op & 0x9f20fc00, 0x0e208400 | 0x0e209c00 | 0x0e209400) {
            // ADD/SUB/MUL/MLA/MLS
            let size = 8 << ((op >> 22) & 3);
            let kind = op & 0xfc00;
            if (kind != 0x8400 && size == 64) || (kind == 0x9c00 && u != 0) {
                return Err(Fault::UnsupportedInstruction(op));
            }
            for i in 0..width / size {
                let x = lane(a, i, size);
                let y = lane(b, i, size);
                let value = if kind == 0x8400 {
                    if u == 0 {
                        x.wrapping_add(y)
                    } else {
                        x.wrapping_sub(y)
                    }
                } else if kind == 0x9c00 {
                    x * y
                } else if u == 0 {
                    lane(old, i, size).wrapping_add(x * y)
                } else {
                    lane(old, i, size).wrapping_sub(x * y)
                };
                result |= (value & bits(size)) << (i * size);
            }
        } else if matches!(
            op & 0xbfe0fc00,
            0x0e000c00 | 0x0e000400 | 0x0e003c00 | 0x0e002c00
        ) {
            // DUP/UMOV/SMOV
            let imm = (op >> 16) & 31;
            if imm == 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let scale = imm.trailing_zeros();
            let size = 8 << scale;
            let index = imm >> (scale + 1);
            if size > 64 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let kind = op & 0xfc00;
            let value = if kind == 0x0c00 {
                self.reg(rn, false) as u128 & bits(size)
            } else {
                lane(a, index, size)
            };
            if kind == 0x3c00 || kind == 0x2c00 {
                self.set(
                    rd,
                    if kind == 0x2c00 {
                        signed(value, size) as u64
                    } else {
                        value as u64
                    },
                    false,
                    q != 0,
                );
                return Ok(true);
            }
            if kind == 0x0c00 && index != 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            for i in 0..width / size {
                result |= value << (i * size);
            }
        } else if op & 0xffe0fc00 == 0x4e001c00 {
            // INS general register
            let imm = (op >> 16) & 31;
            if imm == 0 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let scale = imm.trailing_zeros();
            let size = 8 << scale;
            let index = imm >> (scale + 1);
            if size > 64 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            result = old & !(bits(size) << (index * size))
                | ((self.reg(rn, false) as u128 & bits(size)) << (index * size));
        } else if op & 0x9ff80c00 == 0x0f000400 {
            // modified immediate
            let imm = (((op >> 16) & 7) << 5 | ((op >> 5) & 31)) as u128;
            let cmode = (op >> 12) & 15;
            let (size, mut value) = match cmode {
                0..=7 => (32, imm << ((cmode >> 1) * 8)),
                8..=11 => (16, imm << (((cmode - 8) >> 1) * 8)),
                12 => (32, (imm << 8) | 255),
                13 => (32, (imm << 16) | 65535),
                14 if u == 0 => (8, imm),
                14 => {
                    let mut value = 0;
                    for i in 0..8 {
                        if imm & (1 << i) != 0 {
                            value |= 255u128 << (i * 8);
                        }
                    }
                    (64, value)
                }
                _ => return Err(Fault::UnsupportedInstruction(op)),
            };
            if u != 0 && cmode != 14 {
                value = !value & bits(size);
            }
            for i in 0..width / size {
                result |= value << (i * size);
            }
            if cmode < 12 && cmode & 1 != 0 {
                result = if u == 0 { old | result } else { old & result };
            }
            result &= bits(width);
        } else if op & 0x9f800400 == 0x0f000400 {
            // immediate shifts, widen
            let imm = (op >> 16) & 127;
            if imm < 8 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            let size = 1 << (31 - imm.leading_zeros());
            let kind = (op >> 11) & 31;
            if kind == 20 {
                // SSHLL/USHLL, Q selects source half
                if size == 64 {
                    return Err(Fault::UnsupportedInstruction(op));
                }
                let shift = imm - size;
                for i in 0..64 / size {
                    let x = lane(a, i + q * (64 / size), size);
                    let x = if u == 0 { signed(x, size) as u128 } else { x };
                    result |= ((x << shift) & bits(2 * size)) << (i * 2 * size);
                }
            } else {
                for i in 0..width / size {
                    let x = lane(a, i, size);
                    let value = match kind {
                        10 if u == 0 => (x << (imm - size)) & bits(size),
                        0 => {
                            let shift = 2 * size - imm;
                            if u != 0 {
                                x >> shift
                            } else {
                                (signed(x, size) >> shift) as u128 & bits(size)
                            }
                        }
                        _ => return Err(Fault::UnsupportedInstruction(op)),
                    };
                    result |= value << (i * size);
                }
            }
        } else if op & 0x9f3ffc00 == 0x0e20b800 {
            // ABS/NEG
            let size = 8 << ((op >> 22) & 3);
            for i in 0..width / size {
                let x = lane(a, i, size);
                let value = if u != 0 {
                    x.wrapping_neg()
                } else {
                    signed(x, size).wrapping_abs() as u128
                };
                result |= (value & bits(size)) << (i * size);
            }
        } else if op & 0xbf3ffc00 == 0x0e212800 {
            // XTN/XTN2
            let size = 8 << ((op >> 22) & 3);
            if size == 64 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            result = if q != 0 { old & bits(64) } else { 0 };
            for i in 0..64 / size {
                result |= (lane(a, i, 2 * size) & bits(size)) << (i * size + 64 * q);
            }
        } else if op & 0xbffffc00 == 0x0e205800 {
            // CNT
            for i in 0..width / 8 {
                result |= (lane(a, i, 8).count_ones() as u128) << (i * 8);
            }
        } else if op & 0xbf3ffc00 == 0x2e303800 {
            // UADDLV
            let size = 8 << ((op >> 22) & 3);
            if size > 32 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            for i in 0..width / size {
                result += lane(a, i, size);
            }
        } else if op & 0xbfe08400 == 0x2e000000 {
            // EXT
            let index = (op >> 11) & 15;
            if index >= width / 8 {
                return Err(Fault::UnsupportedInstruction(op));
            }
            result = if index == 0 {
                a & bits(width)
            } else {
                ((a & bits(width)) >> (index * 8) | b << ((width / 8 - index) * 8)) & bits(width)
            };
        } else if op & 0xbf000000 == 0x0c000000 {
            // multiple structure load/store
            let opcode = (op >> 12) & 15;
            let size = 1usize << ((op >> 10) & 3);
            let (registers, structures) = match opcode {
                0 => (4, 4),
                2 => (4, 1),
                4 => (3, 3),
                6 => (3, 1),
                7 => (1, 1),
                8 => (2, 2),
                10 => (2, 1),
                _ => return Err(Fault::UnsupportedInstruction(op)),
            };
            let bytes = (width / 8) as usize;
            let load = op & (1 << 22) != 0;
            let address = self.reg(rn, true);
            let total = registers * bytes;
            let mut buffer = if load {
                memory.read(address, total)?.to_vec()
            } else {
                vec![0; total]
            };
            for r in 0..registers {
                let reg = (rd + r) % 32;
                let mut vector = if load {
                    [0; 16]
                } else {
                    self.v[reg].to_le_bytes()
                };
                for i in 0..bytes / size {
                    let offset = if structures == 1 {
                        r * bytes + i * size
                    } else {
                        (i * structures + r) * size
                    };
                    if load {
                        vector[i * size..(i + 1) * size]
                            .copy_from_slice(&buffer[offset..offset + size]);
                    } else {
                        buffer[offset..offset + size]
                            .copy_from_slice(&vector[i * size..(i + 1) * size]);
                    }
                }
                if load {
                    self.v[reg] = u128::from_le_bytes(vector);
                }
            }
            if !load {
                memory.write(address, &buffer)?;
            }
            if op & (1 << 23) != 0 {
                self.set(
                    rn,
                    address.wrapping_add(if rm == 31 {
                        total as u64
                    } else {
                        self.reg(rm, false)
                    }),
                    true,
                    true,
                );
            }
            return Ok(true);
        } else if op & 0xbf000000 == 0x0d000000 {
            // single lane / replicate structure
            let opcode = (op >> 13) & 7;
            let scale = opcode >> 1;
            let registers = (((opcode & 1) << 1) | ((op >> 21) & 1)) + 1;
            let field = (op >> 10) & 3;
            let s = (op >> 12) & 1;
            let (size, index, replicate) = match scale {
                0 => (1, q * 8 + s * 4 + field, false),
                1 if field & 1 == 0 => (2, q * 4 + s * 2 + (field >> 1), false),
                2 if field == 0 => (4, q * 2 + s, false),
                2 if field == 1 && s == 0 => (8, q, false),
                3 if s == 0 && op & (1 << 22) != 0 => (1 << field, 0, true),
                _ => return Err(Fault::UnsupportedInstruction(op)),
            };
            let address = self.reg(rn, true);
            let load = op & (1 << 22) != 0;
            for r in 0..registers {
                let reg = (rd + r as usize) % 32;
                let at = address.checked_add((r * size) as u64).ok_or(Fault::Read)?;
                if load {
                    let value = memory.load(at, size as usize)? as u128;
                    if replicate {
                        let mut v = 0;
                        for i in 0..width / (size * 8) {
                            v |= value << (i * size * 8);
                        }
                        self.v[reg] = v;
                    } else {
                        let shift = index * size * 8;
                        self.v[reg] = self.v[reg] & !(bits(size * 8) << shift) | value << shift;
                    }
                } else {
                    memory.store(at, size as usize, lane(self.v[reg], index, size * 8) as u64)?;
                }
            }
            if op & (1 << 23) != 0 {
                self.set(
                    rn,
                    address.wrapping_add(if rm == 31 {
                        (registers * size) as u64
                    } else {
                        self.reg(rm, false)
                    }),
                    true,
                    true,
                );
            }
            return Ok(true);
        } else {
            return Ok(false);
        }
        self.v[rd] = result;
        Ok(true)
    }
}
