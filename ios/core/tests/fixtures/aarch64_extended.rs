// Generated from aarch64-extended.S with LLVM; no vendor code.
pub const SCALAR: &[u32] = &[
    0x92089c02, // and x2, x0, #0xff00ff00ff00ff00
    0x32010403, // orr w3, w0, #0x80000001
    0xd34c7c04, // ubfx x4, x0, #0xc, #0x14
    0x13042c25, // sbfx w5, w1, #4, #8
    0xb3701c26, // bfi x6, x1, #0x10, #8
    0x93c12007, // extr x7, x0, x1, #8
    0x8b21c808, // add x8, x0, w1, sxtw #2
    0x9a810009, // csel x9, x0, x1, eq
    0xda81140a, // csneg x10, x0, x1, ne
    0xfa470809, // ccmp x0, #7, #9, eq
    0x9b017c0b, // mul x11, x0, x1
    0x9bc17c0c, // umulh x12, x0, x1
    0x9b417c0d, // smulh x13, x0, x1
    0x9b21080e, // smaddl x14, w0, w1, x2
    0x9ac1080f, // udiv x15, x0, x1
    0x1ac10c10, // sdiv w16, w0, w1
    0x9ac12011, // lsl x17, x0, x1
    0x1ac12c12, // ror w18, w0, w1
    0xdac00c13, // rev x19, x0
    0x5ac01014, // clz w20, w0
    0xdac00015, // rbit x21, x0
    0xa9bf07e0, // stp x0, x1, [sp, #-0x10]!
    0xa8c15ff6, // ldp x22, x23, [sp], #0x10
    0xb81fcfe0, // str w0, [sp, #-4]!
    0x38c047f8, // ldrsb w24, [sp], #4
    0xb8a15bf9, // ldrsw x25, [sp, w1, uxtw #2]
    0xd53bd05a, // mrs x26, tpidr_el0
    0xd65f03c0, // ret 
];
pub const VECTOR: &[u32] = &[
    0x4e040c02, // dup v2.4s, w0
    0x4f04e663, // movi v3.16b, #0x93
    0x6f0727e4, // mvni v4.4s, #0xff, lsl #8
    0x4ea18405, // add v5.4s, v0.4s, v1.4s
    0x4ea19c06, // mul v6.4s, v0.4s, v1.4s
    0x4ea19407, // mla v7.4s, v0.4s, v1.4s
    0x6e618408, // sub v8.8h, v0.8h, v1.8h
    0x2f20a409, // ushll v9.2d, v0.2s, #0
    0x6f20a40a, // ushll2 v10.2d, v0.4s, #0
    0x0ea1282b, // xtn v11.2s, v1.2d
    0x4ea1280b, // xtn2 v11.4s, v0.2d
    0x4f21540c, // shl v12.4s, v0.4s, #1
    0x6f20040d, // ushr v13.4s, v0.4s, #0x20
    0x6ea0b80e, // neg v14.4s, v0.4s
    0x6ea18c0f, // cmeq v15.4s, v0.4s, v1.4s
    0x4e205810, // cnt v16.16b, v0.16b
    0x6e303a11, // uaddlv h17, v16.16b
    0x4e183c01, // mov x1, v0.d[1]
    0x9e660002, // fmov x2, d0
    0x9e670012, // fmov d18, x0
    0x6e014013, // ext v19.16b, v0.16b, v1.16b, #8
    0x4d40c814, // ld1r {v20.4s}, [x0]
    0x4d008034, // st1 {v20.s}[2], [x1]
    0x4cdf8815, // ld2 {v21.4s, v22.4s}, [x0], #32
    0x4c9f8835, // st2 {v21.4s, v22.4s}, [x1], #32
    0x3dc00017, // ldr q23, [x0]
    0x3d800037, // str q23, [x1]
    0xd65f03c0, // ret 
];
