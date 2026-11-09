// Independent ISA regression inputs; assembled using LLVM (Zig cc).
.text
.global scalar_cases
scalar_cases:
 and x2, x0, #0xff00ff00ff00ff00
 orr w3, w0, #0x80000001
 ubfx x4, x0, #12, #20
 sbfx w5, w1, #4, #8
 bfi x6, x1, #16, #8
 extr x7, x0, x1, #8
 add x8, x0, w1, sxtw #2
 csel x9, x0, x1, eq
 csneg x10, x0, x1, ne
 ccmp x0, #7, #9, eq
 mul x11, x0, x1
 umulh x12, x0, x1
 smulh x13, x0, x1
 smaddl x14, w0, w1, x2
 udiv x15, x0, x1
 sdiv w16, w0, w1
 lsl x17, x0, x1
 ror w18, w0, w1
 rev x19, x0
 clz w20, w0
 rbit x21, x0
 stp x0, x1, [sp, #-16]!
 ldp x22, x23, [sp], #16
 str w0, [sp, #-4]!
 ldrsb w24, [sp], #4
 ldrsw x25, [sp, w1, uxtw #2]
 mrs x26, tpidr_el0
 ret
.global vector_cases
vector_cases:
 dup v2.4s, w0
 movi v3.16b, #0x93
 mvni v4.4s, #0xff, lsl #8
 add v5.4s, v0.4s, v1.4s
 mul v6.4s, v0.4s, v1.4s
 mla v7.4s, v0.4s, v1.4s
 sub v8.8h, v0.8h, v1.8h
 ushll v9.2d, v0.2s, #0
 ushll2 v10.2d, v0.4s, #0
 xtn v11.2s, v1.2d
 xtn2 v11.4s, v0.2d
 shl v12.4s, v0.4s, #1
 ushr v13.4s, v0.4s, #32
 neg v14.4s, v0.4s
 cmeq v15.4s, v0.4s, v1.4s
 cnt v16.16b, v0.16b
 uaddlv h17, v16.16b
 mov x1, v0.d[1]
 fmov x2, d0
 fmov d18, x0
 ext v19.16b, v0.16b, v1.16b, #8
 ld1r {v20.4s}, [x0]
 st1 {v20.s}[2], [x1]
 ld2 {v21.4s, v22.4s}, [x0], #32
 st2 {v21.4s, v22.4s}, [x1], #32
 ldr q23, [x0]
 str q23, [x1]
 ret
