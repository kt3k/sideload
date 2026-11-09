// Independently assembled fixtures for emulation.rs. LLVM/Zig assembler:
// zig cc -target aarch64-linux-gnu -c aarch64.S -o /tmp/aarch64.o
// No Apple binaries or external emulator source are used here.
.text
.global sum
sum:
    mov x0, #0
    mov x1, #10
1:  add x0, x0, x1
    subs x1, x1, #1
    b.ne 1b
    ret
.global data_roundtrip
data_roundtrip:
    str x0, [x1, #8]
    ldr w2, [x1, #8]
    mov w3, w2
    ret
.global call_and_stack
call_and_stack:
    sub sp, sp, #16
    str x30, [sp, #8]
    bl increment
    ldr x30, [sp, #8]
    add sp, sp, #16
    ret
increment:
    add w0, w0, #1
    ret
.global constants
constants:
.Lconstants:
    movz x0, #0x1234, lsl #48
    movk x0, #0xabcd, lsl #16
    movn w1, #0
    eor x2, x0, x1, ror #8
    adr x3, .Lconstants
    ret
