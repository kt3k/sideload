use super::*;
mod fixture {
    include!("../../tests/fixtures/aarch64_extended.rs");
}
fn program(words: &[u32]) -> (Cpu, Memory) {
    let bytes: Vec<_> = words.iter().flat_map(|op| op.to_le_bytes()).collect();
    let mut memory = Memory::default();
    memory
        .map(0x1000, bytes.len(), &bytes, Permissions::CODE)
        .unwrap();
    memory.map(0x3000, 512, &[], Permissions::DATA).unwrap();
    let mut cpu = Cpu {
        pc: 0x1000,
        sp: 0x3100,
        ..Cpu::default()
    };
    cpu.x[30] = 0x8000;
    (cpu, memory)
}
fn steps(cpu: &mut Cpu, memory: &mut Memory, n: usize) {
    for _ in 0..n {
        cpu.step(memory).unwrap();
    }
}
fn words(values: &[u32]) -> u128 {
    values
        .iter()
        .enumerate()
        .map(|(i, n)| (*n as u128) << (i * 32))
        .sum()
}
#[test]
fn assembled_scalar_semantics() {
    let (mut c, mut m) = program(&fixture::SCALAR[..21]);
    c.x[0] = 0x0123456789abcdef;
    c.x[1] = 0xff0;
    c.x[6] = u64::MAX;
    c.nzcv = 4;
    steps(&mut c, &mut m, 21);
    assert_eq!(c.x[2], 0x010045008900cd00);
    assert_eq!(c.x[3], 0x89abcdef);
    assert_eq!(c.x[4], 0x89abc);
    assert_eq!(c.x[5], 0xffffffff);
    assert_eq!(c.x[6], 0xfffffffffff0ffff);
    assert_eq!(c.x[7], 0xef0000000000000f);
    assert_eq!(c.x[8], 0x0123456789ac0daf);
    assert_eq!(c.x[9], c.x[0]);
    assert_eq!(c.x[10], 0u64.wrapping_sub(0xff0));
    assert_eq!(c.nzcv, 2);
    assert_eq!(c.x[11], 0x2222222222221110);
    assert_eq!(c.x[12], 0x12);
    assert_eq!(c.x[13], 0x12);
    assert_eq!(c.x[14], 0x01003da2ab22de10);
    assert_eq!(c.x[15], 0x12469d15b06d);
    assert_eq!(c.x[16], 0xfff89351);
    assert_eq!(c.x[17], 0xcdef000000000000);
    assert_eq!(c.x[18], 0xcdef89ab);
    assert_eq!(c.x[19], 0xefcdab8967452301);
    assert_eq!(c.x[20], 0);
    assert_eq!(c.x[21], 0xf7b3d591e6a2c480);
}
#[test]
fn assembled_signed_memory_indexing_and_tls() {
    let (mut c, mut m) = program(&fixture::SCALAR[21..]);
    c.x[0] = u64::MAX;
    c.x[1] = 2;
    c.tpidr = 0x5678;
    m.write(0x3108, &0x80000000u32.to_le_bytes()).unwrap();
    c.run(&mut m, 0x8000, 7).unwrap();
    assert_eq!(c.x[22], u64::MAX);
    assert_eq!(c.x[23], 2);
    assert_eq!(c.x[24], 0xffffffff);
    assert_eq!(c.x[25], 0xffffffff80000000);
    assert_eq!(c.x[26], 0x5678);
    assert_eq!(c.sp, 0x3100);
}
#[test]
fn assembled_integer_simd_semantics() {
    let (mut c, mut m) = program(&fixture::VECTOR[..21]);
    c.x[0] = 0x12345678;
    c.v[0] = words(&[u32::MAX, 0x80000000, 3, 4]);
    c.v[1] = words(&[1, 0x80000000, 5, 4]);
    c.v[7] = words(&[1, 1, 1, 1]);
    steps(&mut c, &mut m, 21);
    assert_eq!(c.v[2], words(&[0x12345678; 4]));
    assert_eq!(c.v[3], u128::from_le_bytes([0x93; 16]));
    assert_eq!(c.v[4], words(&[0xffff00ff; 4]));
    assert_eq!(c.v[5], words(&[0, 0, 8, 8]));
    assert_eq!(c.v[6], words(&[u32::MAX, 0, 15, 16]));
    assert_eq!(c.v[7], words(&[0, 1, 16, 17]));
    assert_eq!(c.v[8], words(&[0xfffffffe, 0, 0xfffe, 0]));
    assert_eq!(c.v[9], 0x0000000080000000_00000000ffffffff);
    assert_eq!(c.v[10], 0x0000000000000004_0000000000000003);
    assert_eq!(c.v[11], words(&[1, 5, u32::MAX, 3]));
    assert_eq!(c.v[12], words(&[0xfffffffe, 0, 6, 8]));
    assert_eq!(c.v[13], 0);
    assert_eq!(c.v[14], words(&[1, 0x80000000, 0xfffffffd, 0xfffffffc]));
    assert_eq!(c.v[15], words(&[0, u32::MAX, 0, u32::MAX]));
    assert_eq!(c.v[17], 36);
    assert_eq!(c.x[1], 0x0000000400000003);
    assert_eq!(c.x[2], 0x80000000ffffffff);
    assert_eq!(c.v[18], 0x12345678);
    assert_eq!(c.v[19], 0x8000000000000001_0000000400000003);
}
#[test]
fn assembled_simd_structure_round_trip_and_writeback() {
    let (mut c, mut m) = program(&fixture::VECTOR[21..]);
    let bytes: Vec<_> = (1u32..=12).flat_map(u32::to_le_bytes).collect();
    m.write(0x3000, &bytes).unwrap();
    c.x[0] = 0x3000;
    c.x[1] = 0x3080;
    c.run(&mut m, 0x8000, 7).unwrap();
    assert_eq!(c.v[20], words(&[1, 1, 1, 1]));
    assert_eq!(c.v[21], words(&[1, 3, 5, 7]));
    assert_eq!(c.v[22], words(&[2, 4, 6, 8]));
    assert_eq!(m.read(0x3080, 48).unwrap(), bytes);
    assert_eq!(c.x[0], 0x3020);
    assert_eq!(c.x[1], 0x30a0);
}
