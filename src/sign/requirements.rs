//! Designated requirement: identifier AND Apple generic anchor AND leaf OU.
use super::{
    SignResult,
    code_directory::{blob, superblob, u32be},
};
use std::collections::BTreeMap;
fn data(out: &mut Vec<u8>, s: &str) {
    u32be(out, s.len() as u32);
    out.extend(s.as_bytes());
    while out.len() % 4 != 0 {
        out.push(0);
    }
}
pub fn designated(identifier: &str, team: &str) -> SignResult<Vec<u8>> {
    let mut expr = Vec::new();
    for n in [1, 6, 6, 2] {
        u32be(&mut expr, n);
    } // expression form, and(and(identifier, anchor), OU)
    data(&mut expr, identifier);
    u32be(&mut expr, 15);
    u32be(&mut expr, 11);
    u32be(&mut expr, 0);
    data(&mut expr, "subject.OU");
    u32be(&mut expr, 1);
    data(&mut expr, team);
    superblob(0xfade0c01, &BTreeMap::from([(3, blob(0xfade0c00, &expr))]))
}
