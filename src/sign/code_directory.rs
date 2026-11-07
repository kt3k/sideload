//! Apple's CodeDirectory and embedded signature blob encodings (big endian).
use super::{SignResult, fail};
use crate::crypto::{sha1, sha256};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    Sha1,
    Sha256,
}
impl HashType {
    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1(data).to_vec(),
            Self::Sha256 => sha256(data).to_vec(),
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }
}
pub(crate) fn u32be(out: &mut Vec<u8>, n: u32) {
    out.extend(n.to_be_bytes());
}
pub fn blob(magic: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    u32be(&mut out, magic);
    u32be(&mut out, (data.len() + 8) as u32);
    out.extend(data);
    out
}
pub fn superblob(magic: u32, slots: &BTreeMap<u32, Vec<u8>>) -> SignResult<Vec<u8>> {
    let size = 12usize
        .checked_add(slots.len() * 8)
        .and_then(|n| slots.values().try_fold(n, |a, b| a.checked_add(b.len())))
        .ok_or_else(|| fail("signature too large"))?;
    let size = u32::try_from(size).map_err(|_| fail("signature exceeds 4 GiB"))?;
    let mut out = Vec::new();
    u32be(&mut out, magic);
    u32be(&mut out, size);
    u32be(&mut out, slots.len() as u32);
    let mut offset = 12 + slots.len() * 8;
    for (slot, data) in slots {
        u32be(&mut out, *slot);
        u32be(&mut out, offset as u32);
        offset += data.len();
    }
    for data in slots.values() {
        out.extend(data);
    }
    Ok(out)
}
/// Special slot values are the complete blobs, except Info.plist and CodeResources,
/// which are the exact bytes on disk. Missing slots are zero-filled.
pub fn build(
    code: &[u8],
    identifier: &str,
    team: &str,
    special: &BTreeMap<u32, Vec<u8>>,
    hash: HashType,
    executable_segment: (u64, u64, u64),
) -> SignResult<Vec<u8>> {
    if identifier.is_empty() || team.is_empty() || identifier.contains('\0') || team.contains('\0')
    {
        return Err(fail("invalid signing identifier or team"));
    }
    let limit = u32::try_from(code.len()).map_err(|_| fail("Mach-O slice exceeds 4 GiB"))?;
    let count = code.len().div_ceil(4096);
    let ns = special.keys().copied().max().unwrap_or(0);
    if ns > 7 {
        return Err(fail("unsupported special slot"));
    }
    let mut strings = identifier.as_bytes().to_vec();
    strings.push(0);
    let team_offset = 88 + strings.len();
    strings.extend(team.as_bytes());
    strings.push(0);
    let hash_offset = 88 + strings.len() + ns as usize * hash.size();
    let length = hash_offset + count * hash.size();
    let mut out = Vec::new();
    for n in [
        0xfade0c02,
        length as u32,
        0x20400,
        0,
        hash_offset as u32,
        88,
        ns,
        count as u32,
        limit,
    ] {
        u32be(&mut out, n);
    }
    out.extend([hash.size() as u8, hash.code(), 0, 12]);
    for n in [0, 0, team_offset as u32, 0] {
        u32be(&mut out, n);
    }
    out.extend(0u64.to_be_bytes());
    out.extend(executable_segment.0.to_be_bytes());
    out.extend(executable_segment.1.to_be_bytes());
    out.extend(executable_segment.2.to_be_bytes());
    out.extend(strings);
    for slot in (1..=ns).rev() {
        match special.get(&slot) {
            Some(b) => out.extend(hash.digest(b)),
            None => out.resize(out.len() + hash.size(), 0),
        }
    }
    for page in code.chunks(4096) {
        out.extend(hash.digest(page));
    }
    Ok(out)
}
pub fn cdhash(directory: &[u8], hash: HashType) -> Vec<u8> {
    hash.digest(directory)[..20].to_vec()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pages_and_special_slots() {
        let code = vec![42; 4097];
        let mut slots = BTreeMap::new();
        slots.insert(2, b"requirements".to_vec());
        for hash in [HashType::Sha1, HashType::Sha256] {
            let cd = build(&code, "com.test", "TEAM", &slots, hash, (0, 4096, 1)).unwrap();
            let off = u32::from_be_bytes(cd[16..20].try_into().unwrap()) as usize;
            assert_eq!(&cd[off..off + hash.size()], hash.digest(&code[..4096]));
            assert_eq!(&cd[off + hash.size()..], hash.digest(&code[4096..]));
            assert_eq!(&cd[off - hash.size()..off], vec![0; hash.size()]);
            assert_eq!(
                &cd[off - 2 * hash.size()..off - hash.size()],
                hash.digest(b"requirements")
            );
        }
    }
}
