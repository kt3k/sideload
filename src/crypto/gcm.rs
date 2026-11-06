//! AES-256-GCM (NIST SP 800-38D) with arbitrary-length IVs.
//!
//! GSA app tokens use 16-byte IVs, which `ring` does not support. This is a
//! straightforward, table-free GHASH; it is not constant-time with respect
//! to the hash key, which is acceptable for decrypting data received from
//! Apple on the user's own machine.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};

use super::{CryptoError, CryptoResult};

const TAG_LEN: usize = 16;

fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

struct Ghash {
    h: u128,
    acc: u128,
}

impl Ghash {
    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.acc = gf_mul(self.acc ^ u128::from_be_bytes(block), self.h);
        }
    }

    fn lengths(&mut self, a_bits: u64, c_bits: u64) {
        let block = (u128::from(a_bits) << 64) | u128::from(c_bits);
        self.acc = gf_mul(self.acc ^ block, self.h);
    }
}

struct Gcm {
    aes: Aes256,
    h: u128,
}

impl Gcm {
    fn new(key: &[u8]) -> CryptoResult<Gcm> {
        let aes = Aes256::new_from_slice(key)
            .map_err(|_| CryptoError::new("AES-256 key must be 32 bytes"))?;
        let mut zero = GenericArray::default();
        aes.encrypt_block(&mut zero);
        let h = u128::from_be_bytes(zero.into());
        Ok(Gcm { aes, h })
    }

    fn encrypt_counter(&self, counter: u128) -> [u8; 16] {
        let mut block = GenericArray::from(counter.to_be_bytes());
        self.aes.encrypt_block(&mut block);
        block.into()
    }

    fn j0(&self, iv: &[u8]) -> u128 {
        if iv.len() == 12 {
            let mut b = [0u8; 16];
            b[..12].copy_from_slice(iv);
            b[15] = 1;
            u128::from_be_bytes(b)
        } else {
            let mut g = Ghash { h: self.h, acc: 0 };
            g.update(iv);
            g.lengths(0, (iv.len() as u64) * 8);
            g.acc
        }
    }

    fn ctr(&self, j0: u128, data: &mut [u8]) {
        let mut counter = j0;
        for chunk in data.chunks_mut(16) {
            // inc32: only the low 32 bits wrap.
            counter = (counter & !0xFFFF_FFFF) | u128::from((counter as u32).wrapping_add(1));
            let ks = self.encrypt_counter(counter);
            for (b, k) in chunk.iter_mut().zip(ks) {
                *b ^= k;
            }
        }
    }

    fn tag(&self, j0: u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut g = Ghash { h: self.h, acc: 0 };
        g.update(aad);
        g.update(ciphertext);
        g.lengths((aad.len() as u64) * 8, (ciphertext.len() as u64) * 8);
        let mask = self.encrypt_counter(j0);
        let mut t = g.acc.to_be_bytes();
        for (b, m) in t.iter_mut().zip(mask) {
            *b ^= m;
        }
        t
    }
}

/// Returns `ciphertext || tag`.
pub fn encrypt(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if iv.is_empty() {
        return Err(CryptoError::new("GCM IV must not be empty"));
    }
    let gcm = Gcm::new(key)?;
    let j0 = gcm.j0(iv);
    let mut out = plaintext.to_vec();
    gcm.ctr(j0, &mut out);
    let tag = gcm.tag(j0, aad, &out);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts `ciphertext || tag`, verifying the tag.
pub fn decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> CryptoResult<Vec<u8>> {
    if iv.is_empty() {
        return Err(CryptoError::new("GCM IV must not be empty"));
    }
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(CryptoError::new("GCM input shorter than the tag"));
    }
    let gcm = Gcm::new(key)?;
    let j0 = gcm.j0(iv);
    let (ct, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);
    let expected = gcm.tag(j0, aad, ct);
    if !super::ct_eq(&expected, tag) {
        return Err(CryptoError::new("GCM authentication failed"));
    }
    let mut out = ct.to_vec();
    gcm.ctr(j0, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    /// Vectors from Python `cryptography` (OpenSSL), key = 00..1f.
    #[test]
    #[allow(clippy::type_complexity)]
    fn matches_python_cryptography() {
        let key: Vec<u8> = (0..32).collect();
        let cases: [(Vec<u8>, &[u8], Vec<u8>, &str); 3] = [
            (
                (0x10..0x20).collect(),
                b"XYZ",
                b"token payload 123".to_vec(),
                "fe35510589514bce1267f108d380203383a89ee719886d69acade691275b8ae15e",
            ),
            (vec![0; 12], b"", vec![], "f05d76ae4ab99fe5a6f69b3148c2363d"),
            (
                (0..60).collect(),
                b"aad",
                vec![b'x'; 40],
                "36b9f6ecc10bbe8199795ea04a369cb3c2e7c1da481a8564206a16dcaee331fa31bd62feccb077ed645136451bea626e2916439186098ad0",
            ),
        ];
        for (iv, aad, pt, expected) in cases {
            let ct = encrypt(&key, &iv, aad, &pt).unwrap();
            assert_eq!(hex(&ct), expected);
            assert_eq!(decrypt(&key, &iv, aad, &ct).unwrap(), pt);
        }
    }

    #[test]
    fn rejects_tampering() {
        let key = [7u8; 32];
        let iv = [1u8; 16];
        let mut ct = encrypt(&key, &iv, b"XYZ", b"secret").unwrap();
        assert!(decrypt(&key, &iv, b"XYZ", &ct).is_ok());
        assert!(decrypt(&key, &iv, b"XYW", &ct).is_err());
        ct[0] ^= 1;
        assert!(decrypt(&key, &iv, b"XYZ", &ct).is_err());
        assert!(decrypt(&key, &iv, b"", &[0; 8]).is_err());
    }
}
