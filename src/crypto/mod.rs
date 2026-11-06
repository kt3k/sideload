//! Protocol-level crypto built on vetted primitives.
//!
//! Primitives come from external crates and are never hand-written here:
//! SHA-1/SHA-256, HMAC, PBKDF2, RSA signing and randomness from `ring`; the
//! AES block cipher from `aes`. This module adds the modes and protocols
//! `ring` does not offer:
//!
//! - `cbc`: AES-256-CBC (GSA `spd` decryption).
//! - `gcm`: AES-256-GCM with 16-byte IVs (GSA app tokens; `ring` only
//!   supports 12-byte nonces).
//! - `srp`: SRP-6a client in Apple's GSA variant.
//! - `rsa_keygen`: RSA-2048 key generation, PKCS#8 encoding and signing.

pub mod cbc;
pub mod gcm;
pub mod rsa_keygen;
pub mod srp;

use std::fmt;

use ring::{digest, hmac, pbkdf2, rand::SecureRandom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub String);

impl CryptoError {
    pub fn new(msg: impl Into<String>) -> Self {
        CryptoError(msg.into())
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    d.as_ref().try_into().expect("SHA-1 is 20 bytes")
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// Streaming SHA-256 over several parts.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    for p in parts {
        ctx.update(p);
    }
    ctx.sign()
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes")
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> CryptoResult<[u8; 32]> {
    let iterations = std::num::NonZeroU32::new(iterations)
        .ok_or_else(|| CryptoError::new("PBKDF2 iteration count must be positive"))?;
    let mut out = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut out,
    );
    Ok(out)
}

pub fn random_bytes(n: usize) -> CryptoResult<Vec<u8>> {
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| CryptoError::new("system random number generator failed"))?;
    Ok(buf)
}

/// Compares two byte strings without an early exit on the first mismatch.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Lowercase hexadecimal.
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_parts(&[b"a", b"bc"]), sha256(b"abc"));
    }

    #[test]
    fn hmac_rfc4231_case2() {
        assert_eq!(
            hex(&hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pbkdf2_rfc7914_vector() {
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1), first 32 bytes.
        assert_eq!(
            hex(&pbkdf2_sha256(b"passwd", b"salt", 1).unwrap()),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert!(pbkdf2_sha256(b"x", b"y", 0).is_err());
    }
}
