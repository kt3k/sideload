//! AES-256-CBC with PKCS#7 padding.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use super::{CryptoError, CryptoResult};

fn cipher(key: &[u8]) -> CryptoResult<Aes256> {
    Aes256::new_from_slice(key).map_err(|_| CryptoError::new("AES-256 key must be 32 bytes"))
}

pub fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let c = cipher(key)?;
    if iv.len() != 16 {
        return Err(CryptoError::new("CBC IV must be 16 bytes"));
    }
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(CryptoError::new(
            "CBC ciphertext is not a multiple of 16 bytes",
        ));
    }
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        c.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        out.extend_from_slice(&block);
        prev.copy_from_slice(chunk);
    }
    let pad = usize::from(*out.last().unwrap_or(&0));
    if pad == 0
        || pad > 16
        || !out[out.len() - pad..]
            .iter()
            .all(|&b| usize::from(b) == pad)
    {
        return Err(CryptoError::new("invalid PKCS#7 padding"));
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

pub fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let c = cipher(key)?;
    if iv.len() != 16 {
        return Err(CryptoError::new("CBC IV must be 16 bytes"));
    }
    let pad = 16 - data.len() % 16;
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = GenericArray::clone_from_slice(iv);
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        c.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    /// Python `cryptography`: AES-256-CBC, PKCS7, key=00..1f, iv=a0..af.
    #[test]
    fn matches_python_cryptography() {
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0xa0..0xb0).collect();
        let pt = b"The quick brown fox jumps over the lazy dog";
        let ct = encrypt(&key, &iv, pt).unwrap();
        assert_eq!(
            hex(&ct),
            "64bac78bf92341822f9cb229d5199006d90c3bab4f7eaa663a51e8c75086e82cabdf122926fa3b24d4f3c9bafa5236b6"
        );
        assert_eq!(decrypt(&key, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn rejects_bad_input() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        assert!(decrypt(&key, &iv, &[0; 15]).is_err());
        assert!(decrypt(&key[..16], &iv, &[0; 16]).is_err());
        let mut ct = encrypt(&key, &iv, b"hello").unwrap();
        ct[15] ^= 0xFF; // corrupts the padding byte
        assert!(decrypt(&key, &iv, &ct).is_err());
    }
}
