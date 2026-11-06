//! SRP-6a client, GSA variant (2048-bit RFC 5054 group, SHA-256).
//!
//! Apple's differences from textbook SRP:
//! - The SRP password is `PBKDF2-HMAC-SHA256(p, salt, iterations, 32)`
//!   where `p = SHA256(password)` (`s2k`) or its lowercase hex (`s2k_fo`).
//! - `x = H(salt | H(":" | password_key))`: the username is not in `x`.
//! - `M1 = H(H(N) xor H(PAD(g)) | H(username) | salt | A | B | K)` with
//!   `K = H(S)`, and `M2 = H(A | M1 | K)`.

use num_bigint::BigUint;
use num_traits::Zero;

use super::{
    CryptoError, CryptoResult, hmac_sha256, pbkdf2_sha256, random_bytes, sha256, sha256_parts,
};

const N_HEX: &str = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73";
const N_LEN: usize = 256;

fn n() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid group modulus")
}

fn g() -> BigUint {
    BigUint::from(2u32)
}

fn pad(v: &BigUint) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; N_LEN.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

fn minimal(v: &BigUint) -> Vec<u8> {
    if v.is_zero() {
        Vec::new()
    } else {
        v.to_bytes_be()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Password hashed with SHA-256.
    S2k,
    /// Password hashed with SHA-256, then lowercase hex encoded.
    S2kFo,
}

impl Protocol {
    pub fn from_name(name: &str) -> Option<Protocol> {
        match name {
            "s2k" => Some(Protocol::S2k),
            "s2k_fo" => Some(Protocol::S2kFo),
            _ => None,
        }
    }
}

pub struct SrpClient {
    a: BigUint,
    a_pub: BigUint,
}

/// The result of processing the server's challenge.
pub struct SrpSession {
    pub m1: [u8; 32],
    m2: [u8; 32],
    /// Session key `K = H(S)`.
    pub key: [u8; 32],
}

impl SrpClient {
    pub fn new() -> CryptoResult<SrpClient> {
        Ok(Self::with_private(&random_bytes(32)?))
    }

    /// Deterministic constructor for tests.
    pub fn with_private(a: &[u8]) -> SrpClient {
        let a = BigUint::from_bytes_be(a);
        let a_pub = g().modpow(&a, &n());
        SrpClient { a, a_pub }
    }

    /// `A`, big-endian without padding (as sent to GSA).
    pub fn public_ephemeral(&self) -> Vec<u8> {
        minimal(&self.a_pub)
    }

    pub fn process(
        &self,
        username: &str,
        password: &str,
        protocol: Protocol,
        salt: &[u8],
        iterations: u32,
        b_pub_bytes: &[u8],
    ) -> CryptoResult<SrpSession> {
        let n = n();
        let g = g();
        let b_pub = BigUint::from_bytes_be(b_pub_bytes);
        if (&b_pub % &n).is_zero() {
            return Err(CryptoError::new("SRP: server sent an invalid public value"));
        }

        let hashed = sha256(password.as_bytes());
        let password_input = match protocol {
            Protocol::S2k => hashed.to_vec(),
            Protocol::S2kFo => super::hex(&hashed).into_bytes(),
        };
        let password_key = pbkdf2_sha256(&password_input, salt, iterations)?;

        let k = BigUint::from_bytes_be(&sha256_parts(&[&pad(&n), &pad(&g)]));
        let u = BigUint::from_bytes_be(&sha256_parts(&[&pad(&self.a_pub), &pad(&b_pub)]));
        if u.is_zero() {
            return Err(CryptoError::new("SRP: invalid scrambling parameter"));
        }
        let inner = sha256_parts(&[b":", &password_key]);
        let x = BigUint::from_bytes_be(&sha256_parts(&[salt, &inner]));

        // S = (B - k * g^x) ^ (a + u * x) mod N
        let kv = (&k * g.modpow(&x, &n)) % &n;
        let base = ((&b_pub % &n) + &n - kv) % &n;
        let s = base.modpow(&(&self.a + &u * &x), &n);
        let key = sha256(&minimal(&s));

        let hn = sha256(&minimal(&n));
        let hg = sha256(&pad(&g));
        let mut hxor = [0u8; 32];
        for (i, b) in hxor.iter_mut().enumerate() {
            *b = hn[i] ^ hg[i];
        }
        let a_bytes = minimal(&self.a_pub);
        let m1 = sha256_parts(&[
            &hxor,
            &sha256(username.as_bytes()),
            salt,
            &a_bytes,
            b_pub_bytes,
            &key,
        ]);
        let m2 = sha256_parts(&[&a_bytes, &m1, &key]);
        Ok(SrpSession { m1, m2, key })
    }
}

impl SrpSession {
    pub fn verify_server(&self, m2: &[u8]) -> bool {
        super::ct_eq(&self.m2, m2)
    }

    /// AES-256-CBC key and IV for the `spd` field:
    /// `HMAC(K, "extra data key:")` and the first 16 bytes of
    /// `HMAC(K, "extra data iv:")`.
    pub fn extra_data_key_iv(&self) -> ([u8; 32], [u8; 16]) {
        let key = hmac_sha256(&self.key, &[b"extra data key:"]);
        let iv_full = hmac_sha256(&self.key, &[b"extra data iv:"]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_full[..16]);
        (key, iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Expected values come from an independent Python implementation of
    /// the same formulas (server side: `B = k*v + g^b`, `S = (A v^u)^b`).
    #[test]
    fn matches_independent_server_computation() {
        let client = SrpClient::with_private(&(1..=32).collect::<Vec<u8>>());
        assert!(
            hex(&client.public_ephemeral())
                .starts_with("630acdff5d334462d92a29e0b7fa6e20020f3333292f6d3a640f1c7a76ad9d31")
        );
        let salt: Vec<u8> = (0..16).collect();
        let cases = [
            (
                Protocol::S2k,
                "a6ff0b1a39cb3af3dd11c5b9306d754f6074f2231786a5d7c45eeec4fab2763165f2d0d8d2c6308fad349f86431fb9f1a58eea76a4dc2de277e26e8cd6935df77704a5a13c0617218d1e0305206147471c3e8d7acdb578e1cd9699a6f5ef33d3eced4e9382a418615e43469d730a7d36526f844fae706e60412873620a279f7aed54d91fabadb943459ac2caf12451a872febda93c516e8ea143077a723e4af7e87d5421e19ea513d87199826e84086391472753478c877adf73db0643659cce9ed4c440ee6932cef644f9ac07967137ab57f3b4f82cf14d17c778998d937e4813b90f6ef88ceadab733b966ed25f18fc8ef178c138e46a5cf063e47c0360f2a",
                "afd706f4aafc8cc1c2fca2585544ac1ea1a98be0e4deb0d6cba4ea4242a603fd",
                "9cee2b914d55825cb8d709cebd9247a157c4991acba81cddaf7ca51c52754fdc",
                "9addb043e7b4baeb793fe53ff25e6b4fa12b3c91bb6df1a41a243ab82a485d6f",
            ),
            (
                Protocol::S2kFo,
                "5aa57459b3e1558e19f194e319ac21d08a8749ce743a014ba9dae344aaac5a45e85206e76a4e7046f92d5e16046e4ae90bb72e117c1bfe16c0daa6245e2b1e5907810a1c2aa757ca594cf8864ab6877d58f0bf6abfe6f8f55c87cb127ba7c7fc75949606742fd4d91f7102e53150cbcdcb8e869aafad5d9aeed904f17c81e2e51cbb5bacecf4fd971ca82e62cecb9e49d2e421a22602d75d7330787769c457794ee6abb83a2d44d16e87e7d7dd31c41288c36bf293dfca67309f068ccecd3b1935e5b4e7d4cec44d8ee210e5729c2394c82f8372ddb001e1c8bc8e9ef84c8588ddaaaa0ccf73152f1cb9f86cb9856dbd7cfa02bec639e25d9ecbe5ac62552662",
                "f85679824ce1b4fc93e49d95b730f5833222a622af498b67242f980dfd6344aa",
                "cf9b85be4b8e1edb6397ba7ec9ba3000fc98fd0676d814ce19a99113c51499b6",
                "1ce5668bcabc17975eb5636879f3d3e83c07acbb1146bf96ac0b072ceb646525",
            ),
        ];
        for (protocol, b, k, m1, m2) in cases {
            let s = client
                .process(
                    "user@example.com",
                    "correct horse",
                    protocol,
                    &salt,
                    1000,
                    &unhex(b),
                )
                .unwrap();
            assert_eq!(hex(&s.key), k, "{protocol:?}");
            assert_eq!(hex(&s.m1), m1, "{protocol:?}");
            assert!(s.verify_server(&unhex(m2)));
            assert!(!s.verify_server(&unhex(m1)));
        }
    }

    #[test]
    fn rejects_zero_b() {
        let client = SrpClient::with_private(&[1; 32]);
        assert!(
            client
                .process("u", "p", Protocol::S2k, b"s", 1, &[0])
                .is_err()
        );
        assert!(
            client
                .process("u", "p", Protocol::S2k, b"s", 1, &unhex(N_HEX))
                .is_err()
        );
    }

    #[test]
    fn protocol_names() {
        assert_eq!(Protocol::from_name("s2k"), Some(Protocol::S2k));
        assert_eq!(Protocol::from_name("s2k_fo"), Some(Protocol::S2kFo));
        assert_eq!(Protocol::from_name("other"), None);
    }
}
