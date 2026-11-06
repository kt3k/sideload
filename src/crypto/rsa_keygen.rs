//! RSA private keys: generation, PKCS#1/PKCS#8 encoding, PEM, and
//! PKCS#1 v1.5 SHA-256 signing (signing is done by `ring`).
//!
//! Key generation runs once per Apple ID on the user's machine; it uses
//! Miller-Rabin over `num-bigint` and the system RNG.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

use super::{CryptoError, CryptoResult, random_bytes};
use crate::formats::{base64, der};

const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
const MR_ROUNDS: usize = 20;

#[derive(Clone, PartialEq, Eq)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPrivateKey({} bits, <private>)", self.n.bits())
    }
}

fn small_primes() -> Vec<u32> {
    let limit = 2000usize;
    let mut sieve = vec![true; limit];
    sieve[0] = false;
    sieve[1] = false;
    for i in 2..limit {
        if sieve[i] {
            let mut j = i * i;
            while j < limit {
                sieve[j] = false;
                j += i;
            }
        }
    }
    (0..limit as u32).filter(|&i| sieve[i as usize]).collect()
}

fn random_below(upper: &BigUint) -> CryptoResult<BigUint> {
    let bytes = random_bytes(upper.bits().div_ceil(8) as usize + 8)?;
    Ok(BigUint::from_bytes_be(&bytes) % upper)
}

/// Miller-Rabin probable-prime test (`n` odd, > 3).
fn is_probable_prime(n: &BigUint, rounds: usize) -> CryptoResult<bool> {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }
    'witness: for _ in 0..rounds {
        let a = random_below(&(n - 3u32))? + &two; // a in [2, n-2]
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return Ok(false);
    }
    Ok(true)
}

fn generate_prime(bits: u64, e: &BigUint, primes: &[u32]) -> CryptoResult<BigUint> {
    loop {
        let mut bytes = random_bytes((bits / 8) as usize)?;
        bytes[0] |= 0xC0; // top two bits: the product has exactly 2*bits bits
        *bytes.last_mut().expect("non-empty") |= 1;
        let candidate = BigUint::from_bytes_be(&bytes);
        if primes.iter().any(|&sp| (&candidate % sp).is_zero()) {
            continue;
        }
        if !(&candidate - 1u32).gcd(e).is_one() {
            continue;
        }
        if is_probable_prime(&candidate, MR_ROUNDS)? {
            return Ok(candidate);
        }
    }
}

impl RsaPrivateKey {
    /// Generates a key with public exponent 65537.
    pub fn generate(bits: u64) -> CryptoResult<RsaPrivateKey> {
        if bits < 1024 || bits % 16 != 0 {
            return Err(CryptoError::new(
                "RSA key size must be a multiple of 16 and at least 1024",
            ));
        }
        let e = BigUint::from(65_537u32);
        let primes = small_primes();
        loop {
            let p = generate_prime(bits / 2, &e, &primes)?;
            let q = generate_prime(bits / 2, &e, &primes)?;
            if p == q {
                continue;
            }
            let (p, q) = if p > q { (p, q) } else { (q, p) };
            if let Some(key) = Self::from_primes(p, q, e.clone()) {
                if key.n.bits() == bits {
                    return Ok(key);
                }
            }
        }
    }

    fn from_primes(p: BigUint, q: BigUint, e: BigUint) -> Option<RsaPrivateKey> {
        let one = BigUint::one();
        let p1 = &p - &one;
        let q1 = &q - &one;
        let lambda = p1.lcm(&q1);
        let d = e.modinv(&lambda)?;
        let dp = &d % &p1;
        let dq = &d % &q1;
        let qinv = q.modinv(&p)?;
        Some(RsaPrivateKey {
            n: &p * &q,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }

    pub fn bits(&self) -> u64 {
        self.n.bits()
    }

    /// PKCS#1 `RSAPrivateKey`.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let i = |v: &BigUint| der::unsigned_integer(&v.to_bytes_be());
        der::sequence([
            der::integer(0),
            i(&self.n),
            i(&self.e),
            i(&self.d),
            i(&self.p),
            i(&self.q),
            i(&self.dp),
            i(&self.dq),
            i(&self.qinv),
        ])
    }

    fn algorithm_identifier() -> Vec<u8> {
        der::sequence([der::oid(RSA_ENCRYPTION_OID), der::null()])
    }

    /// PKCS#8 `PrivateKeyInfo`.
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        der::sequence([
            der::integer(0),
            Self::algorithm_identifier(),
            der::octet_string(&self.to_pkcs1_der()),
        ])
    }

    /// `-----BEGIN PRIVATE KEY-----` (PKCS#8), as upstream writes `key.pem`.
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// PKCS#1 `RSAPublicKey`.
    pub fn public_key_pkcs1_der(&self) -> Vec<u8> {
        der::sequence([
            der::unsigned_integer(&self.n.to_bytes_be()),
            der::unsigned_integer(&self.e.to_bytes_be()),
        ])
    }

    /// X.509 `SubjectPublicKeyInfo`.
    pub fn subject_public_key_info_der(&self) -> Vec<u8> {
        der::sequence([
            Self::algorithm_identifier(),
            der::bit_string(&self.public_key_pkcs1_der()),
        ])
    }

    pub fn from_pkcs1_der(data: &[u8]) -> CryptoResult<RsaPrivateKey> {
        let bad = |e: crate::formats::FormatError| {
            CryptoError::new(format!("invalid RSA private key: {e}"))
        };
        let mut r = der::Reader::new(data);
        let seq = r.expect(der::tag::SEQUENCE).map_err(bad)?;
        r.finish().map_err(bad)?;
        let mut f = seq.children().map_err(bad)?;
        if f.read().and_then(|t| t.as_i64()).map_err(bad)? != 0 {
            return Err(CryptoError::new("unsupported RSA private key version"));
        }
        let mut next = || -> CryptoResult<BigUint> {
            Ok(BigUint::from_bytes_be(
                f.read()
                    .and_then(|t| t.unsigned_integer_bytes())
                    .map_err(bad)?,
            ))
        };
        let key = RsaPrivateKey {
            n: next()?,
            e: next()?,
            d: next()?,
            p: next()?,
            q: next()?,
            dp: next()?,
            dq: next()?,
            qinv: next()?,
        };
        if &key.p * &key.q != key.n {
            return Err(CryptoError::new("invalid RSA private key: n != p*q"));
        }
        Ok(key)
    }

    pub fn from_pkcs8_der(data: &[u8]) -> CryptoResult<RsaPrivateKey> {
        let bad =
            |e: crate::formats::FormatError| CryptoError::new(format!("invalid PKCS#8 key: {e}"));
        let mut r = der::Reader::new(data);
        let seq = r.expect(der::tag::SEQUENCE).map_err(bad)?;
        let mut f = seq.children().map_err(bad)?;
        f.expect(der::tag::INTEGER).map_err(bad)?;
        let alg = f.expect(der::tag::SEQUENCE).map_err(bad)?;
        let oid = alg
            .children()
            .and_then(|mut a| a.read()?.as_oid())
            .map_err(bad)?;
        if oid != RSA_ENCRYPTION_OID {
            return Err(CryptoError::new(format!("unsupported key algorithm {oid}")));
        }
        let inner = f.expect(der::tag::OCTET_STRING).map_err(bad)?;
        Self::from_pkcs1_der(inner.content)
    }

    /// Accepts `PRIVATE KEY` (PKCS#8) and `RSA PRIVATE KEY` (PKCS#1) PEM.
    pub fn from_pem(pem: &str) -> CryptoResult<RsaPrivateKey> {
        if let Some(der) = pem_decode(pem, "PRIVATE KEY") {
            Self::from_pkcs8_der(&der?)
        } else if let Some(der) = pem_decode(pem, "RSA PRIVATE KEY") {
            Self::from_pkcs1_der(&der?)
        } else {
            Err(CryptoError::new("no RSA private key found in PEM"))
        }
    }

    fn ring_key_pair(&self) -> CryptoResult<ring::rsa::KeyPair> {
        ring::rsa::KeyPair::from_pkcs8(&self.to_pkcs8_der())
            .map_err(|e| CryptoError::new(format!("key rejected by ring: {e}")))
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 over `message`.
    pub fn sign_sha256(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let kp = self.ring_key_pair()?;
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            message,
            &mut sig,
        )
        .map_err(|_| CryptoError::new("RSA signing failed"))?;
        Ok(sig)
    }
}

pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Returns the first block with `label`, or `None` if there is none.
pub fn pem_decode(pem: &str, label: &str) -> Option<CryptoResult<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = start + pem[start..].find(&end)?;
    Some(
        base64::decode(&pem[start..stop])
            .map_err(|e| CryptoError::new(format!("invalid PEM: {e}"))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin() {
        let primes = [
            BigUint::from(1_000_000_007u32),
            BigUint::parse_bytes(b"170141183460469231731687303715884105727", 10).unwrap(),
        ];
        for p in primes {
            assert!(is_probable_prime(&p, 10).unwrap());
        }
        // Carmichael number 561 and a composite of two large primes.
        assert!(!is_probable_prime(&BigUint::from(561u32), 10).unwrap());
        assert!(
            !is_probable_prime(
                &(BigUint::from(1_000_000_007u32) * BigUint::from(998_244_353u32)),
                10
            )
            .unwrap()
        );
    }

    #[test]
    fn generate_sign_and_reload() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        assert_eq!(key.bits(), 2048);
        let sig = key.sign_sha256(b"hello").unwrap();
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public_key_pkcs1_der(),
        );
        assert!(public.verify(b"hello", &sig).is_ok());
        assert!(public.verify(b"hellp", &sig).is_err());

        let reloaded = RsaPrivateKey::from_pem(&key.to_pkcs8_pem()).unwrap();
        assert_eq!(reloaded, key);
        assert_eq!(
            RsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap(),
            key
        );
    }

    /// A PKCS#8 key written by OpenSSL (an independent encoder).
    #[test]
    fn loads_openssl_key() {
        let key = RsaPrivateKey::from_pem(include_str!("testdata/openssl_key.pem")).unwrap();
        assert_eq!(key.bits(), 2048);
        assert_eq!(key.e, BigUint::from(65_537u32));
        assert!(key.sign_sha256(b"x").is_ok());
        // Re-encoding yields the same DER OpenSSL wrote.
        let pem = include_str!("testdata/openssl_key.pem");
        assert_eq!(
            key.to_pkcs8_der(),
            pem_decode(pem, "PRIVATE KEY").unwrap().unwrap()
        );
    }

    #[test]
    fn rejects_bad_pem() {
        assert!(RsaPrivateKey::from_pem("nothing here").is_err());
        assert!(
            RsaPrivateKey::from_pem("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----")
                .is_err()
        );
    }
}
