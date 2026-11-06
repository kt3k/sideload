//! Protocol-level crypto built on vetted primitives. Primitives (SHA,
//! HMAC, PBKDF2, AES, AES-GCM, RSA signing) come from external crates and
//! are never hand-written here.
//!
//! - `cbc`: AES-CBC mode over the `aes` block cipher (GSA spd decryption).
//! - `srp`: SRP-6a client for GSA (2048-bit group, Apple variant).
//! - `rsa_keygen`: RSA-2048 key generation (`num-bigint`, Miller-Rabin).
//!
//! TODO: implement.

pub mod cbc;
pub mod rsa_keygen;
pub mod srp;
