//! Developer Service Client (SPEC Sections 3.1, 9). HTTPS goes through
//! `net::http`; requests to gsa.apple.com pin Apple's server CA.
//!
//! - `gsa`: GrandSlam authentication (SRP-6a with Apple's s2k/s2k_fo
//!   password derivation, spd decryption, 2FA trusted-device flow).
//! - `developer`: developerservices2 (QH65B2) operations from SPEC Section 9.4.

pub mod developer;
pub mod gsa;
