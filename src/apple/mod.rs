//! Developer Service Client (SPEC Sections 3.1, 9).
//!
//! - `http`: minimal HTTP/1.1 client over rustls (POST + GET, Content-Length
//!   and chunked bodies). Pins Apple's server authentication CA for
//!   gsa.apple.com.
//! - `gsa`: GrandSlam authentication (SRP-6a with Apple's s2k/s2k_fo
//!   password derivation, spd decryption, 2FA trusted-device flow).
//! - `developer`: developerservices2 (QH65B2) operations from SPEC Section 9.4.

pub mod developer;
pub mod gsa;
pub mod http;
