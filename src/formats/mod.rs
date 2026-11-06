//! In-tree replacements for format crates.
//!
//! - `plist`: XML and binary property lists (Apple APIs, devices, Info.plist).
//! - `zip`: ZIP container (deflate via `miniz_oxide`).
//! - `der`: DER/BER encoding and decoding for CSR, X.509, CMS and DER
//!   entitlements.
//! - `json`: minimal JSON for the anisette-v3 protocol.
//! - `base64`, `date`: shared helpers.

pub mod base64;
pub mod date;
pub mod der;
pub mod json;
pub mod plist;
pub mod zip;

use std::fmt;

/// A malformed or unsupported input. Callers map it to the SPEC error code
/// that fits the context (for example `ipa_invalid` or `apple_api_error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError(pub String);

impl FormatError {
    pub fn new(msg: impl Into<String>) -> Self {
        FormatError(msg.into())
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FormatError {}

impl From<std::io::Error> for FormatError {
    fn from(e: std::io::Error) -> Self {
        FormatError(format!("I/O error: {e}"))
    }
}

pub type FormatResult<T> = Result<T, FormatError>;
