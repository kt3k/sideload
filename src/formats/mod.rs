//! In-tree replacements for format crates.
//!
//! - `plist`: XML and binary property lists (Apple APIs, devices, Info.plist).
//! - `zip`: ZIP container (deflate via `miniz_oxide`).
//! - `der`: DER encoding/decoding for CSR, X.509 public keys and CMS.
//! - `json`: minimal JSON for the anisette-v3 protocol.
//!
//! TODO: implement.

pub mod der;
pub mod json;
pub mod plist;
pub mod zip;
