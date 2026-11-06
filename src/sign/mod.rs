//! Code Signer (SPEC Section 11.2).
//!
//! - `macho`: thin/fat Mach-O parsing, LC_CODE_SIGNATURE, __LINKEDIT resizing.
//! - `code_directory`: CodeDirectory (SHA-1 and SHA-256), special slots.
//! - `requirements`: designated requirement blob.
//! - `entitlements`: XML and DER entitlements (DER is required on iOS 15+),
//!   derived from the provisioning profile.
//! - `cms`: CMS SignedData with Apple hash-agility attributes.
//! - `code_resources`: `_CodeSignature/CodeResources` for (nested) bundles.
//!
//! Reference: apple-codesign (MPL-2.0). TODO: implement.

pub mod cms;
pub mod code_directory;
pub mod code_resources;
pub mod entitlements;
pub mod macho;
pub mod requirements;
