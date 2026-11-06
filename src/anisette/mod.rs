//! Anisette Provider (SPEC Sections 3.1, 9.1).
//!
//! Produces the `X-Apple-I-MD*` headers Apple requires on authentication
//! and Developer Services requests. Two backends:
//! - `remote_v3`: an anisette-v3 compatible server (all platforms).
//! - `local_adi`: Apple's Android ADI libraries loaded in-process
//!   (Linux x86_64 / aarch64 only).

pub mod remote_v3;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod local_adi;

use crate::Result;

/// One set of Anisette headers (name, value), e.g. `X-Apple-I-MD`,
/// `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-LU`,
/// `X-Mme-Device-Id`, `X-Apple-I-Client-Time`, ...
#[derive(Debug, Clone, Default)]
pub struct AnisetteData {
    pub headers: Vec<(String, String)>,
}

pub trait AnisetteProvider {
    /// Returns fresh headers, provisioning the backend first if needed.
    fn headers(&mut self) -> Result<AnisetteData>;
}
