//! Local Anisette: native AOSKit/AuthKit on macOS; Android ADI on Linux and
//! Windows x64. Unsupported hosts fail before downloading native code.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, target_arch = "x86_64")
))]
mod abi;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, target_arch = "x86_64")
))]
pub mod adi;
pub mod download;
pub mod elf;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, target_arch = "x86_64")
))]
pub mod hooks;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, target_arch = "x86_64")
))]
pub mod loader;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, target_arch = "x86_64")
))]
mod memory;
pub mod provisioning;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
pub type AdiResult<T> = std::result::Result<T, String>;
pub(crate) fn fail(msg: impl Into<String>) -> String {
    msg.into()
}
use crate::{
    Result,
    anisette::{AnisetteData, AnisetteProvider},
};
use std::path::Path;
pub struct LocalAdi {
    #[cfg(target_os = "macos")]
    mac: macos::MacOs,
    #[cfg(not(target_os = "macos"))]
    identity: provisioning::Identity,
    #[cfg(not(target_os = "macos"))]
    engine: Box<dyn provisioning::Engine>,
    #[cfg(not(target_os = "macos"))]
    transport: Box<dyn crate::apple::Transport>,
}
impl LocalAdi {
    pub fn new(config: &Path) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let _ = config;
            Ok(Self {
                mac: macos::MacOs::new()?,
            })
        }
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            all(windows, target_arch = "x86_64")
        ))]
        {
            let client =
                crate::net::http::Client::new(concat!("sideload/", env!("CARGO_PKG_VERSION")), &[])
                    .map_err(|_| {
                        crate::Error::new(
                            crate::ErrorCode::AdiDownloadFailed,
                            "cannot initialize ADI download TLS client",
                        )
                    })?;
            download::ensure(&client, config)?;
            let identity = provisioning::Identity::load(config)?;
            let engine = adi::Adi::open(&config.join("lib"), &identity.android_id)
                .map_err(provisioning::error)?;
            Ok(Self {
                identity,
                engine: Box::new(engine),
                transport: Box::new(crate::apple::Https::new()?),
            })
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            all(windows, target_arch = "x86_64")
        )))]
        {
            let _ = config;
            Err(crate::Error::new(
                crate::ErrorCode::AnisetteUnavailable,
                "local Anisette is unsupported on this host; use --anisette-server",
            ))
        }
    }
}
impl AnisetteProvider for LocalAdi {
    fn headers(&mut self) -> Result<AnisetteData> {
        #[cfg(target_os = "macos")]
        {
            self.mac.headers()
        }
        #[cfg(not(target_os = "macos"))]
        {
            provisioning::headers(
                &self.identity,
                self.engine.as_mut(),
                self.transport.as_mut(),
            )
        }
    }
}
