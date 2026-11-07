//! Native local ADI. ELF format parsing/download and provisioning are portable;
//! executable loading currently supports Linux x86_64/aarch64 only. Other hosts
//! fail before downloading code and can use the remote v3 provider.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod adi;
pub mod download;
pub mod elf;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod hooks;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod loader;
pub mod provisioning;
pub type AdiResult<T> = std::result::Result<T, String>;
pub(crate) fn fail(msg: impl Into<String>) -> String {
    msg.into()
}
use crate::{
    Error, ErrorCode, Result,
    anisette::{AnisetteData, AnisetteProvider},
    apple::Transport,
};
use std::path::Path;
pub struct LocalAdi {
    identity: provisioning::Identity,
    engine: Box<dyn provisioning::Engine>,
    transport: Box<dyn Transport>,
}
impl LocalAdi {
    pub fn new(config: &Path) -> Result<Self> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let client =
                crate::net::http::Client::new(concat!("sideload/", env!("CARGO_PKG_VERSION")), &[])
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::AdiDownloadFailed,
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
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = config;
            Err(Error::new(
                ErrorCode::AnisetteUnavailable,
                "local ADI native loader for this OS is not implemented; use --anisette-server",
            ))
        }
    }
}
impl AnisetteProvider for LocalAdi {
    fn headers(&mut self) -> Result<AnisetteData> {
        provisioning::headers(
            &self.identity,
            self.engine.as_mut(),
            self.transport.as_mut(),
        )
    }
}
