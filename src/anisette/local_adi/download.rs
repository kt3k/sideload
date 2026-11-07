//! Download Apple's official APK and install only the two native ADI libraries.
use super::elf::Elf;
use crate::{
    Error, ErrorCode, Result,
    formats::zip::ZipReader,
    net::http::{Client, Request},
};
use std::{fs, io::Cursor, path::Path};
const APK: &str = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk";
pub fn ensure(client: &Client, config: &Path) -> Result<()> {
    let dir = config.join("lib");
    let names = ["libstoreservicescore.so", "libCoreADI.so"];
    if names.iter().all(|n| dir.join(n).is_file()) {
        return Ok(());
    }
    let error = |msg: &str| Error::new(ErrorCode::AdiDownloadFailed, msg);
    let abi = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64-v8a"
    } else {
        return Err(error("unsupported ADI CPU"));
    };
    crate::output::info("Downloading Apple ADI libraries: 0%");
    let response = client
        .send(&Request::get(APK).max_body(256 * 1024 * 1024))
        .map_err(|_| error("cannot download Apple Music APK"))?;
    if !response.is_success() {
        return Err(error("Apple Music APK download returned an error"));
    }
    let mut zip =
        ZipReader::new(Cursor::new(response.body)).map_err(|_| error("invalid Apple Music APK"))?;
    let mut libraries = Vec::new();
    for name in names {
        let path = format!("lib/{abi}/{name}");
        let i = zip
            .entries()
            .iter()
            .position(|e| e.name == path)
            .ok_or_else(|| error("APK has no ADI library for this CPU"))?;
        if zip.entries()[i].uncompressed_size > 32 * 1024 * 1024 {
            return Err(error("APK ADI library is too large"));
        }
        let b = zip
            .read(i)
            .map_err(|_| error("cannot extract ADI library"))?;
        Elf::parse(&b).map_err(|_| error("APK contains unsupported ADI ELF"))?;
        libraries.push((name, b));
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&dir)
        .map_err(|_| error("cannot create ADI library directory"))?;
    if fs::symlink_metadata(&dir)
        .map_err(|_| error("cannot inspect ADI library directory"))?
        .file_type()
        .is_symlink()
    {
        return Err(error("ADI library directory must not be a symlink"));
    }
    for (name, bytes) in libraries {
        let suffix = crate::crypto::hex(
            &crate::crypto::random_bytes(8)
                .map_err(|_| error("cannot create ADI temporary file"))?,
        );
        let temp = dir.join(format!(".{name}-{suffix}"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = options.open(&temp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            fs::rename(&temp, dir.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(error("cannot install ADI library"));
        }
    }
    crate::output::info("Downloading Apple ADI libraries: 100%");
    Ok(())
}
