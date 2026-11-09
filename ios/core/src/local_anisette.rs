//! In-process iOS Anisette: official AArch64 libraries interpreted as data.
use crate::emulation::adi::Adi;
use sideload::{
    Error, ErrorCode, Result,
    anisette::{
        AnisetteData, AnisetteProvider,
        local_adi::{
            download::{self, Abi},
            provisioning::{self, Identity},
        },
    },
    apple::{Https, Transport},
    net::http::Client,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
fn error(message: &str) -> Error {
    Error::new(ErrorCode::AnisetteUnavailable, message)
}
fn directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| error("cannot create private local Anisette directory"))?;
    }
    let m =
        fs::symlink_metadata(path).map_err(|_| error("cannot inspect local Anisette directory"))?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(error(
            "local Anisette directory must be a real private directory",
        ));
    }
    Ok(())
}
fn files(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|_| error("cannot read local provisioning directory"))?
        .take(33)
    {
        if out.len() >= 32 {
            return Err(error("too many local provisioning files"));
        }
        let entry = entry.map_err(|_| error("cannot inspect provisioning file"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| error("invalid provisioning filename"))?;
        if name.is_empty()
            || name.len() > 255
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(error("invalid provisioning filename"));
        }
        let m = fs::symlink_metadata(entry.path())
            .map_err(|_| error("cannot inspect provisioning file"))?;
        if !m.is_file() || m.file_type().is_symlink() || m.len() > 4 * 1024 * 1024 {
            return Err(error("invalid local provisioning file"));
        }
        out.push((
            name,
            fs::read(entry.path()).map_err(|_| error("cannot read local provisioning file"))?,
        ));
    }
    Ok(out)
}
struct Stage {
    path: PathBuf,
    destination: PathBuf,
}
impl Stage {
    fn new(root: &Path) -> Result<Self> {
        let destination = root.join("provisioning");
        directory(&destination)?;
        let suffix = sideload::crypto::hex(
            &sideload::crypto::random_bytes(8)
                .map_err(|_| error("cannot generate local state temporary name"))?,
        );
        let path = root.join(format!(".stage-{suffix}"));
        directory(&path)?;
        let stage = Self { path, destination };
        for (name, bytes) in files(&stage.destination)? {
            stage.write(&stage.path, &name, &bytes)?;
        }
        Ok(stage)
    }
    fn write(&self, dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        let suffix = sideload::crypto::hex(
            &sideload::crypto::random_bytes(8)
                .map_err(|_| error("cannot generate local state temporary name"))?,
        );
        let temporary = dir.join(format!(".write-{suffix}"));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = options.open(&temporary)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            fs::rename(&temporary, dir.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(error("cannot persist local provisioning state"));
        }
        Ok(())
    }
    fn commit(&self) -> Result<()> {
        let files = files(&self.path)?;
        for (name, bytes) in files {
            self.write(&self.destination, &name, &bytes)?;
        }
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct LocalAnisette {
    // Drop the runtime/file handles before removing the staging directory.
    engine: Adi,
    stage: Stage,
    identity: Identity,
    transport: Box<dyn Transport>,
}
impl LocalAnisette {
    pub fn new(data_dir: &Path) -> Result<Self> {
        directory(data_dir)?;
        let root = data_dir.join("anisette-local");
        directory(&root)?;
        let client = Client::new(concat!("sideload-ios/", env!("CARGO_PKG_VERSION")), &[])
            .map_err(|_| error("cannot initialize ADI acquisition client"))?;
        download::ensure_for_abi(&client, &root, Abi::Aarch64)?;
        let identity = Identity::load(&root)?;
        let stage = Stage::new(&root)?;
        let engine = Adi::open(&root.join("lib"), &stage.path, &identity.android_id)
            .map_err(|e| error(&format!("on-device ADI initialization failed: {e}")))?;
        Ok(Self {
            engine,
            stage,
            identity,
            transport: Box::new(Https::new()?),
        })
    }
}
impl AnisetteProvider for LocalAnisette {
    fn headers(&mut self) -> Result<AnisetteData> {
        let headers =
            provisioning::headers(&self.identity, &mut self.engine, self.transport.as_mut())?;
        self.stage.commit()?;
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sideload::pipeline::workdir::WorkDir;
    #[test]
    fn staging_keeps_failed_changes_private_and_commits_success() {
        let root = WorkDir::create(false).unwrap();
        let stable = root.path().join("provisioning");
        directory(&stable).unwrap();
        fs::write(stable.join("adi.pb"), b"old").unwrap();
        {
            let stage = Stage::new(root.path()).unwrap();
            fs::write(stage.path.join("adi.pb"), b"failed").unwrap();
        }
        assert_eq!(fs::read(stable.join("adi.pb")).unwrap(), b"old");
        let stage = Stage::new(root.path()).unwrap();
        assert_eq!(fs::read(stage.path.join("adi.pb")).unwrap(), b"old");
        fs::write(stage.path.join("adi.pb"), b"success").unwrap();
        stage.commit().unwrap();
        assert_eq!(fs::read(stable.join("adi.pb")).unwrap(), b"success");
    }
    #[test]
    fn rejects_symlink_storage_and_provisioning_before_acquisition() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let root = WorkDir::create(false).unwrap();
            symlink(root.path(), root.path().join("anisette-local")).unwrap();
            assert!(LocalAnisette::new(root.path()).is_err());
            let stage_root = root.path().join("stage-test");
            directory(&stage_root).unwrap();
            directory(&stage_root.join("provisioning")).unwrap();
            symlink("/etc/passwd", stage_root.join("provisioning/adi.pb")).unwrap();
            assert!(Stage::new(&stage_root).is_err());
        }
    }
}
