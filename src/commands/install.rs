//! `install` (SPEC Section 7, reference algorithm in Section 15.1).

use std::path::Path;
use std::process::ExitCode;

use crate::cli::InstallArgs;
use crate::config::Settings;
use crate::pipeline::workdir::WorkDir;
use crate::pipeline::{Mode, Phase};
use crate::sidestore;
use crate::{Error, ErrorCode, Result};

pub fn mode(args: &InstallArgs) -> Mode {
    if args.dry_run {
        Mode::DryRun
    } else if args.output.is_some() {
        Mode::Output
    } else {
        Mode::Install
    }
}

pub fn run(args: &InstallArgs, _settings: &Settings) -> Result<ExitCode> {
    validate_arguments(args).map_err(|e| e.with_phase(Phase::ValidatingArguments))?;
    let _mode = mode(args);
    let workdir = WorkDir::create(args.keep_temp)?;

    // TODO: SelectingDevice (SPEC Section 10.1) runs before the download.

    let _ipa = match &args.ipa {
        Some(path) => path.clone(),
        None => {
            let client =
                sidestore::http_client().map_err(|e| e.with_phase(Phase::DownloadingApp))?;
            sidestore::download_latest(&client, workdir.path())
                .map_err(|e| e.with_phase(Phase::DownloadingApp))?
                .0
        }
    };

    // TODO: remaining phases (SPEC Section 7.2).
    Err(Error::not_implemented("install").with_phase(Phase::PreparingBundle))
}

/// SPEC Section 5.6 (the parts specific to `install`; `--output`/`--dry-run`
/// exclusivity and `--thread-count` are checked by the parser, the anisette
/// URL by `Settings::resolve`).
pub fn validate_arguments(args: &InstallArgs) -> Result<()> {
    if let Some(ipa) = &args.ipa {
        validate_ipa_path(ipa)?;
    }
    if let Some(output) = &args.output {
        let parent = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if !parent.is_dir() {
            return Err(Error::new(
                ErrorCode::OutputWriteFailed,
                format!("output directory `{}` does not exist", parent.display()),
            ));
        }
    }
    if let Some(id) = &args.bundle_id {
        validate_bundle_id(id)?;
    }
    Ok(())
}

pub fn validate_ipa_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(Error::new(
            ErrorCode::IpaNotFound,
            format!("`{}` does not exist", path.display()),
        ));
    }
    if !path.is_file() {
        return Err(Error::new(
            ErrorCode::IpaInvalid,
            format!("`{}` is not a regular file", path.display()),
        ));
    }
    if path.extension().and_then(|e| e.to_str()) != Some("ipa") {
        return Err(Error::new(
            ErrorCode::IpaInvalid,
            format!("`{}` is not an .ipa file", path.display()),
        ));
    }
    Ok(())
}

pub fn validate_bundle_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArguments,
            format!("invalid bundle identifier `{id}` (allowed: A-Z a-z 0-9 . -)"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir =
                std::env::temp_dir().join(format!("sideload-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ipa_validation() {
        let dir = TempDir::new("ipa");
        let ipa = dir.0.join("a.ipa");
        std::fs::write(&ipa, b"").unwrap();
        let zip = dir.0.join("a.zip");
        std::fs::write(&zip, b"").unwrap();

        assert!(validate_ipa_path(&ipa).is_ok());
        assert_eq!(
            validate_ipa_path(&dir.0.join("missing.ipa"))
                .unwrap_err()
                .code,
            ErrorCode::IpaNotFound
        );
        assert_eq!(
            validate_ipa_path(&zip).unwrap_err().code,
            ErrorCode::IpaInvalid
        );
        assert_eq!(
            validate_ipa_path(&dir.0).unwrap_err().code,
            ErrorCode::IpaInvalid
        );
    }

    #[test]
    fn output_parent_must_exist() {
        let dir = TempDir::new("out");
        let ipa = dir.0.join("a.ipa");
        std::fs::write(&ipa, b"").unwrap();
        let mut args = InstallArgs {
            ipa: Some(ipa),
            ..Default::default()
        };

        args.output = Some(dir.0.join("signed.ipa"));
        assert!(validate_arguments(&args).is_ok());

        args.output = Some(dir.0.join("nope").join("signed.ipa"));
        assert_eq!(
            validate_arguments(&args).unwrap_err().code,
            ErrorCode::OutputWriteFailed
        );
    }

    #[test]
    fn bundle_id_validation() {
        assert!(validate_bundle_id("com.example.App-1").is_ok());
        for bad in ["", "com.example.app_1", "com.ex ample", "com.例"] {
            assert_eq!(
                validate_bundle_id(bad).unwrap_err().code,
                ErrorCode::InvalidArguments,
                "{bad}"
            );
        }
    }

    #[test]
    fn modes() {
        let mut a = InstallArgs::default();
        assert_eq!(mode(&a), Mode::Install);
        a.output = Some("x".into());
        assert_eq!(mode(&a), Mode::Output);
        a.output = None;
        a.dry_run = true;
        assert_eq!(mode(&a), Mode::DryRun);
    }
}
