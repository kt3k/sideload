//! The per-run working directory (SPEC Sections 12, 13.2, 14.3).
//!
//! Created under the OS temporary directory with a random name and
//! owner-only permissions. Removed on drop unless `keep` is set.

use std::path::{Path, PathBuf};

use crate::{Error, ErrorCode, Result};

pub struct WorkDir {
    path: PathBuf,
    keep: bool,
}

impl WorkDir {
    pub fn create(keep: bool) -> Result<WorkDir> {
        let suffix = crate::crypto::random_bytes(8)
            .map(|b| crate::crypto::hex(&b))
            .map_err(|e| Error::new(ErrorCode::InternalError, e.to_string()))?;
        let path = std::env::temp_dir().join(format!("sideload-{suffix}"));
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|e| {
            Error::new(
                ErrorCode::InternalError,
                format!("cannot create working directory `{}`: {e}", path.display()),
            )
        })?;
        Ok(WorkDir { path, keep })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn keep(&self) -> bool {
        self.keep
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if self.keep {
            crate::output::info(format!("Working directory kept at {}", self.path.display()));
        } else {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_unless_kept() {
        let dir = WorkDir::create(false).unwrap();
        let path = dir.path().to_path_buf();
        std::fs::write(path.join("f"), b"x").unwrap();
        drop(dir);
        assert!(!path.exists());

        let dir = WorkDir::create(true).unwrap();
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(path.exists());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = WorkDir::create(false).unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
