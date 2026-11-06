//! Configuration resolution (SPEC Section 6).
//!
//! Precedence: CLI option > environment variable > default. Environment
//! variables set to the empty string are treated as unset.

use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use crate::{Error, ErrorCode, Result};

pub const ENV_CONFIG_DIR: &str = "SIDELOADER_CONFIG_DIR";
pub const ENV_ANISETTE_SERVER: &str = "SIDELOADER_ANISETTE_SERVER";
pub const ENV_APPLE_ID: &str = "SIDELOADER_APPLE_ID";
pub const ENV_APPLE_PASSWORD: &str = "SIDELOADER_APPLE_PASSWORD";

/// Directory name under the per-OS config root. Fixed for upstream
/// compatibility regardless of the executable name (SPEC Section 5.1).
pub const CONFIG_DIR_NAME: &str = "Sideloader";

/// Environment lookup, injectable for tests.
pub trait Env {
    fn get(&self, key: &str) -> Option<OsString>;

    /// Like `get`, but treats an empty value as unset (SPEC Section 6.2).
    fn get_non_empty(&self, key: &str) -> Option<OsString> {
        self.get(key).filter(|v| !v.is_empty())
    }
}

/// The process environment.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }
}

/// Global options as given on the command line (unresolved).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalOptions {
    pub debug: bool,
    pub thread_count: Option<NonZeroUsize>,
    pub anisette_server: Option<String>,
}

/// Fully resolved settings (SPEC Section 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub debug: bool,
    pub thread_count: NonZeroUsize,
    /// `None` means local ADI.
    pub anisette_server: Option<String>,
    pub config_dir: PathBuf,
}

impl Settings {
    pub fn resolve(opts: &GlobalOptions, env: &dyn Env, os: Os) -> Result<Settings> {
        let thread_count = opts
            .thread_count
            .unwrap_or_else(|| std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN));

        let anisette_server = match &opts.anisette_server {
            Some(url) => Some(url.clone()),
            None => env
                .get_non_empty(ENV_ANISETTE_SERVER)
                .map(|v| v.to_string_lossy().into_owned()),
        };
        if let Some(url) = &anisette_server {
            validate_anisette_url(url)?;
        }

        Ok(Settings {
            debug: opts.debug,
            thread_count,
            anisette_server,
            config_dir: config_dir(env, os)?,
        })
    }
}

/// SPEC Section 5.6: `--anisette-server` must be an `http` or `https` URL.
pub fn validate_anisette_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    match rest {
        Some(rest) if !rest.is_empty() && !rest.starts_with('/') => Ok(()),
        _ => Err(Error::new(
            ErrorCode::InvalidArguments,
            format!("invalid anisette server URL `{url}` (expected http:// or https://)"),
        )),
    }
}

/// SPEC Section 6.3.
pub fn config_dir(env: &dyn Env, os: Os) -> Result<PathBuf> {
    if let Some(dir) = env.get_non_empty(ENV_CONFIG_DIR) {
        return Ok(PathBuf::from(dir));
    }
    let missing = |var: &str| {
        Error::new(
            ErrorCode::InternalError,
            format!(
                "cannot determine the configuration directory: {var} is not set (set {ENV_CONFIG_DIR})"
            ),
        )
    };
    let root = match os {
        Os::Windows => PathBuf::from(
            env.get_non_empty("APPDATA")
                .ok_or_else(|| missing("APPDATA"))?,
        ),
        Os::MacOs => {
            let home = env.get_non_empty("HOME").ok_or_else(|| missing("HOME"))?;
            PathBuf::from(home).join("Library").join("Preferences")
        }
        Os::Linux => match env.get_non_empty("XDG_CONFIG_HOME") {
            Some(xdg) => PathBuf::from(xdg),
            None => {
                let home = env.get_non_empty("HOME").ok_or_else(|| missing("HOME"))?;
                PathBuf::from(home).join(".config")
            }
        },
    };
    Ok(root.join(CONFIG_DIR_NAME))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    pub(crate) struct MapEnv(pub HashMap<&'static str, &'static str>);

    impl Env for MapEnv {
        fn get(&self, key: &str) -> Option<OsString> {
            self.0.get(key).map(OsString::from)
        }
    }

    fn env(pairs: &[(&'static str, &'static str)]) -> MapEnv {
        MapEnv(pairs.iter().copied().collect())
    }

    #[test]
    fn config_dir_override_wins() {
        let e = env(&[(ENV_CONFIG_DIR, "/x"), ("HOME", "/home/u")]);
        assert_eq!(config_dir(&e, Os::Linux).unwrap(), PathBuf::from("/x"));
    }

    #[test]
    fn empty_override_is_unset() {
        let e = env(&[(ENV_CONFIG_DIR, ""), ("HOME", "/home/u")]);
        assert_eq!(
            config_dir(&e, Os::Linux).unwrap(),
            PathBuf::from("/home/u/.config/Sideloader")
        );
    }

    #[test]
    fn linux_honors_xdg_config_home() {
        let e = env(&[("XDG_CONFIG_HOME", "/cfg"), ("HOME", "/home/u")]);
        assert_eq!(
            config_dir(&e, Os::Linux).unwrap(),
            PathBuf::from("/cfg/Sideloader")
        );
    }

    #[test]
    fn macos_and_windows_defaults() {
        let e = env(&[("HOME", "/Users/u"), ("APPDATA", "C:/AppData")]);
        assert_eq!(
            config_dir(&e, Os::MacOs).unwrap(),
            PathBuf::from("/Users/u/Library/Preferences/Sideloader")
        );
        assert_eq!(
            config_dir(&e, Os::Windows).unwrap(),
            PathBuf::from("C:/AppData").join("Sideloader")
        );
    }

    #[test]
    fn cli_anisette_server_beats_env() {
        let e = env(&[(ENV_ANISETTE_SERVER, "https://env.example"), ("HOME", "/h")]);
        let opts = GlobalOptions {
            anisette_server: Some("https://cli.example".into()),
            ..Default::default()
        };
        let s = Settings::resolve(&opts, &e, Os::Linux).unwrap();
        assert_eq!(s.anisette_server.as_deref(), Some("https://cli.example"));

        let s = Settings::resolve(&GlobalOptions::default(), &e, Os::Linux).unwrap();
        assert_eq!(s.anisette_server.as_deref(), Some("https://env.example"));
    }

    #[test]
    fn anisette_url_validation() {
        assert!(validate_anisette_url("https://ani.example/v3").is_ok());
        assert!(validate_anisette_url("http://localhost:6969").is_ok());
        for bad in ["ani.example", "ftp://x", "https://", "https:///path"] {
            let err = validate_anisette_url(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArguments, "{bad}");
        }
    }
}
