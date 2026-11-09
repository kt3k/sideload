//! Request configuration and account (`ios/SPEC.md` Sections 4.2, 9.1).

use std::path::PathBuf;

use sideload::formats::json::Value;

use crate::error::{CResult, invalid};

pub const DEFAULT_DEVICE_HOST: &str = "10.7.0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub data_dir: PathBuf,
    pub anisette_server: Option<String>,
    pub device_host: String,
    /// `<App>`'s own `.app` (Section 4.6).
    pub self_bundle: Option<PathBuf>,
}

/// Credentials and team. `Debug` never prints the password or session.
#[derive(Clone, Default)]
pub struct Account {
    pub apple_id: String,
    pub password: Option<String>,
    /// Opaque saved session (Section 4.2).
    pub session: Option<String>,
    pub team_id: Option<String>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("apple_id", &self.apple_id)
            .field("team_id", &self.team_id)
            .finish_non_exhaustive()
    }
}

/// A non-empty string field, if present.
pub fn opt_str(v: Option<&Value>, key: &str) -> CResult<Option<String>> {
    match v.and_then(|v| v.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(invalid(format!("`{key}` must be a string"))),
    }
}

pub fn req_str(v: Option<&Value>, key: &str) -> CResult<String> {
    opt_str(v, key)?.ok_or_else(|| invalid(format!("missing `{key}`")))
}

impl Config {
    pub fn from_json(v: Option<&Value>) -> CResult<Config> {
        let v = v.ok_or_else(|| invalid("missing `config`"))?;
        Ok(Config {
            data_dir: PathBuf::from(req_str(Some(v), "data_dir")?),
            anisette_server: opt_str(Some(v), "anisette_server")?,
            device_host: opt_str(Some(v), "device_host")?
                .unwrap_or_else(|| DEFAULT_DEVICE_HOST.to_owned()),
            self_bundle: opt_str(Some(v), "self_bundle")?.map(PathBuf::from),
        })
    }

    pub fn pairing_path(&self) -> PathBuf {
        self.data_dir.join("pairing.plist")
    }
}

impl Account {
    pub fn from_json(v: Option<&Value>) -> CResult<Account> {
        let v = v.ok_or_else(|| invalid("missing `account`"))?;
        Ok(Account {
            apple_id: req_str(Some(v), "apple_id")?.to_lowercase(),
            password: opt_str(Some(v), "password")?,
            session: opt_str(Some(v), "session")?,
            team_id: opt_str(Some(v), "team_id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sideload::formats::json;

    #[test]
    fn parses_config_and_account() {
        let v = json::parse(
            r#"{"config":{"data_dir":"/d","anisette_server":"https://a","device_host":null},
                "account":{"apple_id":"Me@X.com","password":"pw","session":""}}"#,
        )
        .unwrap();
        let c = Config::from_json(v.get("config")).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/d"));
        assert_eq!(c.device_host, DEFAULT_DEVICE_HOST);
        assert_eq!(c.self_bundle, None);
        let a = Account::from_json(v.get("account")).unwrap();
        assert_eq!(a.apple_id, "me@x.com");
        assert_eq!(a.session, None);
        assert!(!format!("{a:?}").contains("pw"));
    }

    #[test]
    fn rejects_bad_types() {
        let v = json::parse(r#"{"config":{"data_dir":1}}"#).unwrap();
        assert_eq!(
            Config::from_json(v.get("config")).unwrap_err().code,
            sideload::ErrorCode::InvalidArguments
        );
        assert!(Account::from_json(None).is_err());
    }
}
