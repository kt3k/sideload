//! Saved login sessions (SPEC Section 9.6).
//!
//! On macOS the Developer Services session (adsid, Xcode app token and its
//! expiry) is kept in the user's login Keychain, so later commands skip
//! SRP and 2FA until the token expires. The password is never stored. On
//! other hosts nothing is saved and every command logs in.

#[cfg(target_os = "macos")]
mod macos;

use crate::apple::gsa::Session;
use crate::config::Env;
use crate::formats::plist::{self, Dictionary, Value};

/// Set (non-empty) to disable saving and reusing sessions.
pub const ENV_NO_KEYCHAIN: &str = "SIDELOAD_NO_KEYCHAIN";

/// Keychain service name of saved sessions.
pub const SERVICE: &str = "sideload";

/// A session is reused only if it stays valid at least this long.
const MIN_REMAINING_SECS: u64 = 10 * 60;

/// True if this host can save sessions and the user has not opted out.
pub fn enabled(env: &dyn Env) -> bool {
    cfg!(target_os = "macos") && env.get_non_empty(ENV_NO_KEYCHAIN).is_none()
}

/// The saved session for `apple_id`, if any and still usable at
/// `now_secs`. Unusable or unreadable entries are ignored.
pub fn load(apple_id: &str, now_secs: u64) -> Option<Session> {
    let bytes = backend::read(apple_id).ok()??;
    decode(&bytes).filter(|s| usable(s, now_secs))
}

/// Saves `session` for `apple_id`. Sessions without an expiry are not
/// saved. Returns whether anything was saved.
pub fn save(apple_id: &str, session: &Session) -> std::io::Result<bool> {
    if session.expiry.is_none() {
        return Ok(false);
    }
    backend::write(apple_id, &encode(session))?;
    Ok(true)
}

/// Deletes the saved session for `apple_id`. Returns whether one existed.
pub fn delete(apple_id: &str) -> std::io::Result<bool> {
    backend::delete(apple_id)
}

/// Seconds since the Unix epoch; Apple reports token expiry in
/// milliseconds, older responses in seconds.
fn expiry_secs(expiry: u64) -> u64 {
    if expiry > 100_000_000_000 {
        expiry / 1000
    } else {
        expiry
    }
}

fn usable(session: &Session, now_secs: u64) -> bool {
    session
        .expiry
        .is_some_and(|e| expiry_secs(e) > now_secs.saturating_add(MIN_REMAINING_SECS))
}

/// When `session` expires, as seconds since the Unix epoch.
pub fn expires_at(session: &Session) -> Option<u64> {
    session.expiry.map(expiry_secs)
}

const FORMAT_VERSION: i64 = 1;

fn encode(session: &Session) -> Vec<u8> {
    let mut d = Dictionary::new();
    d.insert("version", FORMAT_VERSION);
    d.insert("adsid", session.adsid.as_str());
    d.insert("token", session.token());
    if let Some(e) = session.expiry {
        d.insert("expiry", Value::Integer(e.into()));
    }
    Value::Dictionary(d).to_xml()
}

fn decode(bytes: &[u8]) -> Option<Session> {
    let v = plist::from_bytes(bytes).ok()?;
    if v.get("version").and_then(Value::as_i64) != Some(FORMAT_VERSION) {
        return None;
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    Some(Session {
        adsid: text("adsid")?,
        token: text("token")?,
        expiry: v.get("expiry").and_then(Value::as_u64),
    })
}

#[cfg(target_os = "macos")]
use macos as backend;

#[cfg(not(target_os = "macos"))]
mod backend {
    pub fn read(_apple_id: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    pub fn write(_apple_id: &str, _data: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    pub fn delete(_apple_id: &str) -> std::io::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(expiry: Option<u64>) -> Session {
        Session {
            adsid: "000123".into(),
            token: "TOKEN".into(),
            expiry,
        }
    }

    #[test]
    fn roundtrip() {
        let s = session(Some(1_900_000_000_000));
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back.adsid, "000123");
        assert_eq!(back.token(), "TOKEN");
        assert_eq!(back.expiry, s.expiry);
        assert!(decode(b"not a plist").is_none());
        let other_version =
            br#"<plist><dict><key>version</key><integer>2</integer></dict></plist>"#;
        assert!(decode(other_version).is_none());
    }

    #[test]
    fn expiry_rules() {
        let now = 1_800_000_000;
        // Milliseconds and seconds.
        assert!(usable(&session(Some((now + 3600) * 1000)), now));
        assert!(usable(&session(Some(now + 3600)), now));
        // Expired, about to expire, or unknown.
        assert!(!usable(&session(Some((now - 1) * 1000)), now));
        assert!(!usable(&session(Some((now + 60) * 1000)), now));
        assert!(!usable(&session(None), now));
        assert_eq!(
            expires_at(&session(Some(5_000_000_000_000))),
            Some(5_000_000_000)
        );
    }

    #[test]
    fn opt_out() {
        struct E(Option<&'static str>);
        impl Env for E {
            fn get(&self, key: &str) -> Option<std::ffi::OsString> {
                (key == ENV_NO_KEYCHAIN).then_some(self.0?.into())
            }
        }
        assert_eq!(enabled(&E(None)), cfg!(target_os = "macos"));
        assert_eq!(enabled(&E(Some(""))), cfg!(target_os = "macos"));
        assert!(!enabled(&E(Some("1"))));
    }

    #[test]
    fn sessions_without_expiry_are_not_saved() {
        assert!(!save("nobody@example.invalid", &session(None)).unwrap());
    }

    /// Real Keychain round trip; run on a Mac with
    /// `cargo test session_store -- --ignored`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the login Keychain"]
    fn keychain_roundtrip() {
        let id = format!("sideload-test-{}@example.invalid", std::process::id());
        let now = 1_800_000_000;
        let s = session(Some((now + 7200) * 1000));
        let _ = delete(&id);
        assert!(load(&id, now).is_none());
        assert!(save(&id, &s).unwrap());
        // Overwrite works.
        assert!(save(&id, &s).unwrap());
        let back = load(&id, now).expect("saved session");
        assert_eq!(back.token(), "TOKEN");
        assert!(delete(&id).unwrap());
        assert!(!delete(&id).unwrap());
        assert!(load(&id, now).is_none());
    }
}
