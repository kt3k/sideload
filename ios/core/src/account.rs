//! Logging in (`ios/SPEC.md` Section 7.2): remote or host-provided Anisette, saved-session
//! reuse, password login with an interactive 2FA callback.

use sideload::ErrorCode;
use sideload::anisette::{AnisetteProvider, remote_v3::RemoteV3};
use sideload::apple::Https;
use sideload::apple::developer::{Developer, Team};
use sideload::apple::gsa::Gsa;
use sideload::config::validate_anisette_url;
use sideload::credentials::CodeInput;
use sideload::formats::base64;
use sideload::pipeline::Phase;
use sideload::{output, session_store};

use crate::config::{Account, AnisetteMode, Config};
use crate::error::{At, CResult, CoreError};

/// Asks the user for a 2FA code; `None` cancels (Section 9.3).
pub type TwoFactor<'a> = &'a mut dyn FnMut() -> Option<String>;

pub struct LoggedIn {
    pub dev: Developer<Https>,
    pub team: Team,
    pub apple_id: String,
    /// Set when a new session was created (Section 7.2 step 5).
    pub new_session: Option<String>,
}

fn anisette(cfg: &Config) -> CResult<Box<dyn AnisetteProvider>> {
    if cfg.anisette_mode == Some(AnisetteMode::Local) {
        return Ok(Box::new(crate::local_anisette::LocalAnisette::new(
            &cfg.data_dir,
        )?));
    }
    if cfg.anisette_mode == Some(AnisetteMode::Remote) && cfg.anisette_server.is_none() {
        return Err(CoreError::new(
            ErrorCode::AnisetteUnavailable,
            "remote Anisette needs a server URL in Settings",
        ));
    }
    let Some(url) = cfg.anisette_server.as_deref() else {
        return Ok(Box::new(crate::anisette::OnDevice::new()?));
    };
    validate_anisette_url(url)?;
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| {
        CoreError::new(
            ErrorCode::InternalError,
            format!("cannot create `{}`: {e}", cfg.data_dir.display()),
        )
    })?;
    Ok(Box::new(RemoteV3::new(url, &cfg.data_dir)?))
}

/// Prepares the selected backend without credentials; returns no header values.
pub fn prepare_anisette(cfg: &Config) -> CResult<()> {
    let phase = Phase::PreparingAnisette.as_str();
    output::phase(Phase::PreparingAnisette);
    anisette(cfg).at(phase)?.headers().at(phase)?;
    Ok(())
}

pub fn decode_session(s: &str) -> Option<sideload::apple::gsa::Session> {
    base64::decode(s)
        .ok()
        .and_then(|b| session_store::decode(&b))
}

pub fn encode_session(s: &sideload::apple::gsa::Session) -> String {
    base64::encode(&session_store::encode(s))
}

/// Maps the 2FA callback to the GSA input contract.
fn code_input(two_factor: TwoFactor<'_>) -> impl FnMut() -> sideload::Result<CodeInput> + '_ {
    move || match two_factor() {
        None => Err(sideload::Error::new(
            ErrorCode::TwoFactorFailed,
            "a verification code is required; open the app and log in",
        )),
        Some(code) => {
            let code = code.trim();
            if code.eq_ignore_ascii_case("resend") {
                Ok(CodeInput::Resend)
            } else {
                Ok(CodeInput::Code(code.to_owned()))
            }
        }
    }
}

pub fn log_in(cfg: &Config, account: &Account, two_factor: TwoFactor<'_>) -> CResult<LoggedIn> {
    let p_anisette = Phase::PreparingAnisette.as_str();
    let p_login = Phase::LoggingIn.as_str();
    output::phase(Phase::PreparingAnisette);
    let mut provider = anisette(cfg).at(p_anisette)?;

    output::phase(Phase::LoggingIn);
    let apple_id = account.apple_id.to_lowercase();
    let now = sideload::formats::date::now_unix().max(0) as u64;
    let saved = account
        .session
        .as_deref()
        .and_then(decode_session)
        .filter(|s| session_store::usable(s, now));
    if let Some(session) = saved {
        let mut dev = Developer::new(session, provider).at(p_login)?;
        match dev.list_teams() {
            Ok(_) => return finish(dev, apple_id, None, account),
            Err(e) => {
                output::debug(format!("saved session rejected: {}", e.code));
                output::info("The saved session was not accepted; logging in again.");
                provider = anisette(cfg).at(p_anisette)?;
            }
        }
    }

    let password = account.password.as_deref().ok_or_else(|| {
        CoreError::new(
            ErrorCode::CredentialsUnavailable,
            "no password saved; enter it in Settings",
        )
        .at(p_login)
    })?;
    let mut gsa = Gsa::new(provider).at(p_login)?;
    output::info(format!("Logging in as {apple_id}..."));
    let session = gsa
        .authenticate(&apple_id, password, &mut code_input(two_factor))
        .at(p_login)?;
    let encoded = encode_session(&session);
    let dev = Developer::from_authenticated(session, gsa);
    finish(dev, apple_id, Some(encoded), account)
}

fn finish(
    mut dev: Developer<Https>,
    apple_id: String,
    new_session: Option<String>,
    account: &Account,
) -> CResult<LoggedIn> {
    output::phase(Phase::SelectingTeam);
    let team = dev
        .select_team(account.team_id.as_deref())
        .at(Phase::SelectingTeam.as_str())?;
    Ok(LoggedIn {
        dev,
        team,
        apple_id,
        new_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::temp_dir;

    #[test]
    fn two_factor_mapping() {
        let mut answers = vec![None, Some(" resend ".to_owned()), Some("123456".to_owned())];
        let mut cb = move || answers.pop().flatten();
        let mut input = code_input(&mut cb);
        assert_eq!(input().unwrap(), CodeInput::Code("123456".into()));
        assert_eq!(input().unwrap(), CodeInput::Resend);
        assert_eq!(input().unwrap_err().code, ErrorCode::TwoFactorFailed);
    }

    #[test]
    fn requires_local_engine_or_valid_remote_server() {
        let dir = temp_dir("no-anisette");
        let cfg = Config {
            data_dir: dir,
            anisette_server: None,
            anisette_mode: None,
            device_host: "x".into(),
            self_bundle: None,
        };
        let mut never = || -> Option<String> { panic!("must not ask") };
        let err = log_in(&cfg, &Account::default(), &mut never).err().unwrap();
        assert_eq!(err.code, ErrorCode::AnisetteUnavailable);
        assert_eq!(err.phase.as_deref(), Some("PreparingAnisette"));
        let bad = Config {
            anisette_server: Some("ftp://x".into()),
            ..cfg
        };
        let err = log_in(&bad, &Account::default(), &mut never).err().unwrap();
        assert_eq!(err.code, ErrorCode::InvalidArguments);
        let missing = Config {
            anisette_server: None,
            anisette_mode: Some(AnisetteMode::Remote),
            ..bad
        };
        assert_eq!(
            prepare_anisette(&missing).unwrap_err().code,
            ErrorCode::AnisetteUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_mode_never_falls_back_to_a_stored_server() {
        let dir = temp_dir("local-no-fallback");
        std::os::unix::fs::symlink(&dir, dir.join("anisette-local")).unwrap();
        let cfg = Config {
            data_dir: dir,
            anisette_server: Some("ftp://unused.example".into()),
            anisette_mode: Some(AnisetteMode::Local),
            device_host: "x".into(),
            self_bundle: None,
        };
        let error = prepare_anisette(&cfg).unwrap_err();
        assert_eq!(error.code, ErrorCode::AnisetteUnavailable);
        assert_eq!(error.phase.as_deref(), Some("PreparingAnisette"));
        assert!(!error.message.contains("unused.example"));
    }

    #[test]
    fn session_codec() {
        assert!(decode_session("!!").is_none());
        assert!(decode_session(&base64::encode(b"<plist/>")).is_none());
    }
}
