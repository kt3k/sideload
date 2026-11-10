//! Shared helper for the commands that talk to Apple: build the anisette
//! provider, collect credentials, log in, and hand back an authenticated
//! Developer Services client (SPEC Sections 9.1-9.4).

use crate::anisette;
use crate::apple::Https;
use crate::apple::developer::{Developer, Team};
use crate::apple::gsa::Gsa;
use crate::config::{ProcessEnv, Settings};
use crate::formats::date::format_iso8601;
use crate::pipeline::Phase;
use crate::{Result, credentials, output, session_store};

/// An authenticated Developer client plus the Apple ID that logged in (used
/// for the per-account signing key path, SPEC Section 4.2).
pub struct Authenticated {
    pub dev: Developer<Https>,
    pub apple_id: String,
}

/// Logs in and returns a Developer client sharing the login's transport and
/// anisette provider. For `install` (`for_install`), announces and tags the
/// `PreparingAnisette` and `LoggingIn` phases; diagnostics pass `false`.
pub fn authenticate(settings: &Settings, for_install: bool) -> Result<Authenticated> {
    let tag = |p: Phase| {
        move |e: crate::Error| {
            if for_install && e.phase.is_none() {
                e.with_phase(p)
            } else {
                e
            }
        }
    };
    if for_install {
        output::phase(Phase::PreparingAnisette);
    }
    let anisette = anisette::provider(settings).map_err(tag(Phase::PreparingAnisette))?;

    if for_install {
        output::phase(Phase::LoggingIn);
    }
    let login = tag(Phase::LoggingIn);
    let env = ProcessEnv;
    if !session_store::enabled(&env) {
        let creds = credentials::resolve(&env).map_err(login)?;
        return log_in(anisette, creds, false).map_err(login);
    }

    // SPEC Section 9.6: reuse a saved session before asking for a password.
    let apple_id = resolve_apple_id(&env).map_err(login)?;
    if let Some(saved) = session_store::load(&apple_id, now_secs()) {
        output::info(format!("Using the saved session for {apple_id}."));
        let mut dev = Developer::new(saved, anisette).map_err(login)?;
        match dev.list_teams() {
            Ok(_) => return Ok(Authenticated { dev, apple_id }),
            Err(e) => {
                output::debug(format!("saved session rejected: {}", e.code.as_str()));
                output::info("The saved session was not accepted; logging in again.");
                if let Err(e) = session_store::delete(&apple_id) {
                    output::warn(format!("could not remove the saved session: {e}"));
                }
            }
        }
        let anisette = anisette::provider(settings).map_err(tag(Phase::PreparingAnisette))?;
        let creds = credentials::resolve_for(&env, &apple_id).map_err(login)?;
        return log_in(anisette, creds, true).map_err(login);
    }
    let creds = credentials::resolve_for(&env, &apple_id).map_err(login)?;
    log_in(anisette, creds, true).map_err(login)
}

/// SPEC Section 9.2 step 1, with the only saved Apple ID as the default.
fn resolve_apple_id(env: &ProcessEnv) -> Result<String> {
    let saved = session_store::saved_apple_ids(env);
    let (apple_id, source) = credentials::resolve_apple_id_or_saved(env, &saved)?;
    if source == credentials::AppleIdSource::Saved {
        output::info(format!(
            "Using the Apple ID {apple_id} (the only one with a saved session; set {} to use another).",
            crate::config::ENV_APPLE_ID
        ));
    }
    Ok(apple_id)
}

/// Full GSA login; with `save`, keeps the resulting session (SPEC 9.6).
fn log_in(
    anisette: Box<dyn anisette::AnisetteProvider>,
    creds: credentials::Credentials,
    save: bool,
) -> Result<Authenticated> {
    let mut gsa = Gsa::new(anisette)?;
    output::info(format!("Logging in as {}...", creds.apple_id));
    let session = gsa.login(&creds, credentials::prompt_two_factor_code)?;
    if save {
        match session_store::save(&creds.apple_id, &session) {
            Ok(true) => output::info(format!(
                "Saved the session in the login Keychain until {} (`sideload logout` removes it).",
                session_store::expires_at(&session)
                    .map(|t| format_iso8601(t as i64))
                    .unwrap_or_default()
            )),
            Ok(false) => {}
            Err(e) => output::warn(format!("could not save the session: {e}")),
        }
    }
    Ok(Authenticated {
        dev: Developer::from_authenticated(session, gsa),
        apple_id: creds.apple_id.clone(),
    })
}

fn now_secs() -> u64 {
    crate::formats::date::now_unix().max(0) as u64
}

/// `logout`: removes the saved session (SPEC Section 9.6). Never logs in.
pub fn logout() -> Result<std::process::ExitCode> {
    let env = ProcessEnv;
    if !cfg!(target_os = "macos") {
        output::info("Sessions are not saved on this platform; nothing to remove.");
        return Ok(std::process::ExitCode::SUCCESS);
    }
    let apple_id = resolve_apple_id(&env)?;
    match session_store::delete(&apple_id) {
        Ok(true) => output::info(format!("Removed the saved session for {apple_id}.")),
        Ok(false) => output::info(format!("No saved session for {apple_id}.")),
        Err(e) => {
            return Err(crate::Error::new(
                crate::ErrorCode::InternalError,
                format!("could not remove the saved session: {e}"),
            ));
        }
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Selects the team per SPEC Section 9.3 and reports the choice.
pub fn select_team(dev: &mut Developer<Https>, team: Option<&str>) -> Result<Team> {
    let team = dev.select_team(team)?;
    output::debug(format!(
        "using team {} ({})",
        team.name.as_deref().unwrap_or("?"),
        team.team_id
    ));
    Ok(team)
}
