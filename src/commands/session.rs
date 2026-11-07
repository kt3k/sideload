//! Shared helper for the commands that talk to Apple: build the anisette
//! provider, collect credentials, log in, and hand back an authenticated
//! Developer Services client (SPEC Sections 9.1-9.4).

use crate::anisette;
use crate::apple::Https;
use crate::apple::developer::{Developer, Team};
use crate::apple::gsa::Gsa;
use crate::config::{ProcessEnv, Settings};
use crate::pipeline::Phase;
use crate::{Result, credentials, output};

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
    let creds = credentials::resolve(&ProcessEnv).map_err(login)?;
    let mut gsa = Gsa::new(anisette).map_err(login)?;
    output::info(format!("Logging in as {}...", creds.apple_id));
    let session = gsa
        .login(&creds, credentials::prompt_two_factor_code)
        .map_err(login)?;
    Ok(Authenticated {
        dev: Developer::from_authenticated(session, gsa),
        apple_id: creds.apple_id.clone(),
    })
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
