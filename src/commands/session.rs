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

/// Logs in and returns a Developer client sharing the login's transport and
/// anisette provider. `phase` tags errors for `install`; diagnostics pass
/// `None`.
pub fn authenticate(settings: &Settings, phase: Option<Phase>) -> Result<Developer<Https>> {
    let tag = |e: crate::Error| match phase {
        Some(p) => e.with_phase(p),
        None => e,
    };

    let anisette = anisette::provider(settings).map_err(tag)?;
    let creds = credentials::resolve(&ProcessEnv).map_err(tag)?;
    let mut gsa = Gsa::new(anisette).map_err(tag)?;
    output::info(format!("Logging in as {}...", creds.apple_id));
    let session = gsa
        .login(&creds, credentials::prompt_two_factor_code)
        .map_err(tag)?;
    Ok(Developer::from_authenticated(session, gsa))
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
