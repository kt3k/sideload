//! Diagnostic commands (SPEC Section 8).
//!
//! All of these log in (SPEC Section 9.2) and then call the Developer
//! Service Client. Matching for `delete`/`revoke` is exact and refuses
//! ambiguous matches (SPEC Sections 4.2, 14.4).

use std::process::ExitCode;

use crate::config::Settings;
use crate::{Error, Result};

pub fn team_list(_settings: &Settings) -> Result<ExitCode> {
    Err(Error::not_implemented("team list"))
}

pub fn device_list(
    _settings: &Settings,
    _team: Option<String>,
    _udid: Option<String>,
) -> Result<ExitCode> {
    // MUST NOT fail when no device is connected (SPEC Section 8.2).
    Err(Error::not_implemented("device list"))
}

pub fn device_delete(
    _settings: &Settings,
    _team: Option<String>,
    _device_id: &str,
) -> Result<ExitCode> {
    Err(Error::not_implemented("device delete"))
}

pub fn cert_list(_settings: &Settings, _team: Option<String>) -> Result<ExitCode> {
    Err(Error::not_implemented("cert list"))
}

pub fn cert_revoke(_settings: &Settings, _team: Option<String>, _serial: &str) -> Result<ExitCode> {
    Err(Error::not_implemented("cert revoke"))
}

pub fn app_id_list(_settings: &Settings, _team: Option<String>) -> Result<ExitCode> {
    Err(Error::not_implemented("app-id list"))
}

pub fn app_id_delete(
    _settings: &Settings,
    _team: Option<String>,
    _identifier: &str,
) -> Result<ExitCode> {
    Err(Error::not_implemented("app-id delete"))
}
