//! Diagnostic commands (SPEC Section 8). Each logs in, runs one Developer
//! Services operation, and prints a listing. `device list` also reports
//! connected devices (SPEC Section 8.2).

use std::process::ExitCode;

use crate::commands::session::{authenticate, select_team};
use crate::config::Settings;
use crate::device::usbmuxd::{Usbmuxd, UsbmuxdDevice};
use crate::formats::date::format_iso8601;
use crate::{Error, ErrorCode, Result, output};

fn date(secs: Option<f64>) -> String {
    secs.map(|s| format_iso8601(s as i64))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Exactly-one matcher for `delete`/`revoke` (SPEC Sections 8.5, 8.7, 14.4).
fn exactly_one<'a, T>(matches: Vec<&'a T>, nothing: ErrorCode, what: &str) -> Result<&'a T> {
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(Error::new(nothing, format!("no matching {what}"))),
        n => Err(Error::new(
            ErrorCode::AmbiguousMatch,
            format!("{n} {what}s match; refusing to act"),
        )),
    }
}

pub fn team_list(settings: &Settings) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let teams = dev.list_teams()?;
    println!("Teams:");
    for team in &teams {
        println!(
            " - `{}`, with ID `{}`.",
            team.name.as_deref().unwrap_or("(unnamed)"),
            team.team_id
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Connected devices from usbmuxd; empty (not an error) if none or usbmuxd
/// is unreachable (SPEC Section 8.2).
fn connected_devices() -> Vec<UsbmuxdDevice> {
    match Usbmuxd::connect().and_then(|mut m| m.list_devices()) {
        Ok(devices) => devices,
        Err(e) => {
            output::debug(format!("could not list connected devices: {e}"));
            Vec::new()
        }
    }
}

pub fn device_list(
    settings: &Settings,
    team: Option<String>,
    udid: Option<String>,
) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let registered = dev.list_devices(&team.team_id)?;
    let connected = connected_devices();
    let show = |u: &str| udid.as_deref().is_none_or(|want| want == u);

    println!("You have {} devices registered.", registered.len());
    for d in &registered {
        if !show(&d.udid) {
            continue;
        }
        let mark = if connected.iter().any(|c| c.udid == d.udid) {
            " (connected)"
        } else {
            ""
        };
        println!(
            " - Device `{}` of UDID `{}` with the identifier `{}`{mark}",
            d.name.as_deref().unwrap_or("(unnamed)"),
            d.udid,
            d.device_id,
        );
    }
    let unregistered: Vec<_> = connected
        .iter()
        .filter(|c| show(&c.udid) && !registered.iter().any(|r| r.udid == c.udid))
        .collect();
    if !unregistered.is_empty() {
        println!("Connected devices not registered:");
        for c in unregistered {
            println!(" - `{}`", c.udid);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn device_delete(
    settings: &Settings,
    team: Option<String>,
    device_id: &str,
) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let devices = dev.list_devices(&team.team_id)?;
    let matches: Vec<_> = devices
        .iter()
        .filter(|d| d.device_id == device_id)
        .collect();
    let device = exactly_one(matches, ErrorCode::DeviceNotFound, "device")?;
    let device_id = device.device_id.clone();
    dev.delete_device(&team.team_id, &device_id)?;
    output::info("Done.");
    Ok(ExitCode::SUCCESS)
}

pub fn cert_list(settings: &Settings, team: Option<String>) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let certs = dev.list_development_certs(&team.team_id)?;
    println!("You have {} certificates registered.", certs.len());
    for c in &certs {
        let mine = if c.machine_name.as_deref() == Some("Sideloader") {
            " (this machine)"
        } else {
            ""
        };
        println!(
            " - `{}` with the serial number `{}`, from the machine named `{}`.{mine}",
            c.name.as_deref().unwrap_or("(unnamed)"),
            c.serial_number,
            c.machine_name.as_deref().unwrap_or("(unknown)"),
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn cert_revoke(settings: &Settings, team: Option<String>, serial: &str) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let certs = dev.list_development_certs(&team.team_id)?;
    let matches: Vec<_> = certs.iter().filter(|c| c.serial_number == serial).collect();
    let cert = exactly_one(matches, ErrorCode::CertificateNotFound, "certificate")?;
    output::info(format!(
        "Revoking certificate `{}` (serial {}). Apps signed with it will stop launching.",
        cert.name.as_deref().unwrap_or("(unnamed)"),
        cert.serial_number,
    ));
    dev.revoke_development_cert(&team.team_id, serial)?;
    output::info("Done.");
    Ok(ExitCode::SUCCESS)
}

pub fn app_id_list(settings: &Settings, team: Option<String>) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let list = dev.list_app_ids(&team.team_id)?;
    match (list.available_quantity, list.max_quantity) {
        (Some(a), Some(m)) => {
            println!("You have {a} App IDs available out of the {m} you have at your disposal.")
        }
        _ => println!("You have {} App IDs registered.", list.app_ids.len()),
    }
    for a in &list.app_ids {
        println!(
            " - `{}` for the app `{}`, expiring on {}.",
            a.identifier,
            a.name,
            date(a.expiration_date),
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn app_id_delete(
    settings: &Settings,
    team: Option<String>,
    identifier: &str,
) -> Result<ExitCode> {
    let mut dev = authenticate(settings, None)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let list = dev.list_app_ids(&team.team_id)?;
    let matches: Vec<_> = list
        .app_ids
        .iter()
        .filter(|a| a.identifier == identifier)
        .collect();
    let app_id = exactly_one(matches, ErrorCode::AppIdNotFound, "App ID")?;
    let app_id_id = app_id.app_id_id.clone();
    dev.delete_app_id(&team.team_id, &app_id_id)?;
    output::info("Done. (This does not restore your App ID quota.)");
    Ok(ExitCode::SUCCESS)
}
