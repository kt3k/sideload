//! Diagnostic commands (SPEC Section 8). Each logs in, runs one Developer
//! Services operation, and prints a listing. `device list` also reports
//! connected devices (SPEC Section 8.2).

use std::fmt::Write as _;
use std::process::ExitCode;

use crate::apple::developer::{AppIds, Certificate, Device, Team};
use crate::commands::cert_identity;
use crate::commands::session::{authenticate, select_team};
use crate::config::Settings;
use crate::crypto::rsa_keygen::RsaPrivateKey;
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
    let mut dev = authenticate(settings, false)?.dev;
    let teams = dev.list_teams()?;
    print!("{}", render_teams(&teams));
    Ok(ExitCode::SUCCESS)
}

fn render_teams(teams: &[Team]) -> String {
    let mut out = String::from("Teams:\n");
    for team in teams {
        let _ = writeln!(
            out,
            " - `{}`, with ID `{}`.",
            team.name.as_deref().unwrap_or("(unnamed)"),
            team.team_id
        );
    }
    out
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
    let mut dev = authenticate(settings, false)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let registered = dev.list_devices(&team.team_id)?;
    let connected = connected_devices();
    print!(
        "{}",
        render_devices(&registered, &connected, udid.as_deref())
    );
    Ok(ExitCode::SUCCESS)
}

/// SPEC Section 8.2.
fn render_devices(
    registered: &[Device],
    connected: &[UsbmuxdDevice],
    udid: Option<&str>,
) -> String {
    let mut out = String::new();
    let show = |u: &str| udid.is_none_or(|want| want == u);

    // With --udid, print only lines about that device (SPEC Section 8.2).
    if udid.is_none() {
        let _ = writeln!(out, "You have {} devices registered.", registered.len());
    }
    for d in registered {
        if !show(&d.udid) {
            continue;
        }
        let mark = if connected.iter().any(|c| c.udid == d.udid) {
            " (connected)"
        } else {
            ""
        };
        let _ = writeln!(
            out,
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
        let _ = writeln!(out, "Connected devices not registered:");
        for c in unregistered {
            let _ = writeln!(out, " - `{}`", c.udid);
        }
    }
    out
}

pub fn device_delete(
    settings: &Settings,
    team: Option<String>,
    device_id: &str,
) -> Result<ExitCode> {
    let mut dev = authenticate(settings, false)?.dev;
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
    let auth = authenticate(settings, false)?;
    let mut dev = auth.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let certs = dev.list_development_certs(&team.team_id)?;
    // SPEC Section 8.4: mark the Matching Certificate (a Sideloader
    // Certificate whose public key matches this machine's key).
    let key = cert_identity::read_key_if_present(&settings.config_dir, &auth.apple_id);
    print!("{}", render_certs(&certs, key.as_ref()));
    Ok(ExitCode::SUCCESS)
}

/// SPEC Section 8.4.
fn render_certs(certs: &[Certificate], key: Option<&RsaPrivateKey>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "You have {} certificates registered.", certs.len());
    for c in certs {
        let matching = c.machine_name.as_deref() == Some(cert_identity::MACHINE_NAME)
            && key.is_some_and(|k| cert_identity::certificate_matches_key(c, k));
        let mine = if matching { " (this machine)" } else { "" };
        let _ = writeln!(
            out,
            " - `{}` with the serial number `{}`, from the machine named `{}`.{mine}",
            c.name.as_deref().unwrap_or("(unnamed)"),
            c.serial_number,
            c.machine_name.as_deref().unwrap_or("(unknown)"),
        );
    }
    out
}

pub fn cert_revoke(settings: &Settings, team: Option<String>, serial: &str) -> Result<ExitCode> {
    let mut dev = authenticate(settings, false)?.dev;
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
    let mut dev = authenticate(settings, false)?.dev;
    let team = select_team(&mut dev, team.as_deref())?;
    let list = dev.list_app_ids(&team.team_id)?;
    print!("{}", render_app_ids(&list));
    Ok(ExitCode::SUCCESS)
}

/// SPEC Section 8.6.
fn render_app_ids(list: &AppIds) -> String {
    let mut out = String::new();
    match (list.available_quantity, list.max_quantity) {
        (Some(a), Some(m)) => {
            let _ = writeln!(
                out,
                "You have {a} App IDs available out of the {m} you have at your disposal."
            );
        }
        _ => {
            let _ = writeln!(out, "You have {} App IDs registered.", list.app_ids.len());
        }
    }
    for a in &list.app_ids {
        let _ = writeln!(
            out,
            " - `{}` for the app `{}`, expiring on {}.",
            a.identifier,
            a.name,
            date(a.expiration_date),
        );
    }
    out
}

pub fn app_id_delete(
    settings: &Settings,
    team: Option<String>,
    identifier: &str,
) -> Result<ExitCode> {
    let mut dev = authenticate(settings, false)?.dev;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::developer::AppId;
    use crate::formats::plist::Dictionary;

    fn device(id: &str, udid: &str) -> Device {
        Device {
            device_id: id.into(),
            udid: udid.into(),
            name: Some(format!("iPhone {id}")),
            status: None,
        }
    }

    fn usb(udid: &str) -> UsbmuxdDevice {
        UsbmuxdDevice {
            device_id: 1,
            udid: udid.into(),
            connection_type: "USB".into(),
        }
    }

    #[test]
    fn team_list_format() {
        let teams = [Team {
            team_id: "T1".into(),
            name: Some("Me".into()),
            kind: None,
        }];
        assert_eq!(render_teams(&teams), "Teams:\n - `Me`, with ID `T1`.\n");
    }

    #[test]
    fn device_list_format() {
        let registered = [device("D1", "U1"), device("D2", "U2")];
        let connected = [usb("U1"), usb("U3")];
        assert_eq!(
            render_devices(&registered, &connected, None),
            "You have 2 devices registered.\n\
             \x20- Device `iPhone D1` of UDID `U1` with the identifier `D1` (connected)\n\
             \x20- Device `iPhone D2` of UDID `U2` with the identifier `D2`\n\
             Connected devices not registered:\n\
             \x20- `U3`\n"
        );
        // --udid: only lines about that device.
        assert_eq!(
            render_devices(&registered, &connected, Some("U2")),
            " - Device `iPhone D2` of UDID `U2` with the identifier `D2`\n"
        );
        assert_eq!(
            render_devices(&registered, &connected, Some("U3")),
            "Connected devices not registered:\n - `U3`\n"
        );
        // No device connected is not an error.
        assert_eq!(
            render_devices(&[], &[], None),
            "You have 0 devices registered.\n"
        );
    }

    #[test]
    fn cert_list_marks_only_the_matching_certificate() {
        let key =
            RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem")).unwrap();
        let der = crate::crypto::rsa_keygen::pem_decode(
            include_str!("../sign/testdata/certificate.pem"),
            "CERTIFICATE",
        )
        .unwrap()
        .unwrap();
        let cert = |serial: &str, machine: &str, content: Option<Vec<u8>>| Certificate {
            platform: Some("ios".into()),
            certificate_id: None,
            serial_number: serial.into(),
            name: Some("dev".into()),
            machine_name: Some(machine.into()),
            content,
            expiration_date: None,
        };
        let certs = [
            cert("S1", cert_identity::MACHINE_NAME, Some(der.clone())),
            cert("S2", cert_identity::MACHINE_NAME, None),
            cert("X1", "Xcode", Some(der)),
        ];
        let out = render_certs(&certs, Some(&key));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "You have 3 certificates registered.");
        assert!(lines[1].ends_with("(this machine)"), "{}", lines[1]);
        assert!(
            !lines[2].contains("(this machine)"),
            "other Sideloader cert"
        );
        assert!(
            !lines[3].contains("(this machine)"),
            "same key, other machine"
        );
        // Without a local key nothing is marked.
        assert!(!render_certs(&certs, None).contains("(this machine)"));
    }

    #[test]
    fn app_id_list_format() {
        let app_id = AppId {
            app_id_id: "A".into(),
            identifier: "com.example.a".into(),
            name: "A".into(),
            features: Dictionary::new(),
            expiration_date: Some(0.0),
        };
        let free = AppIds {
            app_ids: vec![app_id.clone()],
            available_quantity: Some(9),
            max_quantity: Some(10),
        };
        assert_eq!(
            render_app_ids(&free),
            "You have 9 App IDs available out of the 10 you have at your disposal.\n\
             \x20- `com.example.a` for the app `A`, expiring on 1970-01-01T00:00:00Z.\n"
        );
        let paid = AppIds {
            app_ids: vec![app_id],
            available_quantity: None,
            max_quantity: None,
        };
        assert!(render_app_ids(&paid).starts_with("You have 1 App IDs registered.\n"));
    }

    #[test]
    fn exactly_one_match() {
        let items = [1, 2, 2];
        let find = |n: i32| {
            exactly_one(
                items.iter().filter(|&&i| i == n).collect(),
                ErrorCode::AppIdNotFound,
                "App ID",
            )
            .copied()
            .map_err(|e| e.code)
        };
        assert_eq!(find(1), Ok(1));
        assert_eq!(find(3), Err(ErrorCode::AppIdNotFound));
        assert_eq!(find(2), Err(ErrorCode::AmbiguousMatch));
    }
}
