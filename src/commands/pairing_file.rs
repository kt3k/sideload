//! SideStore pairing file (SPEC Section 10.4): put this computer's pairing
//! record, with the device UDID added, into every installed SideStore's (and
//! Sideload iOS app's, `ios/SPEC.md` 5.1) `Documents/ALTPairingFile.mobiledevicepairing`,
//! and enable Wi-Fi connections, so the app can refresh apps without the
//! computer.
//!
//! Like `deliver`, this needs a real paired device; the record handling and
//! the service clients are tested separately.

use std::process::ExitCode;

use crate::commands::deliver;
use crate::device::connect::Usbmux;
use crate::device::installation_proxy::{self, InstallationProxyClient};
use crate::device::{house_arrest, usbmuxd::Usbmuxd};
use crate::formats::plist::{self, Value};
use crate::{Error, ErrorCode, Result, output};

/// Bundle identifiers SideStore is installed under start with this
/// (`install -s` appends the team ID).
pub const SIDESTORE_PREFIX: &str = "com.SideStore.SideStore";
/// The Sideload iOS app's original bundle identifier (`ios/SPEC.md` 13).
pub const SIDELOAD_APP_PREFIX: &str = "io.github.kt3k.sideload";
pub const PAIRING_FILE: &str = "/Documents/ALTPairingFile.mobiledevicepairing";

/// The pairing file content: usbmuxd's record plus `UDID`, as XML.
pub fn pairing_file(record: &[u8], udid: &str) -> Result<Vec<u8>> {
    let mut v = plist::from_bytes(record).map_err(|e| {
        Error::new(
            ErrorCode::DeviceNotPaired,
            format!("cannot read the pairing record: {e}"),
        )
    })?;
    let dict = v.as_dict_mut().ok_or_else(|| {
        Error::new(
            ErrorCode::DeviceNotPaired,
            "pairing record is not a dictionary",
        )
    })?;
    dict.insert("UDID", udid);
    Ok(v.to_xml())
}

/// The installed SideStore and Sideload app bundle identifiers among
/// `installed`.
pub fn sidestore_bundles(installed: &[String]) -> Vec<String> {
    installed
        .iter()
        .filter(|id| id.starts_with(SIDESTORE_PREFIX) || id.starts_with(SIDELOAD_APP_PREFIX))
        .cloned()
        .collect()
}

/// Writes the pairing file for `udid` (connected as `device_id`). Returns
/// the SideStore bundle identifiers it was written for.
pub fn set_up(device_id: u32, udid: &str) -> Result<Vec<String>> {
    let record = deliver::pairing_record_bytes(udid)?;
    let pairing = crate::device::pairing::PairingRecord::parse(&record)?;
    let content = pairing_file(&record, udid)?;
    let conn = Usbmux { device_id };
    let mut lockdown = deliver::open_lockdown(&conn, &pairing)?;

    let ip = deliver::open_service(&mut lockdown, &conn, installation_proxy::SERVICE, None)?;
    let bundles = sidestore_bundles(&InstallationProxyClient::new(ip).browse_user_bundle_ids()?);
    if bundles.is_empty() {
        return Err(Error::new(
            ErrorCode::SidestoreNotInstalled,
            "neither SideStore nor the Sideload app is installed on the device (install SideStore with `install -s`)",
        ));
    }

    // SideStore reaches the device over Wi-Fi with this pairing.
    lockdown.set_value(
        "com.apple.mobile.wireless_lockdown",
        "EnableWifiDebugging",
        Value::Boolean(true),
    )?;

    for bundle in &bundles {
        output::debug(format!("writing the pairing file for {bundle}"));
        let stream = deliver::open_service(&mut lockdown, &conn, house_arrest::SERVICE, None)?;
        let mut afc = house_arrest::vend_container(stream, bundle)?;
        // Documents normally exists; creating it is harmless if it does.
        let _ = afc.make_directory("/Documents");
        afc.write_file(PAIRING_FILE, &content)?;
    }
    Ok(bundles)
}

/// `sidestore pairing-file [--udid <UDID>]`.
pub fn run(udid: Option<&str>) -> Result<ExitCode> {
    let devices = Usbmuxd::connect()?.list_devices()?;
    let device = match udid {
        Some(want) => devices.iter().find(|d| d.udid == want).ok_or_else(|| {
            Error::new(
                ErrorCode::DeviceNotConnected,
                "the requested device is not connected",
            )
        })?,
        None => match devices.as_slice() {
            [one] => one,
            [] => {
                return Err(Error::new(
                    ErrorCode::NoDeviceConnected,
                    "no device connected",
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::MultipleDevicesConnected,
                    "multiple devices are connected; select one with --udid",
                ));
            }
        },
    };
    let bundles = set_up(device.device_id, &device.udid)?;
    output::info(format!(
        "Set up the pairing file for {}.",
        bundles.join(", ")
    ));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::plist::Dictionary;

    #[test]
    fn pairing_file_adds_udid_and_keeps_the_record() {
        let record: Dictionary = [
            ("HostID", Value::from("H")),
            ("SystemBUID", Value::from("B")),
            ("HostPrivateKey", Value::Data(b"k".to_vec())),
        ]
        .into_iter()
        .collect();
        let out = pairing_file(&Value::Dictionary(record).to_xml(), "U1").unwrap();
        assert!(out.starts_with(b"<?xml"));
        let v = plist::from_bytes(&out).unwrap();
        assert_eq!(v.get("UDID").and_then(Value::as_str), Some("U1"));
        assert_eq!(v.get("HostID").and_then(Value::as_str), Some("H"));
        assert_eq!(
            v.get("HostPrivateKey").and_then(Value::as_data),
            Some(&b"k"[..])
        );
        assert_eq!(
            pairing_file(b"junk", "U").unwrap_err().code,
            ErrorCode::DeviceNotPaired
        );
    }

    #[test]
    fn finds_sidestore_bundles() {
        let installed = [
            "com.example.app".to_owned(),
            "com.SideStore.SideStore.TEAM".to_owned(),
            "com.SideStore.SideStore".to_owned(),
            "com.sidestore.other".to_owned(),
            "io.github.kt3k.sideload.TEAM".to_owned(),
        ];
        assert_eq!(
            sidestore_bundles(&installed),
            [
                "com.SideStore.SideStore.TEAM",
                "com.SideStore.SideStore",
                "io.github.kt3k.sideload.TEAM"
            ]
        );
        assert!(sidestore_bundles(&[]).is_empty());
    }
}
