//! `device pairing-file` (SPEC Section 8.9): export a device's usbmuxd pair
//! record, with `UDID` added, for the on-device app (`ios/SPEC.md` 5.1).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::device::pairing::PairingRecord;
use crate::device::usbmuxd::Usbmuxd;
use crate::formats::plist::{self, Value};
use crate::{Error, ErrorCode, Result, output};

pub fn run(udid: Option<String>, out: Option<PathBuf>) -> Result<ExitCode> {
    let mut mux = Usbmuxd::connect()?;
    let udid = match udid {
        Some(u) => u,
        None => {
            let devices = mux.list_devices()?;
            match devices.as_slice() {
                [one] => one.udid.clone(),
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
            }
        }
    };
    // A fresh connection: usbmuxd answers one request per listen state.
    let record = Usbmuxd::connect()?
        .read_pair_record(&udid)?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::DeviceNotPaired,
                format!("device {udid} is not paired; trust this computer on the device"),
            )
        })?;
    let bytes = pairing_file_bytes(&record, &udid)?;
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{udid}.mobiledevicepairing")));
    write_private(&path, &bytes)?;
    output::info(format!(
        "Wrote the pairing file for {udid} to {}.",
        path.display()
    ));
    output::warn(
        "the pairing file grants full access to the device; copy it only to that device and delete other copies",
    );
    Ok(ExitCode::SUCCESS)
}

/// The pair record as an XML plist with `UDID` set. Fails if the record is
/// not a usable pairing record.
pub fn pairing_file_bytes(record: &[u8], udid: &str) -> Result<Vec<u8>> {
    PairingRecord::parse(record)?;
    let mut dict = plist::from_bytes(record)
        .ok()
        .and_then(|v| v.as_dict().cloned())
        .ok_or_else(|| Error::new(ErrorCode::DeviceNotPaired, "invalid pairing record"))?;
    dict.insert("UDID", udid);
    Ok(Value::Dictionary(dict).to_xml())
}

/// Writes `bytes` to `path` through a temporary file, owner-readable only.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let fail = |e: std::io::Error| {
        Error::new(
            ErrorCode::OutputWriteFailed,
            format!("cannot write `{}`: {e}", path.display()),
        )
    };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = options.open(&tmp).map_err(fail)?;
        f.write_all(bytes).map_err(fail)?;
        f.sync_all().map_err(fail)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::pairing::tests::sample_record;

    #[test]
    fn adds_udid_and_keeps_fields() {
        let (record, _) = sample_record();
        let mut d = plist::from_bytes(&record)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone();
        d.remove("UDID");
        let record = Value::Dictionary(d).to_xml();
        let out = pairing_file_bytes(&record, "0000-TEST").unwrap();
        let parsed = PairingRecord::parse(&out).unwrap();
        assert_eq!(parsed.udid.as_deref(), Some("0000-TEST"));
        assert_eq!(parsed.host_id, "11112222-3333");
    }

    #[test]
    fn rejects_invalid_record() {
        let err = pairing_file_bytes(b"nope", "x").unwrap_err();
        assert_eq!(err.code, ErrorCode::DeviceNotPaired);
    }

    #[test]
    fn writes_file_privately() {
        let dir = crate::bundle::ipa::tests::temp_dir("pairing-file");
        let path = dir.join("p.mobiledevicepairing");
        write_private(&path, b"data").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
