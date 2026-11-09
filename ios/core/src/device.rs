//! The Device Link (`ios/SPEC.md` Sections 3.3, 4.3, 7.1): lockdownd on the
//! device itself, over TCP through the loopback VPN.

use sideload::ErrorCode;
use sideload::commands::deliver;
use sideload::device::connect::Tcp;
use sideload::device::pairing::PairingRecord;
use sideload::formats::plist::Value;

use crate::config::Config;
use crate::error::{CResult, CoreError, internal};
use crate::registry::write_atomic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub product_version: String,
}

/// An open link: the connector, the pairing record and what lockdownd said.
pub struct Link {
    pub conn: Tcp,
    pub pairing: PairingRecord,
    pub info: DeviceInfo,
}

pub fn load_pairing(cfg: &Config) -> CResult<PairingRecord> {
    let path = cfg.pairing_path();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::new(
                ErrorCode::DeviceNotPaired,
                "no pairing file; import one first (run `sideload sidestore pairing-file` on a computer)",
            ));
        }
        Err(e) => return Err(internal(format!("cannot read `{}`: {e}", path.display()))),
    };
    Ok(PairingRecord::parse(&bytes)?)
}

/// Section 4.3: validate, then replace `pairing.plist`. Returns the UDID the
/// file names, if any.
pub fn import_pairing(cfg: &Config, source: &std::path::Path) -> CResult<Option<String>> {
    let bytes = std::fs::read(source).map_err(|e| {
        CoreError::new(
            ErrorCode::DeviceNotPaired,
            format!("cannot read `{}`: {e}", source.display()),
        )
    })?;
    let record = PairingRecord::parse(&bytes)?;
    write_atomic(&cfg.pairing_path(), &bytes)?;
    Ok(record.udid)
}

fn string_value(v: Value, key: &str) -> CResult<String> {
    match v {
        Value::String(s) => Ok(s),
        _ => Err(CoreError::new(
            ErrorCode::DeviceTransportError,
            format!("lockdownd: {key} is not a string"),
        )),
    }
}

/// Section 7.1.
pub fn connect(cfg: &Config) -> CResult<Link> {
    let pairing = load_pairing(cfg)?;
    let conn = Tcp::new(cfg.device_host.clone());
    let mut lockdown = deliver::open_lockdown(&conn, &pairing)?;
    let udid = string_value(lockdown.get_value("UniqueDeviceID")?, "UniqueDeviceID")?;
    let name = string_value(lockdown.get_value("DeviceName")?, "DeviceName")?;
    let product_version = string_value(lockdown.get_value("ProductVersion")?, "ProductVersion")?;
    check_udid(pairing.udid.as_deref(), &udid)?;
    Ok(Link {
        conn,
        pairing,
        info: DeviceInfo {
            udid,
            name,
            product_version,
        },
    })
}

fn check_udid(in_file: Option<&str>, actual: &str) -> CResult<()> {
    match in_file {
        Some(u) if !u.eq_ignore_ascii_case(actual) => Err(CoreError::new(
            ErrorCode::DeviceNotPaired,
            format!("the pairing file is for device {u}, but this device is {actual}"),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::temp_dir;

    fn cfg(dir: &std::path::Path) -> Config {
        Config {
            data_dir: dir.to_path_buf(),
            anisette_server: None,
            anisette_mode: None,
            device_host: "127.0.0.1".into(),
            self_bundle: None,
        }
    }

    #[test]
    fn missing_pairing_file() {
        let dir = temp_dir("no-pairing");
        let err = load_pairing(&cfg(&dir)).unwrap_err();
        assert_eq!(err.code, ErrorCode::DeviceNotPaired);
        assert_eq!(
            connect(&cfg(&dir)).err().unwrap().code,
            ErrorCode::DeviceNotPaired
        );
    }

    #[test]
    fn import_validates_and_replaces() {
        let dir = temp_dir("import-pairing");
        let c = cfg(&dir);
        let good = dir.join("good.plist");
        std::fs::write(&good, sample_pairing()).unwrap();
        assert_eq!(
            import_pairing(&c, &good).unwrap().as_deref(),
            Some("00008030-001A2B3C")
        );
        let before = std::fs::read(c.pairing_path()).unwrap();
        let bad = dir.join("bad.plist");
        std::fs::write(&bad, b"not a plist").unwrap();
        assert_eq!(
            import_pairing(&c, &bad).unwrap_err().code,
            ErrorCode::DeviceNotPaired
        );
        assert_eq!(std::fs::read(c.pairing_path()).unwrap(), before);
        assert!(load_pairing(&c).is_ok());
    }

    #[test]
    fn udid_mismatch() {
        assert!(check_udid(None, "A").is_ok());
        assert!(check_udid(Some("a"), "A").is_ok());
        assert_eq!(
            check_udid(Some("B"), "A").unwrap_err().code,
            ErrorCode::DeviceNotPaired
        );
    }

    /// A pairing record with a real key and certificate (from the sideload
    /// crate's test data).
    pub(crate) fn sample_pairing() -> Vec<u8> {
        use sideload::formats::plist::Dictionary;
        let key = include_str!("../../../src/crypto/testdata/openssl_key.pem");
        let cert = include_str!("../../../src/sign/testdata/certificate.pem");
        let mut d = Dictionary::new();
        d.insert("HostCertificate", Value::Data(cert.as_bytes().to_vec()));
        d.insert("HostPrivateKey", Value::Data(key.as_bytes().to_vec()));
        d.insert("HostID", "HOST");
        d.insert("SystemBUID", "BUID");
        d.insert("UDID", "00008030-001A2B3C");
        Value::Dictionary(d).to_xml()
    }
}
