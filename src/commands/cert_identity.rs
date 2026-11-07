//! Certificate preparation for `install` (SPEC Section 7.3): a per-account
//! RSA key stored under the configuration directory, reused with a matching
//! Apple-issued "Sideloader" certificate or (re)created via a CSR.

use std::fs;
use std::path::{Path, PathBuf};

use crate::apple::Transport;
use crate::apple::developer::{Certificate, Developer, make_csr};
use crate::crypto::rsa_keygen::RsaPrivateKey;
use crate::crypto::{hex, sha1};
use crate::formats::der;
use crate::output;
use crate::pipeline::Phase;
use crate::sign::SigningIdentity;
use crate::{Error, ErrorCode, Result};

/// The machine name Apple stores for certificates this tool creates
/// (fixed for upstream compatibility, SPEC Section 5.1).
pub const MACHINE_NAME: &str = "Sideloader";
const COMMON_NAME: &str = "Sideloader";

fn fail(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::CertificateLimitReached, msg).with_phase(Phase::PreparingCertificate)
}

fn io_fail(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InternalError, msg).with_phase(Phase::PreparingCertificate)
}

/// `<config>/keys/<sha1(apple_id) hex lower>/key.pem` (SPEC Section 4.2).
pub fn key_path(config_dir: &Path, apple_id: &str) -> PathBuf {
    let id = hex(&sha1(apple_id.as_bytes()));
    config_dir.join("keys").join(id).join("key.pem")
}

/// Loads this account's signing key, if one exists and parses.
pub fn read_key_if_present(config_dir: &Path, apple_id: &str) -> Option<RsaPrivateKey> {
    let pem = fs::read_to_string(key_path(config_dir, apple_id)).ok()?;
    RsaPrivateKey::from_pem(&pem).ok()
}

/// The RSA public key (PKCS#1 DER) inside a certificate's SubjectPublicKeyInfo.
fn cert_public_key(cert_der: &[u8]) -> Option<Vec<u8>> {
    let mut r = der::Reader::new(cert_der);
    let cert = r.expect(der::tag::SEQUENCE).ok()?;
    let tbs = cert.children().ok()?.expect(der::tag::SEQUENCE).ok()?;
    let mut t = tbs.children().ok()?;
    t.optional(der::tag::context(0, true)).ok()?; // version
    t.expect(der::tag::INTEGER).ok()?; // serial
    t.expect(der::tag::SEQUENCE).ok()?; // signature alg
    t.expect(der::tag::SEQUENCE).ok()?; // issuer
    t.expect(der::tag::SEQUENCE).ok()?; // validity
    t.expect(der::tag::SEQUENCE).ok()?; // subject
    let spki = t.expect(der::tag::SEQUENCE).ok()?;
    let mut s = spki.children().ok()?;
    s.expect(der::tag::SEQUENCE).ok()?; // algorithm
    Some(
        s.expect(der::tag::BIT_STRING)
            .ok()?
            .bit_string()
            .ok()?
            .to_vec(),
    )
}

/// True if `cert` was issued for `key`.
pub fn certificate_matches_key(cert: &Certificate, key: &RsaPrivateKey) -> bool {
    cert.content
        .as_deref()
        .and_then(cert_public_key)
        .is_some_and(|pk| pk == key.public_key_pkcs1_der())
}

fn load_or_generate_key(path: &Path) -> Result<(RsaPrivateKey, bool)> {
    if path.exists() {
        let pem = fs::read_to_string(path)
            .map_err(|e| io_fail(format!("cannot read `{}`: {e}", path.display())))?;
        let key = RsaPrivateKey::from_pem(&pem)
            .map_err(|e| io_fail(format!("cannot parse `{}`: {e}", path.display())))?;
        Ok((key, false))
    } else {
        output::info("Generating a new signing key...");
        Ok((
            RsaPrivateKey::generate(2048).map_err(|e| io_fail(e.to_string()))?,
            true,
        ))
    }
}

/// Writes the key owner-only (SPEC Section 14.3): the file is created with
/// mode 0600 from the start (never briefly readable by others), written to a
/// temporary name, then renamed over any previous key.
fn write_key(path: &Path, key: &RsaPrivateKey) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| io_fail(format!("cannot create `{}`: {e}", dir.display())))?;
        set_dir_private(dir)
            .map_err(|e| io_fail(format!("cannot restrict `{}`: {e}", dir.display())))?;
    }
    let tmp = path.with_extension("partial");
    let _ = fs::remove_file(&tmp);
    let result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(key.to_pkcs8_pem().as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io_fail(format!("cannot write `{}`: {e}", path.display())));
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}
#[cfg(not(unix))]
fn set_dir_private(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Decides, without making changes, what SPEC 7.3 will do (for the plan).
pub fn plan_action(
    sideloader: &[&Certificate],
    key: Option<&RsaPrivateKey>,
    new_cert: bool,
) -> crate::pipeline::plan::CertificateAction {
    use crate::pipeline::plan::CertificateAction;
    if new_cert {
        return CertificateAction::RevokeAndCreate {
            serials: sideloader.iter().map(|c| c.serial_number.clone()).collect(),
        };
    }
    if let Some(key) = key {
        if let Some(c) = sideloader.iter().find(|c| certificate_matches_key(c, key)) {
            return CertificateAction::Reuse {
                serial: c.serial_number.clone(),
            };
        }
    }
    CertificateAction::Create
}

/// Prepares a signing identity for `team` (SPEC Section 7.3).
pub fn prepare<T: Transport>(
    dev: &mut Developer<T>,
    team_id: &str,
    config_dir: &Path,
    apple_id: &str,
    new_cert: bool,
) -> Result<SigningIdentity> {
    let path = key_path(config_dir, apple_id);
    let sideloader_certs = |dev: &mut Developer<T>| -> Result<Vec<Certificate>> {
        Ok(dev
            .list_development_certs(team_id)?
            .into_iter()
            .filter(|c| c.machine_name.as_deref() == Some(MACHINE_NAME))
            .collect())
    };

    let key = if new_cert {
        // SPEC Section 14.5: list every certificate before revoking any.
        let existing = sideloader_certs(dev)?;
        if !existing.is_empty() {
            output::info("Revoking these certificates:");
            for c in &existing {
                output::info(format!(
                    "  `{}` (serial {})",
                    c.name.as_deref().unwrap_or("(unnamed)"),
                    c.serial_number
                ));
            }
        }
        for c in &existing {
            dev.revoke_development_cert(team_id, &c.serial_number)?;
        }
        let key = RsaPrivateKey::generate(2048).map_err(|e| io_fail(e.to_string()))?;
        write_key(&path, &key)?;
        key
    } else {
        let (key, generated) = load_or_generate_key(&path)?;
        if !generated {
            // Reuse a matching certificate if Apple still has one.
            if let Some(cert) = sideloader_certs(dev)?
                .into_iter()
                .find(|c| certificate_matches_key(c, &key))
            {
                if let Some(content) = cert.content {
                    output::debug(format!("reusing certificate serial {}", cert.serial_number));
                    return Ok(SigningIdentity::with_apple_chain(
                        content,
                        key,
                        team_id.to_owned(),
                    ));
                }
            }
        } else {
            write_key(&path, &key)?;
        }
        key
    };

    // Submit a CSR and fetch the issued certificate.
    output::info("Requesting a development certificate from Apple...");
    let csr = make_csr(&key, COMMON_NAME).map_err(|e| fail(e.message))?;
    dev.submit_development_csr(team_id, &csr)?;
    let issued = sideloader_certs(dev)?
        .into_iter()
        .find(|c| certificate_matches_key(c, &key))
        .ok_or_else(|| fail("Apple did not return the certificate we just requested"))?;
    let content = issued
        .content
        .ok_or_else(|| fail("issued certificate has no content"))?;
    Ok(SigningIdentity::with_apple_chain(
        content,
        key,
        team_id.to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::developer::Certificate;

    fn cert_with(content: Option<Vec<u8>>, serial: &str) -> Certificate {
        Certificate {
            platform: Some("ios".into()),
            certificate_id: Some("C1".into()),
            serial_number: serial.into(),
            name: Some("Sideloader".into()),
            machine_name: Some(MACHINE_NAME.into()),
            content,
            expiration_date: None,
        }
    }

    #[test]
    fn key_path_is_per_apple_id() {
        let p = key_path(Path::new("/cfg"), "User@Example.com");
        // sha1("User@Example.com") lowercased hex.
        let expected = hex(&sha1(b"User@Example.com"));
        assert_eq!(
            p,
            Path::new("/cfg")
                .join("keys")
                .join(expected)
                .join("key.pem")
        );
    }

    #[test]
    fn matches_key_by_public_key() {
        let key =
            RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem")).unwrap();
        let cert_der = {
            let pem = include_str!("../sign/testdata/certificate.pem");
            crate::crypto::rsa_keygen::pem_decode(pem, "CERTIFICATE")
                .unwrap()
                .unwrap()
        };
        let matching = cert_with(Some(cert_der), "S1");
        assert!(certificate_matches_key(&matching, &key));

        let other = RsaPrivateKey::generate(2048).unwrap();
        assert!(!certificate_matches_key(&matching, &other));
        assert!(!certificate_matches_key(&cert_with(None, "S2"), &key));
    }

    #[test]
    fn plan_action_reuse_create_revoke() {
        use crate::pipeline::plan::CertificateAction;
        let key =
            RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem")).unwrap();
        let cert_der = crate::crypto::rsa_keygen::pem_decode(
            include_str!("../sign/testdata/certificate.pem"),
            "CERTIFICATE",
        )
        .unwrap()
        .unwrap();
        let matching = cert_with(Some(cert_der), "S1");

        assert_eq!(
            plan_action(&[&matching], Some(&key), false),
            CertificateAction::Reuse {
                serial: "S1".into()
            }
        );
        assert_eq!(
            plan_action(&[], Some(&key), false),
            CertificateAction::Create
        );
        assert_eq!(plan_action(&[], None, false), CertificateAction::Create);
        assert_eq!(
            plan_action(&[&matching], Some(&key), true),
            CertificateAction::RevokeAndCreate {
                serials: vec!["S1".into()]
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn written_key_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sideload-key-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("keys").join("abc").join("key.pem");
        let key =
            RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem")).unwrap();
        write_key(&path, &key).unwrap();
        // Replacing an existing key works and keeps it private.
        write_key(&path, &key).unwrap();
        assert!(!path.with_extension("partial").exists());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            RsaPrivateKey::from_pem(&fs::read_to_string(&path).unwrap()).unwrap(),
            key
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    // ---- prepare() against a scripted Developer API (SPEC 7.3, 16.5) ----

    use crate::commands::test_support::{Script, developer, dict};
    use crate::formats::plist::Value;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sideload-cert-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn listed_cert(serial: &str, machine: &str, content: &[u8]) -> Value {
        Value::Dictionary(dict([
            ("serialNumber", Value::from(serial)),
            ("name", Value::from("cert")),
            ("machineName", Value::from(machine)),
            ("certificatePlatform", Value::from("ios")),
            ("certContent", Value::Data(content.to_vec())),
        ]))
    }

    fn test_cert_der() -> Vec<u8> {
        crate::crypto::rsa_keygen::pem_decode(
            include_str!("../sign/testdata/certificate.pem"),
            "CERTIFICATE",
        )
        .unwrap()
        .unwrap()
    }

    fn script_with_certs(certs: Vec<Value>) -> Rc<RefCell<Script>> {
        let mut s = Script::default();
        s.replies.insert(
            "listAllDevelopmentCerts",
            dict([("certificates", Value::Array(certs))]),
        );
        s.replies.insert(
            "submitDevelopmentCSR",
            dict([(
                "certRequest",
                Value::Dictionary(dict([("certRequestId", Value::from("R1"))])),
            )]),
        );
        Rc::new(RefCell::new(s))
    }

    fn actions(script: &Rc<RefCell<Script>>) -> Vec<String> {
        script.borrow().calls.iter().map(|c| c.0.clone()).collect()
    }

    #[test]
    fn existing_key_reuses_matching_certificate_without_csr() {
        let dir = temp("reuse");
        let path = key_path(&dir, "a@b.c");
        let pem = include_str!("../crypto/testdata/openssl_key.pem");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, pem).unwrap();
        let script = script_with_certs(vec![listed_cert("S1", MACHINE_NAME, &test_cert_der())]);

        prepare(&mut developer(&script), "TEAM", &dir, "a@b.c", false).unwrap();
        assert_eq!(actions(&script), ["listAllDevelopmentCerts"]);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem, "key untouched");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn new_cert_revokes_every_sideloader_cert_then_replaces_the_key() {
        let dir = temp("new-cert");
        let path = key_path(&dir, "a@b.c");
        let old = include_str!("../crypto/testdata/openssl_key.pem");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, old).unwrap();
        let der = test_cert_der();
        let script = script_with_certs(vec![
            listed_cert("S1", MACHINE_NAME, &der),
            listed_cert("X1", "Xcode", &der),
            listed_cert("S2", MACHINE_NAME, &der),
        ]);

        // The mock never issues a certificate for the new key, so prepare
        // ends with an error after the revocations and the CSR.
        let err = prepare(&mut developer(&script), "TEAM", &dir, "a@b.c", true).unwrap_err();
        assert!(err.message.contains("did not return"), "{}", err.message);

        let calls = script.borrow().calls.clone();
        let revoked: Vec<&str> = calls
            .iter()
            .filter(|c| c.0 == "revokeDevelopmentCert")
            .map(|c| c.1.get("serialNumber").and_then(Value::as_str).unwrap())
            .collect();
        assert_eq!(revoked, ["S1", "S2"], "only Sideloader certificates");
        let order = actions(&script);
        let last_revoke = order.iter().rposition(|a| a == "revokeDevelopmentCert");
        let csr = order.iter().position(|a| a == "submitDevelopmentCSR");
        assert!(last_revoke < csr, "{order:?}");

        let new = fs::read_to_string(&path).unwrap();
        assert_ne!(new, old, "--new-cert replaces the key");
        assert!(RsaPrivateKey::from_pem(&new).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
}
