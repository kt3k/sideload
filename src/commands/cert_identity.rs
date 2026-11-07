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

fn write_key(path: &Path, key: &RsaPrivateKey) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| io_fail(format!("cannot create `{}`: {e}", dir.display())))?;
        set_dir_private(dir);
    }
    fs::write(path, key.to_pkcs8_pem())
        .map_err(|e| io_fail(format!("cannot write `{}`: {e}", path.display())))?;
    set_file_private(path);
    Ok(())
}

#[cfg(unix)]
fn set_dir_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn set_dir_private(_dir: &Path) {}

#[cfg(unix)]
fn set_file_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_file_private(_path: &Path) {}

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
        let existing = sideloader_certs(dev)?;
        for c in &existing {
            output::info(format!(
                "Revoking certificate `{}` (serial {}).",
                c.name.as_deref().unwrap_or("(unnamed)"),
                c.serial_number
            ));
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
}
