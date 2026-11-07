//! Pairing records (SPEC Section 10): the certificates and identifiers
//! lockdownd needs to open a TLS session with a paired device. The record
//! comes from usbmuxd (`ReadPairRecord`); this module only parses it.
//!
//! The plist stores PEM certificates and keys inside `Data` fields.

use crate::crypto::rsa_keygen::{self, RsaPrivateKey};
use crate::formats::plist::{self, Value};
use crate::{Error, ErrorCode, Result};

#[derive(Clone)]
pub struct PairingRecord {
    /// DER-encoded host certificate (the TLS client certificate).
    pub host_certificate: Vec<u8>,
    pub host_private_key: RsaPrivateKey,
    pub host_id: String,
    pub system_buid: String,
    /// DER-encoded device certificate, when present.
    pub device_certificate: Option<Vec<u8>>,
    /// Passed to lockdownd `StartService` for escrowed services.
    pub escrow_bag: Option<Vec<u8>>,
    pub udid: Option<String>,
}

impl std::fmt::Debug for PairingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingRecord")
            .field("host_id", &self.host_id)
            .field("system_buid", &self.system_buid)
            .field("udid", &self.udid)
            .finish_non_exhaustive()
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::DeviceNotPaired,
        format!("invalid pairing record: {}", msg.into()),
    )
}

/// One PEM certificate's DER, from a plist `Data` (or UTF-8 `String`) field.
fn pem_cert(value: Option<&Value>, field: &str) -> Result<Vec<u8>> {
    let pem = pem_text(value, field)?;
    rsa_keygen::pem_decode(&pem, "CERTIFICATE")
        .ok_or_else(|| invalid(format!("{field} has no CERTIFICATE block")))?
        .map_err(|e| invalid(format!("{field}: {e}")))
}

fn pem_text(value: Option<&Value>, field: &str) -> Result<String> {
    let bytes = match value {
        Some(Value::Data(d)) => d.clone(),
        Some(Value::String(s)) => s.clone().into_bytes(),
        _ => return Err(invalid(format!("missing {field}"))),
    };
    String::from_utf8(bytes).map_err(|_| invalid(format!("{field} is not UTF-8 PEM")))
}

impl PairingRecord {
    pub fn parse(bytes: &[u8]) -> Result<PairingRecord> {
        let value = plist::from_bytes(bytes).map_err(|e| invalid(e.to_string()))?;
        let d = value.as_dict().ok_or_else(|| invalid("not a dictionary"))?;

        let host_private_key =
            RsaPrivateKey::from_pem(&pem_text(d.get("HostPrivateKey"), "HostPrivateKey")?)
                .map_err(|e| invalid(format!("HostPrivateKey: {e}")))?;
        let string = |k: &str| {
            d.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("missing {k}")))
        };
        Ok(PairingRecord {
            host_certificate: pem_cert(d.get("HostCertificate"), "HostCertificate")?,
            host_private_key,
            host_id: string("HostID")?,
            system_buid: string("SystemBUID")?,
            device_certificate: match d.get("DeviceCertificate") {
                Some(_) => Some(pem_cert(d.get("DeviceCertificate"), "DeviceCertificate")?),
                None => None,
            },
            escrow_bag: d
                .get("EscrowBag")
                .and_then(Value::as_data)
                .map(<[u8]>::to_vec),
            udid: d.get("UDID").and_then(Value::as_str).map(str::to_owned),
        })
    }

    /// PKCS#8 DER of the host private key, for the TLS client identity.
    pub fn host_private_key_pkcs8_der(&self) -> Vec<u8> {
        self.host_private_key.to_pkcs8_der()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::rsa_keygen::pem_encode;
    use crate::formats::plist::{Dictionary, Value};

    /// Builds a pairing record plist from a freshly generated key and a
    /// self-signed certificate created from it.
    pub(crate) fn sample_record() -> (Vec<u8>, RsaPrivateKey) {
        // certificate.pem is the self-signed certificate for this key, so the
        // record is also usable to build a TLS client identity.
        let key =
            RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem")).unwrap();
        let cert_pem = include_str!("../sign/testdata/certificate.pem").to_owned();
        let mut d = Dictionary::new();
        d.insert(
            "HostCertificate",
            Value::Data(cert_pem.clone().into_bytes()),
        );
        d.insert(
            "HostPrivateKey",
            Value::Data(key.to_pkcs8_pem().into_bytes()),
        );
        d.insert("DeviceCertificate", Value::Data(cert_pem.into_bytes()));
        d.insert("HostID", Value::from("11112222-3333"));
        d.insert("SystemBUID", Value::from("AAAA-BBBB"));
        d.insert("UDID", Value::from("00008030-001A2B3C"));
        d.insert("EscrowBag", Value::Data(vec![1, 2, 3, 4]));
        let _ = pem_encode;
        (Value::Dictionary(d).to_xml(), key)
    }

    #[test]
    fn parses_record() {
        let (bytes, key) = sample_record();
        let record = PairingRecord::parse(&bytes).unwrap();
        assert_eq!(record.host_id, "11112222-3333");
        assert_eq!(record.system_buid, "AAAA-BBBB");
        assert_eq!(record.udid.as_deref(), Some("00008030-001A2B3C"));
        assert_eq!(record.escrow_bag.as_deref(), Some(&[1u8, 2, 3, 4][..]));
        assert!(record.device_certificate.is_some());
        assert_eq!(record.host_private_key, key);
        assert_eq!(record.host_private_key_pkcs8_der(), key.to_pkcs8_der());
    }

    #[test]
    fn missing_fields_are_rejected() {
        let mut d = Dictionary::new();
        d.insert("HostID", Value::from("x"));
        let err = PairingRecord::parse(&Value::Dictionary(d).to_xml()).unwrap_err();
        assert_eq!(err.code, ErrorCode::DeviceNotPaired);
        assert!(PairingRecord::parse(b"not a plist").is_err());
    }

    #[test]
    fn device_certificate_optional() {
        let (bytes, _) = sample_record();
        let mut d = plist::from_bytes(&bytes)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone();
        d.remove("DeviceCertificate");
        let record = PairingRecord::parse(&Value::Dictionary(d).to_xml()).unwrap();
        assert!(record.device_certificate.is_none());
    }
}
