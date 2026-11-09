//! What the core reads from provisioning profiles (`ios/SPEC.md` 4.5, 7.4).

use sideload::crypto::{hex, sha256};
use sideload::formats::plist::Value;
use sideload::sign::entitlements::profile_plist;

use crate::error::{CResult, CoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInfo {
    pub team_id: Option<String>,
    /// `ExpirationDate`, Unix seconds.
    pub expires: Option<i64>,
    /// Lowercase hex SHA-256 of each `DeveloperCertificates` entry.
    pub certificates: Vec<String>,
}

pub fn certificate_sha256(der: &[u8]) -> String {
    hex(&sha256(der))
}

impl ProfileInfo {
    pub fn parse(raw: &[u8]) -> CResult<ProfileInfo> {
        let p = profile_plist(raw).map_err(|e| {
            CoreError::new(
                sideload::ErrorCode::ProfileDownloadFailed,
                format!("invalid provisioning profile: {e}"),
            )
        })?;
        Ok(ProfileInfo {
            team_id: p
                .get("TeamIdentifier")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_owned),
            expires: p
                .get("ExpirationDate")
                .and_then(Value::as_date)
                .map(|d| d as i64),
            certificates: p
                .get("DeveloperCertificates")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_data)
                        .map(certificate_sha256)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// The earliest expiry among `profiles` (Section 4.5 `profile_expires`).
pub fn earliest_expiry(profiles: &[ProfileInfo]) -> Option<i64> {
    profiles.iter().filter_map(|p| p.expires).min()
}

/// Section 7.4 step 3: profile-only refresh is possible when the signing
/// certificate is unknown or every profile authorizes it.
pub fn authorizes(profiles: &[ProfileInfo], certificate_sha256: Option<&str>) -> bool {
    match certificate_sha256 {
        None => true,
        Some(want) => profiles
            .iter()
            .all(|p| p.certificates.iter().any(|c| c.eq_ignore_ascii_case(want))),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sideload::formats::plist::Dictionary;

    /// A minimal CMS SignedData wrapping `plist` the way Apple's profiles do,
    /// enough for `profile_plist`.
    pub(crate) fn wrap_profile(plist: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let n = body.len();
            if n < 0x80 {
                out.push(n as u8);
            } else {
                let bytes: Vec<u8> = n
                    .to_be_bytes()
                    .into_iter()
                    .skip_while(|&b| b == 0)
                    .collect();
                out.push(0x80 | bytes.len() as u8);
                out.extend(bytes);
            }
            out.extend_from_slice(body);
            out
        }
        // OIDs 1.2.840.113549.1.7.2 (signedData) and .1 (data).
        let oid = |last: u8| {
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, last],
            )
        };
        let content = tlv(0xa0, &tlv(0x04, plist));
        let eci = tlv(0x30, &[oid(1), content].concat());
        let sd = tlv(0x30, &[tlv(0x02, &[1]), tlv(0x31, &[]), eci].concat());
        tlv(0x30, &[oid(2), tlv(0xa0, &sd)].concat())
    }

    pub(crate) fn profile(team: &str, expires: f64, certs: &[&[u8]]) -> Vec<u8> {
        let mut d = Dictionary::new();
        d.insert("TeamIdentifier", Value::Array(vec![team.into()]));
        d.insert("ExpirationDate", Value::Date(expires));
        d.insert(
            "DeveloperCertificates",
            Value::Array(certs.iter().map(|c| Value::Data(c.to_vec())).collect()),
        );
        wrap_profile(&Value::Dictionary(d).to_xml())
    }

    #[test]
    fn parses_profile() {
        let raw = profile("TEAM1", 1_800_000_000.0, &[b"cert-a", b"cert-b"]);
        let info = ProfileInfo::parse(&raw).unwrap();
        assert_eq!(info.team_id.as_deref(), Some("TEAM1"));
        assert_eq!(info.expires, Some(1_800_000_000));
        assert_eq!(info.certificates[0], certificate_sha256(b"cert-a"));
        assert!(ProfileInfo::parse(b"junk").is_err());
    }

    #[test]
    fn authorization_and_expiry() {
        let a = ProfileInfo::parse(&profile("T", 200.0, &[b"a", b"b"])).unwrap();
        let b = ProfileInfo::parse(&profile("T", 100.0, &[b"a"])).unwrap();
        let both = [a, b];
        assert_eq!(earliest_expiry(&both), Some(100));
        assert!(authorizes(&both, None));
        assert!(authorizes(&both, Some(&certificate_sha256(b"a"))));
        assert!(!authorizes(&both, Some(&certificate_sha256(b"b"))));
        assert_eq!(earliest_expiry(&[]), None);
    }
}
