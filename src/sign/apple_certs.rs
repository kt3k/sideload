//! Apple's public CA certificates, included in the CMS certificate set so
//! that iOS can build the chain leaf -> WWDR intermediate -> Apple Root CA.
//!
//! The DER files are Apple's published certificates:
//! - Apple Worldwide Developer Relations CA G3 (SHA-256
//!   DCF21878C77F4198E4B4614F03D696D89C66C66008D4244E1B99161AAC91601F)
//! - Apple Root CA (SHA-256
//!   B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024)

use crate::formats::der;

pub const WWDR_G3: &[u8] = include_bytes!("certs/AppleWWDRCAG3.cer");
pub const ROOT_CA: &[u8] = include_bytes!("certs/AppleRootCA.cer");

/// Known intermediates that may issue development certificates.
const INTERMEDIATES: &[&[u8]] = &[WWDR_G3];

/// Returns the raw (issuer, subject) Name encodings of a certificate.
fn issuer_and_subject(cert: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut r = der::Reader::new(cert);
    let root = r.expect(der::tag::SEQUENCE).ok()?;
    let tbs = root.children().ok()?.expect(der::tag::SEQUENCE).ok()?;
    let mut t = tbs.children().ok()?;
    t.optional(der::tag::context(0, true)).ok()?;
    t.expect(der::tag::INTEGER).ok()?;
    t.expect(der::tag::SEQUENCE).ok()?;
    let issuer = t.expect(der::tag::SEQUENCE).ok()?.raw.to_vec();
    t.expect(der::tag::SEQUENCE).ok()?;
    let subject = t.expect(der::tag::SEQUENCE).ok()?.raw.to_vec();
    Some((issuer, subject))
}

/// `[leaf, issuing intermediate (if known), Apple Root CA]`.
pub fn chain_for(leaf: Vec<u8>) -> Vec<Vec<u8>> {
    let mut chain = vec![leaf];
    if let Some((issuer, _)) = issuer_and_subject(&chain[0]) {
        for intermediate in INTERMEDIATES {
            if issuer_and_subject(intermediate).is_some_and(|(_, subject)| subject == issuer) {
                chain.push(intermediate.to_vec());
                break;
            }
        }
    }
    chain.push(ROOT_CA.to_vec());
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hex, sha256};

    #[test]
    fn bundled_certificates_are_apples() {
        assert_eq!(
            hex(&sha256(WWDR_G3)),
            "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f"
        );
        assert_eq!(
            hex(&sha256(ROOT_CA)),
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
        );
        // WWDR G3 is issued by the root.
        let (wwdr_issuer, _) = issuer_and_subject(WWDR_G3).unwrap();
        let (_, root_subject) = issuer_and_subject(ROOT_CA).unwrap();
        assert_eq!(wwdr_issuer, root_subject);
    }

    /// A minimal TBS prefix whose issuer is WWDR G3's subject.
    fn issued_by_wwdr() -> Vec<u8> {
        let (_, wwdr_subject) = issuer_and_subject(WWDR_G3).unwrap();
        let subject = der::sequence([der::set_of([der::sequence([
            der::oid("2.5.4.3"),
            der::utf8_string("Apple Development: Test"),
        ])])]);
        let tbs = der::sequence([
            der::explicit(0, &der::integer(2)),
            der::integer(1),
            der::sequence([der::oid("1.2.840.113549.1.1.11")]),
            wwdr_subject,
            der::sequence::<[Vec<u8>; 0], Vec<u8>>([]),
            subject,
        ]);
        der::sequence([tbs])
    }

    #[test]
    fn chain_includes_matching_intermediate_only() {
        let leaf = issued_by_wwdr();
        assert_eq!(
            chain_for(leaf.clone()),
            vec![leaf, WWDR_G3.to_vec(), ROOT_CA.to_vec()]
        );

        // Not issued by a known intermediate: leaf and root only.
        let pem = std::str::from_utf8(include_bytes!("testdata/certificate.pem")).unwrap();
        let der = crate::crypto::rsa_keygen::pem_decode(pem, "CERTIFICATE")
            .unwrap()
            .unwrap();
        assert_eq!(chain_for(der.clone()), vec![der, ROOT_CA.to_vec()]);

        // Unparsable input: still leaf and root, never a panic.
        assert_eq!(
            chain_for(vec![1, 2, 3]),
            vec![vec![1, 2, 3], ROOT_CA.to_vec()]
        );
    }
}
