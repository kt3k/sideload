//! Detached CMS SignedData with Apple's v1 and v2 hash agility attributes.
use super::{
    SignResult,
    code_directory::{HashType, cdhash},
    fail,
};
use crate::{
    crypto::{rsa_keygen::RsaPrivateKey, sha256},
    formats::{
        der,
        plist::{Dictionary, Value},
    },
};
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
fn alg(oid: &str) -> Vec<u8> {
    der::sequence([der::oid(oid), der::null()])
}
fn attr(oid: &str, values: Vec<Vec<u8>>) -> Vec<u8> {
    der::sequence([der::oid(oid), der::set_of(values)])
}
struct Certificate {
    issuer: Vec<u8>,
    serial: Vec<u8>,
    public: Vec<u8>,
}
fn certificate(cert: &[u8]) -> SignResult<Certificate> {
    (|| -> crate::formats::FormatResult<Certificate> {
        let mut r = der::Reader::new(cert);
        let root = r.expect(0x30)?;
        r.finish()?;
        let tbs = root.children()?.expect(0x30)?;
        let mut t = tbs.children()?;
        t.optional(0xa0)?;
        let serial = t.expect(2)?.raw.to_vec();
        t.expect(0x30)?;
        let issuer = t.expect(0x30)?.raw.to_vec();
        t.expect(0x30)?;
        t.expect(0x30)?;
        let spki = t.expect(0x30)?;
        let mut p = spki.children()?;
        let a = p.expect(0x30)?;
        if a.children()?.read()?.as_oid()? != "1.2.840.113549.1.1.1" {
            return Err(crate::formats::FormatError::new(
                "signing certificate must use RSA",
            ));
        }
        let public = p.expect(3)?.bit_string()?.to_vec();
        Ok(Certificate {
            issuer,
            serial,
            public,
        })
    })()
    .map_err(|e| fail(format!("invalid signing certificate: {e}")))
}
pub fn validate_identity(cert: &[u8], key: &RsaPrivateKey) -> SignResult<()> {
    let cert = certificate(cert)?;
    if cert.public != key.public_key_pkcs1_der() {
        return Err(fail("certificate does not match private key"));
    }
    Ok(())
}
/// `certificates[0]` is the signer; remaining DER certificates form its chain.
pub fn sign(
    directory: &[u8],
    directories: &[(HashType, Vec<u8>)],
    certificates: &[Vec<u8>],
    key: &RsaPrivateKey,
) -> SignResult<Vec<u8>> {
    let leaf = certificates
        .first()
        .ok_or_else(|| fail("no signing certificate"))?;
    validate_identity(leaf, key)?;
    let cert = certificate(leaf)?;
    let hashes = directories
        .iter()
        .map(|(h, d)| Value::Data(cdhash(d, *h)))
        .collect();
    let plist =
        Value::Dictionary(Dictionary::from_iter([("cdhashes", Value::Array(hashes))])).to_xml();
    let agility = directories
        .iter()
        .map(|(h, d)| {
            der::sequence([
                der::oid(match h {
                    HashType::Sha1 => "1.3.14.3.2.26",
                    HashType::Sha256 => SHA256,
                }),
                der::octet_string(&h.digest(d)),
            ])
        })
        .collect();
    let attrs = der::set_of([
        attr(
            "1.2.840.113549.1.9.3",
            vec![der::oid("1.2.840.113549.1.7.1")],
        ),
        attr(
            "1.2.840.113549.1.9.4",
            vec![der::octet_string(&sha256(directory))],
        ),
        attr("1.2.840.113635.100.9.1", vec![der::octet_string(&plist)]),
        attr("1.2.840.113635.100.9.2", agility),
    ]);
    let signature = key.sign_sha256(&attrs).map_err(|e| fail(e.to_string()))?;
    let mut implicit = attrs;
    implicit[0] = 0xa0;
    let signer = der::sequence([
        der::integer(1),
        der::sequence([cert.issuer, cert.serial]),
        alg(SHA256),
        implicit,
        alg("1.2.840.113549.1.1.1"),
        der::octet_string(&signature),
    ]);
    let mut certs = certificates.to_vec();
    certs.sort();
    certs.dedup();
    let sd = der::sequence([
        der::integer(1),
        der::set_of([alg(SHA256)]),
        der::sequence([der::oid("1.2.840.113549.1.7.1")]),
        der::tlv(0xa0, &certs.concat()),
        der::set_of([signer]),
    ]);
    Ok(der::sequence([
        der::oid("1.2.840.113549.1.7.2"),
        der::explicit(0, &sd),
    ]))
}
