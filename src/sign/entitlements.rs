//! Profile-derived XML and DER entitlements, including iOS 15's DER slot.
use super::{SignResult, fail};
use crate::formats::{
    der,
    plist::{self, Dictionary, Value},
};

/// Reads the encapsulated plist from a BER/CMS mobileprovision file.
/// The profile must come from the trusted Apple API; this is not a CMS trust verifier.
pub fn profile_plist(profile: &[u8]) -> SignResult<Value> {
    let parsed = (|| -> crate::formats::FormatResult<Vec<u8>> {
        let mut root = der::Reader::new(profile);
        let ci = root.expect(der::tag::SEQUENCE)?;
        root.finish()?;
        let mut c = ci.children()?;
        if c.read()?.as_oid()? != "1.2.840.113549.1.7.2" {
            return Err(crate::formats::FormatError::new(
                "profile is not SignedData",
            ));
        }
        let ctx = c.expect(0xa0)?;
        let sd = ctx.children()?.expect(0x30)?;
        let mut s = sd.children()?;
        s.expect(2)?;
        s.expect(0x31)?;
        let eci = s.expect(0x30)?;
        let mut e = eci.children()?;
        if e.read()?.as_oid()? != "1.2.840.113549.1.7.1" {
            return Err(crate::formats::FormatError::new(
                "profile has no data content",
            ));
        }
        let content = e.expect(0xa0)?;
        let octets = content.children()?.read()?;
        Ok(octets.octet_string()?.into_owned())
    })()
    .map_err(|e| fail(e.to_string()))?;
    plist::from_bytes(&parsed).map_err(|e| fail(e.to_string()))
}
pub fn derive(profile: &Value, identifier: &str, team: &str) -> SignResult<Dictionary> {
    let mut d = profile
        .get("Entitlements")
        .and_then(Value::as_dict)
        .cloned()
        .ok_or_else(|| fail("profile has no Entitlements dictionary"))?;
    let app = d
        .get("application-identifier")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("profile has no application-identifier"))?;
    let app = app.to_owned();
    let (prefix, pattern) = app
        .split_once('.')
        .ok_or_else(|| fail("invalid profile application identifier"))?;
    let allowed = pattern == identifier
        || pattern
            .strip_suffix('*')
            .is_some_and(|p| identifier.starts_with(p));
    if !allowed {
        return Err(fail(format!("profile does not cover {identifier}")));
    }
    if d.get("com.apple.developer.team-identifier")
        .and_then(Value::as_str)
        != Some(team)
    {
        return Err(fail("profile team does not match signing team"));
    }
    let application = format!("{prefix}.{identifier}");
    // The wildcard authorizes a concrete identifier, and must not remain in signed entitlements.
    if let Some(Value::Array(groups)) = d.get_mut("keychain-access-groups") {
        for g in groups {
            if let Value::String(s) = g {
                if s == &format!("{prefix}.*") {
                    *s = application.clone();
                } else if s.contains('*') {
                    return Err(fail("unsupported keychain access group wildcard"));
                }
            }
        }
    }
    d.insert("application-identifier", application);
    Ok(d)
}
pub fn xml(d: &Dictionary) -> Vec<u8> {
    Value::Dictionary(d.clone()).to_xml()
}
pub fn encode_der(d: &Dictionary) -> SignResult<Vec<u8>> {
    // Application 16 wraps the version and context 16 dictionary (modern
    // Apple DER plist format). Dictionary entries are sorted by UTF-8 key.
    let mut body = der::integer(1);
    body.extend(value_der(&Value::Dictionary(d.clone()), 0)?);
    Ok(der::tlv(der::tag::application(16, true), &body))
}
fn value_der(v: &Value, depth: usize) -> SignResult<Vec<u8>> {
    if depth > 64 {
        return Err(fail("entitlements nesting too deep"));
    }
    Ok(match v {
        Value::Dictionary(d) => {
            let entries: std::collections::BTreeMap<_, _> = d.iter().collect();
            let mut body = Vec::new();
            for (k, v) in entries {
                body.extend(der::sequence([
                    der::utf8_string(k),
                    value_der(v, depth + 1)?,
                ]));
            }
            der::tlv(der::tag::context(16, true), &body)
        }
        Value::Array(a) => der::sequence(
            a.iter()
                .map(|v| value_der(v, depth + 1))
                .collect::<SignResult<Vec<_>>>()?,
        ),
        Value::String(s) => der::utf8_string(s),
        Value::Boolean(b) => der::boolean(*b),
        Value::Integer(i) => {
            der::integer(i64::try_from(*i).map_err(|_| fail("entitlement integer outside i64"))?)
        }
        _ => return Err(fail("unsupported entitlement value type")),
    })
}
/// Executable-segment permissions implied by development entitlements.
pub fn executable_flags(d: &Dictionary) -> u64 {
    [
        ("get-task-allow", 0x10),
        ("run-unsigned-code", 0x10),
        ("com.apple.private.cs.debugger", 0x20),
        ("dynamic-codesigning", 0x40),
        ("com.apple.private.skip-library-validation", 0x80),
        ("com.apple.private.amfi.can-load-cdhash", 0x100),
        ("com.apple.private.amfi.can-execute-cdhash", 0x200),
    ]
    .into_iter()
    .filter(|(key, _)| d.get(key).and_then(Value::as_bool) == Some(true))
    .fold(0, |flags, (_, bit)| flags | bit)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn der_dictionary_golden() {
        let d = Dictionary::from_iter([("a", Value::Boolean(true))]);
        assert_eq!(
            encode_der(&d).unwrap(),
            [
                0x70, 13, 2, 1, 1, 0xb0, 8, 0x30, 6, 0x0c, 1, b'a', 1, 1, 0xff
            ]
        );
    }
    #[test]
    fn profile_identifier_and_team() {
        let mut e = Dictionary::new();
        e.insert("application-identifier", "PREFIX.com.test.*");
        e.insert("com.apple.developer.team-identifier", "TEAM");
        e.insert("keychain-access-groups", vec![Value::from("PREFIX.*")]);
        let p = Value::Dictionary(Dictionary::from_iter([(
            "Entitlements",
            Value::Dictionary(e),
        )]));
        let d = derive(&p, "com.test.app", "TEAM").unwrap();
        assert_eq!(
            d.get("application-identifier").and_then(Value::as_str),
            Some("PREFIX.com.test.app")
        );
        assert!(derive(&p, "com.other", "TEAM").is_err());
        assert!(derive(&p, "com.test.app", "OTHER").is_err());
    }
}
