//! ASN.1 DER encoding and a BER-tolerant decoder (ITU-T X.690).
//!
//! Encoding is strict DER (definite lengths, minimal integers, sorted
//! `SET OF`). Decoding also accepts BER indefinite lengths and constructed
//! strings, because `.mobileprovision` files are BER-encoded CMS.
//! Only low tag numbers (0-30) are supported.

use std::borrow::Cow;

use super::{FormatError, FormatResult, date};

pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    pub const CONSTRUCTED: u8 = 0x20;

    /// `[n]` context-specific tag.
    pub const fn context(n: u8, constructed: bool) -> u8 {
        0x80 | if constructed { CONSTRUCTED } else { 0 } | (n & 0x1F)
    }

    /// `[APPLICATION n]` tag.
    pub const fn application(n: u8, constructed: bool) -> u8 {
        0x40 | if constructed { CONSTRUCTED } else { 0 } | (n & 0x1F)
    }
}

const MAX_DEPTH: usize = 64;

fn err(msg: impl Into<String>) -> FormatError {
    FormatError::new(format!("DER: {}", msg.into()))
}

// ---------------------------------------------------------------- encoding

pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn concat<I, T>(parts: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p.as_ref());
    }
    content
}

/// `SEQUENCE { parts... }` where each part is already encoded.
pub fn sequence<I, T>(parts: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    tlv(tag::SEQUENCE, &concat(parts))
}

/// `SET OF { parts... }`, sorted by encoding as DER requires.
pub fn set_of<I, T>(parts: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut parts: Vec<Vec<u8>> = parts.into_iter().map(|p| p.as_ref().to_vec()).collect();
    parts.sort();
    tlv(tag::SET, &concat(parts))
}

/// Explicit context tag `[n] { inner }` (constructed).
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(tag::context(n, true), inner)
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if v { 0xFF } else { 0x00 }])
}

pub fn null() -> Vec<u8> {
    vec![tag::NULL, 0]
}

pub fn integer(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    // Drop redundant leading 0x00 / 0xFF bytes (minimal two's complement).
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xFF && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(tag::INTEGER, &bytes[start..])
}

/// Non-negative INTEGER from big-endian magnitude bytes (RSA moduli, serials).
pub fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let trimmed = &magnitude[magnitude.iter().take_while(|&&b| b == 0).count()..];
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() || trimmed[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(tag::INTEGER, &content)
}

pub fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, data)
}

/// BIT STRING with no unused bits.
pub fn bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(data.len() + 1);
    content.push(0);
    content.extend_from_slice(data);
    tlv(tag::BIT_STRING, &content)
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, s.as_bytes())
}

pub fn printable_string(s: &str) -> FormatResult<Vec<u8>> {
    let ok = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
    if ok {
        Ok(tlv(tag::PRINTABLE_STRING, s.as_bytes()))
    } else {
        Err(err(format!("`{s}` is not a PrintableString")))
    }
}

pub fn ia5_string(s: &str) -> FormatResult<Vec<u8>> {
    if s.is_ascii() {
        Ok(tlv(tag::IA5_STRING, s.as_bytes()))
    } else {
        Err(err(format!("`{s}` is not an IA5String")))
    }
}

pub fn utc_time(unix_secs: i64) -> FormatResult<Vec<u8>> {
    Ok(tlv(
        tag::UTC_TIME,
        date::format_utc_time(unix_secs)?.as_bytes(),
    ))
}

/// Encodes a dotted OID such as `1.2.840.113549.1.1.11`.
pub fn encode_oid(dotted: &str) -> FormatResult<Vec<u8>> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| {
            a.parse::<u64>()
                .map_err(|_| err(format!("invalid OID `{dotted}`")))
        })
        .collect::<FormatResult<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err(err(format!("invalid OID `{dotted}`")));
    }
    let first = arcs[0]
        .checked_mul(40)
        .and_then(|v| v.checked_add(arcs[1]))
        .ok_or_else(|| err("OID arc too large"))?;
    let mut content = Vec::new();
    for arc in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut chunk = vec![(arc & 0x7F) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            chunk.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
        content.extend(chunk.iter().rev());
    }
    Ok(tlv(tag::OID, &content))
}

/// `encode_oid` for compile-time constants; panics on an invalid literal.
pub fn oid(dotted: &str) -> Vec<u8> {
    encode_oid(dotted).expect("invalid OID literal")
}

// ---------------------------------------------------------------- decoding

/// One decoded TLV. `content` excludes the end-of-contents octets of an
/// indefinite-length value; `raw` is the complete encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader {
            data,
            pos: 0,
            depth: 0,
        }
    }

    fn nested(data: &'a [u8], depth: usize) -> FormatResult<Self> {
        if depth > MAX_DEPTH {
            return Err(err("nesting too deep"));
        }
        Ok(Reader {
            data,
            pos: 0,
            depth,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Reads the next TLV.
    pub fn read(&mut self) -> FormatResult<Tlv<'a>> {
        let start = self.pos;
        let d = self.data;
        let tag = *d.get(start).ok_or_else(|| err("unexpected end of input"))?;
        if tag & 0x1F == 0x1F {
            return Err(err("high tag numbers are not supported"));
        }
        let first = *d.get(start + 1).ok_or_else(|| err("missing length"))?;
        let mut pos = start + 2;
        if first == 0x80 {
            if tag & tag::CONSTRUCTED == 0 {
                return Err(err("indefinite length on a primitive value"));
            }
            let mut inner = Reader::nested(&d[pos..], self.depth + 1)?;
            loop {
                if inner.data[inner.pos..].starts_with(&[0, 0]) {
                    let content = &d[pos..pos + inner.pos];
                    self.pos = pos + inner.pos + 2;
                    return Ok(Tlv {
                        tag,
                        content,
                        raw: &d[start..self.pos],
                    });
                }
                inner.read()?;
            }
        }
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7F);
            if n > 8 {
                return Err(err("length too large"));
            }
            let bytes = d.get(pos..pos + n).ok_or_else(|| err("truncated length"))?;
            pos += n;
            bytes
                .iter()
                .try_fold(0usize, |acc, &b| {
                    acc.checked_mul(256).map(|v| v | usize::from(b))
                })
                .ok_or_else(|| err("length too large"))?
        };
        let end = pos
            .checked_add(len)
            .filter(|&e| e <= d.len())
            .ok_or_else(|| err("value extends past the end of input"))?;
        self.pos = end;
        Ok(Tlv {
            tag,
            content: &d[pos..end],
            raw: &d[start..end],
        })
    }

    /// Reads the next TLV and checks its tag.
    pub fn expect(&mut self, expected: u8) -> FormatResult<Tlv<'a>> {
        let t = self.read()?;
        if t.tag != expected {
            return Err(err(format!(
                "expected tag 0x{expected:02x}, found 0x{:02x}",
                t.tag
            )));
        }
        Ok(t)
    }

    /// Reads the next TLV only if it has `tag`.
    pub fn optional(&mut self, tag: u8) -> FormatResult<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fails unless all input was consumed.
    pub fn finish(&self) -> FormatResult<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(err("trailing data"))
        }
    }
}

impl<'a> Tlv<'a> {
    pub fn is_constructed(&self) -> bool {
        self.tag & tag::CONSTRUCTED != 0
    }

    /// A reader over the children of a constructed value.
    pub fn children(&self) -> FormatResult<Reader<'a>> {
        if !self.is_constructed() {
            return Err(err("value is not constructed"));
        }
        Reader::nested(self.content, 1)
    }

    /// Two's complement content of an INTEGER.
    pub fn integer_bytes(&self) -> FormatResult<&'a [u8]> {
        if self.tag != tag::INTEGER || self.content.is_empty() {
            return Err(err("not an INTEGER"));
        }
        Ok(self.content)
    }

    /// Big-endian magnitude of a non-negative INTEGER (leading zero removed).
    pub fn unsigned_integer_bytes(&self) -> FormatResult<&'a [u8]> {
        let b = self.integer_bytes()?;
        if b[0] & 0x80 != 0 {
            return Err(err("negative INTEGER"));
        }
        Ok(if b.len() > 1 && b[0] == 0 { &b[1..] } else { b })
    }

    pub fn as_i64(&self) -> FormatResult<i64> {
        let b = self.integer_bytes()?;
        if b.len() > 8 {
            return Err(err("INTEGER does not fit in i64"));
        }
        let fill = if b[0] & 0x80 != 0 { 0xFF } else { 0x00 };
        let mut buf = [fill; 8];
        buf[8 - b.len()..].copy_from_slice(b);
        Ok(i64::from_be_bytes(buf))
    }

    pub fn as_bool(&self) -> FormatResult<bool> {
        match (self.tag, self.content) {
            (tag::BOOLEAN, [b]) => Ok(*b != 0),
            _ => Err(err("not a BOOLEAN")),
        }
    }

    pub fn as_oid(&self) -> FormatResult<String> {
        if self.tag != tag::OID || self.content.is_empty() {
            return Err(err("not an OBJECT IDENTIFIER"));
        }
        let mut arcs = Vec::new();
        let mut v: u64 = 0;
        for (i, &b) in self.content.iter().enumerate() {
            v = v.checked_mul(128).ok_or_else(|| err("OID arc too large"))? | u64::from(b & 0x7F);
            if b & 0x80 == 0 {
                if arcs.is_empty() {
                    let (a, b) = if v < 40 {
                        (0, v)
                    } else if v < 80 {
                        (1, v - 40)
                    } else {
                        (2, v - 80)
                    };
                    arcs.push(a);
                    arcs.push(b);
                } else {
                    arcs.push(v);
                }
                v = 0;
            } else if i == self.content.len() - 1 {
                return Err(err("truncated OID"));
            }
        }
        Ok(arcs
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."))
    }

    /// Text of UTF8String / PrintableString / IA5String.
    pub fn as_string(&self) -> FormatResult<&'a str> {
        match self.tag {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => {
                std::str::from_utf8(self.content).map_err(|_| err("invalid string"))
            }
            t => Err(err(format!("tag 0x{t:02x} is not a supported string type"))),
        }
    }

    /// OCTET STRING content, concatenating BER constructed segments.
    pub fn octet_string(&self) -> FormatResult<Cow<'a, [u8]>> {
        self.octet_string_at(0)
    }

    fn octet_string_at(&self, depth: usize) -> FormatResult<Cow<'a, [u8]>> {
        if depth > MAX_DEPTH {
            return Err(err("nesting too deep"));
        }
        match self.tag {
            tag::OCTET_STRING => Ok(Cow::Borrowed(self.content)),
            t if t == tag::OCTET_STRING | tag::CONSTRUCTED => {
                let mut out = Vec::new();
                let mut r = self.children()?;
                while !r.is_empty() {
                    out.extend_from_slice(&r.read()?.octet_string_at(depth + 1)?);
                }
                Ok(Cow::Owned(out))
            }
            t => Err(err(format!("expected OCTET STRING, found tag 0x{t:02x}"))),
        }
    }

    /// BIT STRING content (only whole bytes, unused bits must be 0).
    pub fn bit_string(&self) -> FormatResult<&'a [u8]> {
        match (self.tag, self.content.split_first()) {
            (tag::BIT_STRING, Some((0, rest))) => Ok(rest),
            _ => Err(err("not a byte-aligned BIT STRING")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn oids() {
        assert_eq!(oid("1.2.840.113549.1.1.11"), hex("06092a864886f70d01010b"));
        assert_eq!(oid("2.5.4.3"), hex("0603550403"));
        assert_eq!(
            oid("1.2.840.113635.100.6.1.2"),
            hex("060a2a864886f763640601 02".replace(' ', "").as_str())
        );
        for s in ["1.2.840.113549.1.1.11", "2.999.3", "0.0"] {
            let enc = oid(s);
            assert_eq!(Reader::new(&enc).read().unwrap().as_oid().unwrap(), s);
        }
        assert!(encode_oid("3.1").is_err());
        assert!(encode_oid("1.40").is_err());
        assert!(encode_oid("1").is_err());
    }

    #[test]
    fn integers() {
        for (v, enc) in [
            (0, "020100"),
            (127, "02017f"),
            (128, "02020080"),
            (256, "02020100"),
            (-1, "0201ff"),
            (-128, "020180"),
            (-129, "0202ff7f"),
        ] {
            assert_eq!(integer(v), hex(enc), "{v}");
            assert_eq!(Reader::new(&hex(enc)).read().unwrap().as_i64().unwrap(), v);
        }
        assert_eq!(unsigned_integer(&[0x00, 0x80, 0x01]), hex("0203008001"));
        assert_eq!(unsigned_integer(&[]), hex("020100"));
        let t = unsigned_integer(&[0xFF; 3]);
        assert_eq!(
            Reader::new(&t)
                .read()
                .unwrap()
                .unsigned_integer_bytes()
                .unwrap(),
            &[0xFF; 3]
        );
    }

    #[test]
    fn lengths() {
        let long = tlv(tag::OCTET_STRING, &[0; 300]);
        assert_eq!(&long[..4], &hex("0482012c")[..]);
        let t = Reader::new(&long).read().unwrap();
        assert_eq!(t.content.len(), 300);
        assert_eq!(t.raw.len(), 304);
    }

    #[test]
    fn set_of_is_sorted() {
        let s = set_of([utf8_string("b"), utf8_string("a")]);
        assert_eq!(s, hex("31060c01610c0162"));
    }

    #[test]
    fn nested_sequence_roundtrip() {
        let enc = sequence([
            integer(5),
            sequence([boolean(true), null()]),
            explicit(0, &octet_string(b"x")),
        ]);
        let mut r = Reader::new(&enc);
        let seq = r.expect(tag::SEQUENCE).unwrap();
        r.finish().unwrap();
        let mut c = seq.children().unwrap();
        assert_eq!(c.read().unwrap().as_i64().unwrap(), 5);
        let inner = c.expect(tag::SEQUENCE).unwrap();
        assert!(inner.children().unwrap().read().unwrap().as_bool().unwrap());
        let ctx = c.expect(tag::context(0, true)).unwrap();
        assert_eq!(
            &*ctx
                .children()
                .unwrap()
                .read()
                .unwrap()
                .octet_string()
                .unwrap(),
            b"x"
        );
        assert!(c.is_empty());
    }

    #[test]
    fn ber_indefinite_and_constructed_octets() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" } }
        let ber = hex("30802480040261620401630000 0000".replace(' ', "").as_str());
        let outer = Reader::new(&ber).read().unwrap();
        assert_eq!(outer.raw.len(), ber.len());
        let os = outer.children().unwrap().read().unwrap();
        assert_eq!(&*os.octet_string().unwrap(), b"abc");
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["", "30", "3005020101", "0480", "1f0100", "3080020101"] {
            assert!(Reader::new(&hex(bad)).read().is_err(), "{bad}");
        }
        assert!(printable_string("a_b").is_err());
        assert!(
            Reader::new(&utf8_string("x"))
                .read()
                .unwrap()
                .as_i64()
                .is_err()
        );
    }

    /// Parses a certificate produced by `openssl req -x509` (independent
    /// encoder) down to the subject public key.
    #[test]
    fn parses_openssl_certificate() {
        let pem = include_str!("testdata/openssl_cert.pem");
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = crate::formats::base64::decode(&b64).unwrap();

        let mut r = Reader::new(&der);
        let cert = r.expect(tag::SEQUENCE).unwrap();
        r.finish().unwrap();
        let mut c = cert.children().unwrap();
        let tbs = c.expect(tag::SEQUENCE).unwrap();
        let sig_alg = c.expect(tag::SEQUENCE).unwrap();
        assert_eq!(
            sig_alg
                .children()
                .unwrap()
                .read()
                .unwrap()
                .as_oid()
                .unwrap(),
            "1.2.840.113549.1.1.11"
        );
        c.expect(tag::BIT_STRING).unwrap();

        let mut t = tbs.children().unwrap();
        t.expect(tag::context(0, true)).unwrap(); // version
        t.expect(tag::INTEGER).unwrap(); // serial
        t.expect(tag::SEQUENCE).unwrap(); // signature
        let issuer = t.expect(tag::SEQUENCE).unwrap();
        let rdn = issuer.children().unwrap().expect(tag::SET).unwrap();
        let atv = rdn.children().unwrap().expect(tag::SEQUENCE).unwrap();
        let mut a = atv.children().unwrap();
        assert_eq!(a.read().unwrap().as_oid().unwrap(), "2.5.4.3");
        assert_eq!(a.read().unwrap().as_string().unwrap(), "sideload test");
        t.expect(tag::SEQUENCE).unwrap(); // validity
        t.expect(tag::SEQUENCE).unwrap(); // subject
        let spki = t.expect(tag::SEQUENCE).unwrap();
        let mut s = spki.children().unwrap();
        let alg = s.expect(tag::SEQUENCE).unwrap();
        assert_eq!(
            alg.children().unwrap().read().unwrap().as_oid().unwrap(),
            "1.2.840.113549.1.1.1"
        );
        let key = s.expect(tag::BIT_STRING).unwrap().bit_string().unwrap();
        let rsa = Reader::new(key).expect(tag::SEQUENCE).unwrap();
        let mut k = rsa.children().unwrap();
        assert_eq!(
            k.read().unwrap().unsigned_integer_bytes().unwrap().len(),
            256
        ); // 2048-bit modulus
        assert_eq!(k.read().unwrap().as_i64().unwrap(), 65537);
    }
}
