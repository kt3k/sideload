//! XML property lists (Apple `PropertyList-1.0.dtd`).

use super::{Dictionary, INTEGER_MAX, INTEGER_MIN, Value};
use crate::formats::{FormatError, FormatResult, base64, date};

const MAX_DEPTH: usize = 512;

const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n";

// ---------------------------------------------------------------- writing

pub fn to_bytes(value: &Value) -> Vec<u8> {
    to_string(value).into_bytes()
}

pub fn to_string(value: &Value) -> String {
    let mut out = String::from(HEADER);
    write_value(&mut out, value, 0);
    out.push_str("</plist>\n");
    out
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push('\t');
    }
}

fn escape(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

fn simple(out: &mut String, level: usize, tag: &str, text: &str) {
    indent(out, level);
    out.push('<');
    out.push_str(tag);
    out.push('>');
    escape(out, text);
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\n");
}

fn format_real(r: f64) -> String {
    if r.is_nan() {
        "nan".into()
    } else if r.is_infinite() {
        if r > 0.0 { "+infinity" } else { "-infinity" }.into()
    } else {
        format!("{r:?}")
    }
}

fn write_value(out: &mut String, value: &Value, level: usize) {
    match value {
        Value::Array(items) if items.is_empty() => {
            indent(out, level);
            out.push_str("<array/>\n");
        }
        Value::Array(items) => {
            indent(out, level);
            out.push_str("<array>\n");
            for item in items {
                write_value(out, item, level + 1);
            }
            indent(out, level);
            out.push_str("</array>\n");
        }
        Value::Dictionary(d) if d.is_empty() => {
            indent(out, level);
            out.push_str("<dict/>\n");
        }
        Value::Dictionary(d) => {
            indent(out, level);
            out.push_str("<dict>\n");
            for (k, v) in d.iter() {
                simple(out, level + 1, "key", k);
                write_value(out, v, level + 1);
            }
            indent(out, level);
            out.push_str("</dict>\n");
        }
        Value::Boolean(b) => {
            indent(out, level);
            out.push_str(if *b { "<true/>\n" } else { "<false/>\n" });
        }
        Value::Data(d) => simple(out, level, "data", &base64::encode(d)),
        Value::Date(secs) => simple(
            out,
            level,
            "date",
            &date::format_iso8601(secs.floor() as i64),
        ),
        Value::Integer(i) => simple(out, level, "integer", &i.to_string()),
        Value::Real(r) => simple(out, level, "real", &format_real(*r)),
        Value::String(s) => simple(out, level, "string", s),
        Value::Uid(u) => {
            let mut d = Dictionary::new();
            d.insert("CF$UID", Value::Integer((*u).into()));
            write_value(out, &Value::Dictionary(d), level);
        }
    }
}

// ---------------------------------------------------------------- parsing

pub fn from_bytes(data: &[u8]) -> FormatResult<Value> {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let text =
        std::str::from_utf8(data).map_err(|_| FormatError::new("plist: XML is not valid UTF-8"))?;
    from_str(text)
}

pub fn from_str(text: &str) -> FormatResult<Value> {
    let mut p = Parser { s: text, pos: 0 };
    p.skip_misc()?;
    let tag = p.open_tag()?;
    let value = if tag.name == "plist" {
        if tag.self_closing {
            return Err(err("empty <plist/>"));
        }
        p.skip_misc()?;
        let inner = p.open_tag()?;
        let value = p.value(inner, 0)?;
        p.skip_misc()?;
        p.close_tag("plist")?;
        value
    } else {
        p.value(tag, 0)?
    };
    p.skip_misc()?;
    if p.pos != p.s.len() {
        return Err(err("trailing content after the root element"));
    }
    Ok(value)
}

fn err(msg: impl Into<String>) -> FormatError {
    FormatError::new(format!("plist XML: {}", msg.into()))
}

struct Tag<'a> {
    name: &'a str,
    self_closing: bool,
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn skip_ws(&mut self) {
        let trimmed = self.rest().trim_start_matches([' ', '\t', '\r', '\n']);
        self.pos = self.s.len() - trimmed.len();
    }

    fn skip_past(&mut self, end: &str) -> FormatResult<()> {
        match self.rest().find(end) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => Err(err(format!("unterminated construct, expected `{end}`"))),
        }
    }

    /// Skips whitespace, the XML declaration, processing instructions,
    /// comments and the DOCTYPE.
    fn skip_misc(&mut self) -> FormatResult<()> {
        loop {
            self.skip_ws();
            let r = self.rest();
            if r.starts_with("<?") {
                self.skip_past("?>")?;
            } else if r.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if r.starts_with("<!DOCTYPE") {
                if r[..r.find('>').unwrap_or(r.len())].contains('[') {
                    return Err(err("DOCTYPE internal subsets are not supported"));
                }
                self.skip_past(">")?;
            } else {
                return Ok(());
            }
        }
    }

    fn open_tag(&mut self) -> FormatResult<Tag<'a>> {
        let r = self.rest();
        if !r.starts_with('<') || r.starts_with("</") {
            return Err(err(format!("expected an element at byte {}", self.pos)));
        }
        let end = r.find('>').ok_or_else(|| err("unterminated tag"))?;
        let inner = &r[1..end];
        let (inner, self_closing) = match inner.strip_suffix('/') {
            Some(i) => (i, true),
            None => (inner, false),
        };
        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(inner.len());
        let name = &inner[..name_end];
        if name.is_empty() {
            return Err(err("empty tag name"));
        }
        self.pos += end + 1;
        Ok(Tag { name, self_closing })
    }

    fn close_tag(&mut self, name: &str) -> FormatResult<()> {
        let r = self.rest();
        let expected_len = 2 + name.len();
        if r.starts_with("</") && r[2..].starts_with(name) {
            let after = r[expected_len..].trim_start_matches([' ', '\t', '\r', '\n']);
            if let Some(after) = after.strip_prefix('>') {
                self.pos = self.s.len() - after.len();
                return Ok(());
            }
        }
        Err(err(format!("expected </{name}> at byte {}", self.pos)))
    }

    /// Reads character data up to `</name>`, decoding entities and CDATA.
    fn text(&mut self, tag: &Tag<'_>) -> FormatResult<String> {
        if tag.self_closing {
            return Ok(String::new());
        }
        let mut out = String::new();
        loop {
            let r = self.rest();
            if r.starts_with("</") {
                self.close_tag(tag.name)?;
                return Ok(out);
            }
            if let Some(cdata) = r.strip_prefix("<![CDATA[") {
                let end = cdata.find("]]>").ok_or_else(|| err("unterminated CDATA"))?;
                out.push_str(&cdata[..end]);
                self.pos += 9 + end + 3;
                continue;
            }
            if r.starts_with("<!--") {
                self.skip_past("-->")?;
                continue;
            }
            if r.starts_with('<') {
                return Err(err(format!("unexpected element inside <{}>", tag.name)));
            }
            if r.is_empty() {
                return Err(err(format!("unterminated <{}>", tag.name)));
            }
            if let Some(entity) = r.strip_prefix('&') {
                let end = entity.find(';').ok_or_else(|| err("unterminated entity"))?;
                let name = &entity[..end];
                let c = match name {
                    "lt" => '<',
                    "gt" => '>',
                    "amp" => '&',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => {
                        let code = if let Some(hex) = name.strip_prefix("#x") {
                            u32::from_str_radix(hex, 16).ok()
                        } else if let Some(dec) = name.strip_prefix('#') {
                            dec.parse().ok()
                        } else {
                            None
                        };
                        code.and_then(char::from_u32)
                            .ok_or_else(|| err(format!("unknown entity &{name};")))?
                    }
                };
                out.push(c);
                self.pos += 1 + end + 1;
                continue;
            }
            let chunk_end = r.find(['<', '&']).unwrap_or(r.len());
            out.push_str(&r[..chunk_end]);
            self.pos += chunk_end;
        }
    }

    fn value(&mut self, tag: Tag<'a>, depth: usize) -> FormatResult<Value> {
        if depth > MAX_DEPTH {
            return Err(err("nesting too deep"));
        }
        Ok(match tag.name {
            "dict" => {
                let mut d = Dictionary::new();
                if !tag.self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with("</") {
                            self.close_tag("dict")?;
                            break;
                        }
                        let key_tag = self.open_tag()?;
                        if key_tag.name != "key" {
                            return Err(err(format!("expected <key>, found <{}>", key_tag.name)));
                        }
                        let key = self.text(&key_tag)?;
                        self.skip_misc()?;
                        let value_tag = self.open_tag()?;
                        let value = self.value(value_tag, depth + 1)?;
                        if d.insert(key.clone(), value).is_some() {
                            return Err(err(format!("duplicate key `{key}`")));
                        }
                    }
                }
                Value::Dictionary(d)
            }
            "array" => {
                let mut items = Vec::new();
                if !tag.self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with("</") {
                            self.close_tag("array")?;
                            break;
                        }
                        let t = self.open_tag()?;
                        items.push(self.value(t, depth + 1)?);
                    }
                }
                Value::Array(items)
            }
            "true" | "false" => {
                if !tag.self_closing {
                    self.close_tag(tag.name)?;
                }
                Value::Boolean(tag.name == "true")
            }
            "string" => Value::String(self.text(&tag)?),
            "data" => Value::Data(base64::decode(&self.text(&tag)?)?),
            "date" => Value::Date(date::parse_iso8601(self.text(&tag)?.trim())? as f64),
            "integer" => Value::Integer(parse_integer(self.text(&tag)?.trim())?),
            "real" => Value::Real(parse_real(self.text(&tag)?.trim())?),
            other => return Err(err(format!("unknown element <{other}>"))),
        })
    }
}

fn parse_integer(s: &str) -> FormatResult<i128> {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let magnitude = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16)
    } else {
        digits.parse::<i128>()
    }
    .ok()
    .filter(|_| !digits.is_empty() && !digits.starts_with(['+', '-']))
    .ok_or_else(|| err(format!("invalid integer `{s}`")))?;
    let v = if neg { -magnitude } else { magnitude };
    if !(INTEGER_MIN..=INTEGER_MAX).contains(&v) {
        return Err(err(format!("integer out of range `{s}`")));
    }
    Ok(v)
}

fn parse_real(s: &str) -> FormatResult<f64> {
    match s.to_ascii_lowercase().as_str() {
        "nan" => Ok(f64::NAN),
        "inf" | "+inf" | "infinity" | "+infinity" => Ok(f64::INFINITY),
        "-inf" | "-infinity" => Ok(f64::NEG_INFINITY),
        _ => s
            .parse::<f64>()
            .ok()
            .filter(|r| r.is_finite())
            .ok_or_else(|| err(format!("invalid real `{s}`"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::plist::tests::sample;

    #[test]
    fn roundtrip() {
        let v = sample();
        let xml = to_string(&v);
        assert_eq!(from_str(&xml).unwrap(), v);
    }

    #[test]
    fn writes_apple_layout() {
        let mut d = Dictionary::new();
        d.insert("CFBundleIdentifier", "com.example.app");
        d.insert("Flags", Value::Array(vec![true.into()]));
        d.insert("Empty", Dictionary::new());
        let expected = format!(
            "{HEADER}<dict>\n\t<key>CFBundleIdentifier</key>\n\t<string>com.example.app</string>\n\
             \t<key>Flags</key>\n\t<array>\n\t\t<true/>\n\t</array>\n\t<key>Empty</key>\n\t<dict/>\n</dict>\n</plist>\n"
        );
        assert_eq!(to_string(&Value::Dictionary(d)), expected);
    }

    /// Output of Python's `plistlib.dumps` (an independent implementation).
    #[test]
    fn parses_python_plistlib_output() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>a</key>
	<array>
		<integer>1</integer>
		<real>2.5</real>
		<string>x &amp; y</string>
	</array>
	<key>d</key>
	<date>2026-11-06T12:34:56Z</date>
	<key>data</key>
	<data>
	AAEC/w==
	</data>
	<key>t</key>
	<true/>
</dict>
</plist>
"#;
        let v = from_str(xml).unwrap();
        assert_eq!(
            v.get("a").unwrap().as_array().unwrap(),
            &[Value::from(1i64), Value::Real(2.5), Value::from("x & y")]
        );
        assert_eq!(v.get("d").unwrap().as_date(), Some(1_793_968_496.0));
        assert_eq!(
            v.get("data").unwrap().as_data(),
            Some(&[0u8, 1, 2, 255][..])
        );
        assert_eq!(v.get("t").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn entities_cdata_comments() {
        let v =
            from_str("<plist><!-- c --><string>&#65;&#x42;<![CDATA[<raw>]]>&lt;</string></plist>")
                .unwrap();
        assert_eq!(v, Value::from("AB<raw><"));
    }

    #[test]
    fn integers() {
        assert_eq!(parse_integer("0x10").unwrap(), 16);
        assert_eq!(parse_integer("-5").unwrap(), -5);
        assert_eq!(parse_integer("18446744073709551615").unwrap(), INTEGER_MAX);
        for bad in ["", "-", "18446744073709551616", "1.5", "--1", "abc"] {
            assert!(parse_integer(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "<plist><dict><key>a</key></dict></plist>",
            "<plist><dict><string>a</string></dict></plist>",
            "<plist><string>a</plist>",
            "<plist><foo/></plist>",
            "<plist><dict><key>a</key><true/><key>a</key><true/></dict></plist>",
            "<plist><string>a</string></plist>junk",
            "<!DOCTYPE plist [<!ENTITY x \"y\">]><plist><string>&x;</string></plist>",
        ] {
            assert!(from_str(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn depth_limit() {
        let deep = "<array>".repeat(MAX_DEPTH + 2) + &"</array>".repeat(MAX_DEPTH + 2);
        assert!(from_str(&deep).is_err());
    }
}
