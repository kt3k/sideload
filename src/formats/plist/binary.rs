//! Binary property lists (`bplist00`).
//!
//! Layout: `bplist00` header, objects, an offset table, and a 32-byte
//! trailer `[6 unused][offset_int_size][object_ref_size][num_objects:u64]
//! [top_object:u64][offset_table_offset:u64]` (all big-endian).

use super::{Dictionary, Value};
use crate::formats::date::APPLE_EPOCH_OFFSET;
use crate::formats::{FormatError, FormatResult};

pub const MAGIC: &[u8] = b"bplist00";
const TRAILER_LEN: usize = 32;
const MAX_DEPTH: usize = 512;

fn err(msg: impl Into<String>) -> FormatError {
    FormatError::new(format!("binary plist: {}", msg.into()))
}

fn read_be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

// ---------------------------------------------------------------- parsing

pub fn from_bytes(data: &[u8]) -> FormatResult<Value> {
    if !data.starts_with(MAGIC) || data.len() < MAGIC.len() + TRAILER_LEN {
        return Err(err("missing header or trailer"));
    }
    let t = &data[data.len() - TRAILER_LEN..];
    let offset_size = usize::from(t[6]);
    let ref_size = usize::from(t[7]);
    let num_objects = read_be(&t[8..16]);
    let top = read_be(&t[16..24]);
    let table_offset = read_be(&t[24..32]);

    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return Err(err("invalid integer sizes in trailer"));
    }
    let objects_end = (data.len() - TRAILER_LEN) as u64;
    let table_len = num_objects
        .checked_mul(offset_size as u64)
        .ok_or_else(|| err("offset table too large"))?;
    if num_objects == 0
        || top >= num_objects
        || table_offset < MAGIC.len() as u64
        || table_offset
            .checked_add(table_len)
            .is_none_or(|end| end > objects_end)
    {
        return Err(err("invalid trailer"));
    }
    let table = &data[table_offset as usize..(table_offset + table_len) as usize];
    let offsets: Vec<usize> = table
        .chunks(offset_size)
        .map(|c| read_be(c) as usize)
        .collect();
    if offsets
        .iter()
        .any(|&o| o < MAGIC.len() || o as u64 >= table_offset)
    {
        return Err(err("object offset out of range"));
    }

    let mut p = Reader {
        data: &data[..table_offset as usize],
        offsets,
        ref_size,
        in_progress: vec![false; num_objects as usize],
    };
    p.object(top as usize, 0)
}

struct Reader<'a> {
    data: &'a [u8],
    offsets: Vec<usize>,
    ref_size: usize,
    in_progress: Vec<bool>,
}

impl Reader<'_> {
    fn bytes(&self, start: usize, len: usize) -> FormatResult<&[u8]> {
        start
            .checked_add(len)
            .and_then(|end| self.data.get(start..end))
            .ok_or_else(|| err("object extends past the offset table"))
    }

    /// Reads an integer object at `pos`; returns (value, bytes consumed).
    fn int_at(&self, pos: usize) -> FormatResult<(i128, usize)> {
        let marker = *self.bytes(pos, 1)?.first().unwrap_or(&0);
        if marker >> 4 != 0x1 {
            return Err(err("expected an integer"));
        }
        let len = 1usize << (marker & 0xF);
        let b = self.bytes(pos + 1, len)?;
        let v = match len {
            1 | 2 | 4 => i128::from(read_be(b)),
            8 => i128::from(read_be(b) as i64),
            16 => i128::from_be_bytes(b.try_into().map_err(|_| err("bad integer"))?),
            _ => return Err(err("unsupported integer width")),
        };
        Ok((v, 1 + len))
    }

    /// Returns (count, position of the payload) for marker at `pos`.
    fn count(&self, pos: usize) -> FormatResult<(usize, usize)> {
        let nibble = self.bytes(pos, 1)?[0] & 0xF;
        if nibble != 0xF {
            return Ok((usize::from(nibble), pos + 1));
        }
        let (n, used) = self.int_at(pos + 1)?;
        let n = usize::try_from(n).map_err(|_| err("invalid length"))?;
        if n > self.data.len() {
            return Err(err("length exceeds input"));
        }
        Ok((n, pos + 1 + used))
    }

    fn refs(&self, start: usize, n: usize) -> FormatResult<Vec<usize>> {
        let len = n
            .checked_mul(self.ref_size)
            .ok_or_else(|| err("too many references"))?;
        Ok(self
            .bytes(start, len)?
            .chunks(self.ref_size)
            .map(|c| read_be(c) as usize)
            .collect())
    }

    fn object(&mut self, idx: usize, depth: usize) -> FormatResult<Value> {
        if depth > MAX_DEPTH {
            return Err(err("nesting too deep"));
        }
        let pos = *self
            .offsets
            .get(idx)
            .ok_or_else(|| err("object reference out of range"))?;
        if self.in_progress[idx] {
            return Err(err("reference cycle"));
        }
        let marker = self.bytes(pos, 1)?[0];
        let value = match marker >> 4 {
            0x0 => match marker {
                0x08 => Value::Boolean(false),
                0x09 => Value::Boolean(true),
                _ => return Err(err(format!("unsupported marker 0x{marker:02x}"))),
            },
            0x1 => Value::Integer(self.int_at(pos)?.0),
            0x2 => {
                let len = 1usize << (marker & 0xF);
                let b = self.bytes(pos + 1, len)?;
                Value::Real(match len {
                    4 => f64::from(f32::from_bits(read_be(b) as u32)),
                    8 => f64::from_bits(read_be(b)),
                    _ => return Err(err("unsupported real width")),
                })
            }
            0x3 if marker == 0x33 => {
                let b = self.bytes(pos + 1, 8)?;
                Value::Date(f64::from_bits(read_be(b)) + APPLE_EPOCH_OFFSET as f64)
            }
            0x4 => {
                let (n, start) = self.count(pos)?;
                Value::Data(self.bytes(start, n)?.to_vec())
            }
            0x5 => {
                let (n, start) = self.count(pos)?;
                // "ASCII" strings are written by CF for code points < 0x80;
                // decode as Latin-1 to be lenient.
                Value::String(
                    self.bytes(start, n)?
                        .iter()
                        .map(|&b| char::from(b))
                        .collect(),
                )
            }
            0x6 => {
                let (n, start) = self.count(pos)?;
                let len = n.checked_mul(2).ok_or_else(|| err("string too long"))?;
                let units: Vec<u16> = self
                    .bytes(start, len)?
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Value::String(String::from_utf16(&units).map_err(|_| err("invalid UTF-16 string"))?)
            }
            0x8 => {
                let len = usize::from(marker & 0xF) + 1;
                if len > 8 {
                    return Err(err("UID too large"));
                }
                Value::Uid(read_be(self.bytes(pos + 1, len)?))
            }
            0xA => {
                let (n, start) = self.count(pos)?;
                let refs = self.refs(start, n)?;
                self.in_progress[idx] = true;
                let items = refs
                    .into_iter()
                    .map(|r| self.object(r, depth + 1))
                    .collect::<FormatResult<Vec<_>>>()?;
                self.in_progress[idx] = false;
                Value::Array(items)
            }
            0xD => {
                let (n, start) = self.count(pos)?;
                let keys = self.refs(start, n)?;
                let values = self.refs(start + n * self.ref_size, n)?;
                self.in_progress[idx] = true;
                let mut d = Dictionary::new();
                for (k, v) in keys.into_iter().zip(values) {
                    let key = match self.object(k, depth + 1)? {
                        Value::String(s) => s,
                        _ => return Err(err("dictionary key is not a string")),
                    };
                    let value = self.object(v, depth + 1)?;
                    if d.insert(key.clone(), value).is_some() {
                        return Err(err(format!("duplicate key `{key}`")));
                    }
                }
                self.in_progress[idx] = false;
                Value::Dictionary(d)
            }
            _ => return Err(err(format!("unsupported marker 0x{marker:02x}"))),
        };
        Ok(value)
    }
}

// ---------------------------------------------------------------- writing

enum Flat {
    Leaf(Vec<u8>),
    Array(Vec<usize>),
    Dict(Vec<usize>, Vec<usize>),
}

fn width_for(max: u64) -> usize {
    match max {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFFFF_FFFF => 4,
        _ => 8,
    }
}

fn push_be(out: &mut Vec<u8>, v: u64, width: usize) {
    out.extend_from_slice(&v.to_be_bytes()[8 - width..]);
}

fn encode_int(out: &mut Vec<u8>, v: i128) -> FormatResult<()> {
    if (0..=0xFF).contains(&v) {
        out.push(0x10);
        out.push(v as u8);
    } else if (0..=0xFFFF).contains(&v) {
        out.push(0x11);
        push_be(out, v as u64, 2);
    } else if (0..=0xFFFF_FFFF).contains(&v) {
        out.push(0x12);
        push_be(out, v as u64, 4);
    } else if let Ok(i) = i64::try_from(v) {
        out.push(0x13);
        out.extend_from_slice(&i.to_be_bytes());
    } else if (0..=i128::from(u64::MAX)).contains(&v) {
        out.push(0x14);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(err("integer out of range"));
    }
    Ok(())
}

fn marker_with_count(out: &mut Vec<u8>, kind: u8, n: usize) {
    if n < 15 {
        out.push(kind << 4 | n as u8);
    } else {
        out.push(kind << 4 | 0xF);
        // Infallible: counts are non-negative and fit in i128.
        let _ = encode_int(out, n as i128);
    }
}

fn flatten(v: &Value, out: &mut Vec<Flat>) -> FormatResult<usize> {
    let idx = out.len();
    out.push(Flat::Leaf(Vec::new()));
    let flat = match v {
        Value::Array(items) => {
            let refs = items
                .iter()
                .map(|i| flatten(i, out))
                .collect::<FormatResult<_>>()?;
            Flat::Array(refs)
        }
        Value::Dictionary(d) => {
            let mut keys = Vec::with_capacity(d.len());
            for k in d.keys() {
                keys.push(flatten(&Value::String(k.to_owned()), out)?);
            }
            let mut values = Vec::with_capacity(d.len());
            for (_, v) in d.iter() {
                values.push(flatten(v, out)?);
            }
            Flat::Dict(keys, values)
        }
        leaf => {
            let mut b = Vec::new();
            match leaf {
                Value::Boolean(false) => b.push(0x08),
                Value::Boolean(true) => b.push(0x09),
                Value::Integer(i) => encode_int(&mut b, *i)?,
                Value::Real(r) => {
                    b.push(0x23);
                    b.extend_from_slice(&r.to_bits().to_be_bytes());
                }
                Value::Date(secs) => {
                    b.push(0x33);
                    b.extend_from_slice(
                        &(secs - APPLE_EPOCH_OFFSET as f64).to_bits().to_be_bytes(),
                    );
                }
                Value::Data(d) => {
                    marker_with_count(&mut b, 0x4, d.len());
                    b.extend_from_slice(d);
                }
                Value::String(s) if s.is_ascii() => {
                    marker_with_count(&mut b, 0x5, s.len());
                    b.extend_from_slice(s.as_bytes());
                }
                Value::String(s) => {
                    let units: Vec<u16> = s.encode_utf16().collect();
                    marker_with_count(&mut b, 0x6, units.len());
                    for u in units {
                        b.extend_from_slice(&u.to_be_bytes());
                    }
                }
                Value::Uid(u) => {
                    let w = width_for(*u);
                    b.push(0x80 | (w as u8 - 1));
                    push_be(&mut b, *u, w);
                }
                Value::Array(_) | Value::Dictionary(_) => unreachable!(),
            }
            Flat::Leaf(b)
        }
    };
    out[idx] = flat;
    Ok(idx)
}

pub fn to_bytes(value: &Value) -> FormatResult<Vec<u8>> {
    let mut objects = Vec::new();
    flatten(value, &mut objects)?;
    let ref_size = width_for(objects.len() as u64 - 1);

    let mut out = MAGIC.to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for obj in &objects {
        offsets.push(out.len() as u64);
        match obj {
            Flat::Leaf(b) => out.extend_from_slice(b),
            Flat::Array(refs) => {
                marker_with_count(&mut out, 0xA, refs.len());
                for &r in refs {
                    push_be(&mut out, r as u64, ref_size);
                }
            }
            Flat::Dict(keys, values) => {
                marker_with_count(&mut out, 0xD, keys.len());
                for &r in keys.iter().chain(values) {
                    push_be(&mut out, r as u64, ref_size);
                }
            }
        }
    }
    let table_offset = out.len() as u64;
    let offset_size = width_for(table_offset);
    for o in offsets {
        push_be(&mut out, o, offset_size);
    }
    out.extend_from_slice(&[0; 6]);
    out.push(offset_size as u8);
    out.push(ref_size as u8);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&table_offset.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::base64;
    use crate::formats::plist::tests::sample;

    #[test]
    fn roundtrip() {
        let v = sample();
        assert_eq!(from_bytes(&to_bytes(&v).unwrap()).unwrap(), v);
    }

    #[test]
    fn roundtrip_large_counts() {
        let v = Value::Array((0..300).map(|i| Value::from(format!("item {i}"))).collect());
        assert_eq!(from_bytes(&to_bytes(&v).unwrap()).unwrap(), v);
        let v = Value::Data(vec![7; 70_000]);
        assert_eq!(from_bytes(&to_bytes(&v).unwrap()).unwrap(), v);
    }

    /// `plistlib.dumps({"a": [1, 2.5, "x"], "u": "ü", "t": True,
    /// "d": datetime(2026, 11, 6, 12, 34, 56), "b": b"\x00\x01"},
    /// fmt=FMT_BINARY)` from Python (an independent implementation).
    #[test]
    fn parses_python_plistlib_output() {
        let data = base64::decode(PYTHON_BPLIST).unwrap();
        let v = from_bytes(&data).unwrap();
        assert_eq!(
            v.get("a").unwrap().as_array().unwrap(),
            &[Value::from(1i64), Value::Real(2.5), Value::from("x")]
        );
        assert_eq!(v.get("u").unwrap().as_str(), Some("ü"));
        assert_eq!(v.get("t").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("d").unwrap().as_date(), Some(1_793_968_496.0));
        assert_eq!(v.get("b").unwrap().as_data(), Some(&[0u8, 1][..]));
    }

    const PYTHON_BPLIST: &str = include_str!("testdata/python.bplist.b64");

    #[test]
    fn rejects_cycles_and_garbage() {
        // A one-element array that references itself.
        let mut data = MAGIC.to_vec();
        data.extend_from_slice(&[0xA1, 0x00]); // array [obj 0] at offset 8
        let table = data.len() as u64;
        data.push(8);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]);
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&table.to_be_bytes());
        assert!(from_bytes(&data).unwrap_err().0.contains("cycle"));

        assert!(from_bytes(b"bplist00").is_err());
        let mut truncated = to_bytes(&sample()).unwrap();
        truncated.truncate(truncated.len() - 1);
        assert!(from_bytes(&truncated).is_err());
    }
}
