//! Property lists: the value model plus XML and binary codecs.
//!
//! Written from Apple's published formats (the `PropertyList-1.0.dtd` and
//! CoreFoundation's `CFBinaryPList.c` layout).

pub mod binary;
pub mod xml;

use super::FormatResult;

/// A plist value. Integers are stored as `i128` so that the full plist
/// range (`i64::MIN..=u64::MAX`) round-trips.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Array(Vec<Value>),
    Dictionary(Dictionary),
    Boolean(bool),
    Data(Vec<u8>),
    /// Seconds since the Unix epoch.
    Date(f64),
    Integer(i128),
    Real(f64),
    String(String),
    /// Keyed-archiver UID (binary plists only; XML writes `{CF$UID: n}`).
    Uid(u64),
}

pub const INTEGER_MIN: i128 = i64::MIN as i128;
pub const INTEGER_MAX: i128 = u64::MAX as i128;

/// An insertion-ordered dictionary. Keys are unique; `insert` replaces.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dictionary {
    entries: Vec<(String, Value)>,
}

impl Dictionary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Inserts or replaces; returns the previous value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        let key = key.into();
        let value = value.into();
        match self.get_mut(&key) {
            Some(slot) => Some(std::mem::replace(slot, value)),
            None => {
                self.entries.push((key, value));
                None
            }
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(idx).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }
}

impl<K: Into<String>, V: Into<Value>> FromIterator<(K, V)> for Dictionary {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut d = Dictionary::new();
        for (k, v) in iter {
            d.insert(k, v);
        }
        d
    }
}

impl IntoIterator for Dictionary {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i128> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_integer().and_then(|i| i64::try_from(i).ok())
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_integer().and_then(|i| u64::try_from(i).ok())
    }

    pub fn as_real(&self) -> Option<f64> {
        match self {
            Value::Real(r) => Some(*r),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<f64> {
        match self {
            Value::Date(d) => Some(*d),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dictionary> {
        match self {
            Value::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_dict_mut(&mut self) -> Option<&mut Dictionary> {
        match self {
            Value::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    /// Dictionary lookup; `None` if this is not a dictionary.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict()?.get(key)
    }

    pub fn to_xml(&self) -> Vec<u8> {
        xml::to_bytes(self)
    }

    pub fn to_binary(&self) -> FormatResult<Vec<u8>> {
        binary::to_bytes(self)
    }
}

/// Parses either format (binary if it starts with `bplist00`).
pub fn from_bytes(data: &[u8]) -> FormatResult<Value> {
    if data.starts_with(binary::MAGIC) {
        binary::from_bytes(data)
    } else {
        xml::from_bytes(data)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Boolean(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Integer(i.into())
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Value::Integer(i.into())
    }
}

impl From<u64> for Value {
    fn from(i: u64) -> Self {
        Value::Integer(i.into())
    }
}

impl From<u32> for Value {
    fn from(i: u32) -> Self {
        Value::Integer(i.into())
    }
}

impl From<f64> for Value {
    fn from(r: f64) -> Self {
        Value::Real(r)
    }
}

impl From<Dictionary> for Value {
    fn from(d: Dictionary) -> Self {
        Value::Dictionary(d)
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Value {
        let mut inner = Dictionary::new();
        inner.insert("nested", true);
        inner.insert("empty", Dictionary::new());
        let d: Dictionary = [
            ("string", Value::from("héllo <&> \"wörld\" 😀")),
            ("ascii", Value::from("plain")),
            ("int", Value::from(42i64)),
            ("negative", Value::from(-7i64)),
            ("big", Value::Integer(INTEGER_MAX)),
            ("min", Value::Integer(INTEGER_MIN)),
            ("real", Value::from(1.5f64)),
            ("true", Value::from(true)),
            ("false", Value::from(false)),
            ("data", Value::Data((0u8..=255).collect())),
            ("date", Value::Date(1_793_968_496.0)),
            (
                "array",
                Value::Array(vec![1i64.into(), "two".into(), Value::Array(vec![])]),
            ),
            ("dict", inner.into()),
        ]
        .into_iter()
        .collect();
        Value::Dictionary(d)
    }

    #[test]
    fn dictionary_insert_replaces_and_keeps_order() {
        let mut d = Dictionary::new();
        d.insert("a", 1i64);
        d.insert("b", 2i64);
        assert_eq!(d.insert("a", 3i64), Some(Value::from(1i64)));
        assert_eq!(d.keys().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(d.get("a"), Some(&Value::from(3i64)));
        assert_eq!(d.remove("a"), Some(Value::from(3i64)));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn from_bytes_detects_format() {
        let v = sample();
        assert_eq!(from_bytes(&v.to_xml()).unwrap(), v);
        assert_eq!(from_bytes(&v.to_binary().unwrap()).unwrap(), v);
    }
}
