//! The registry of managed apps, `apps.json` (`ios/SPEC.md` Section 4.5).

use std::path::{Path, PathBuf};

use sideload::formats::json::{self, Value};

use crate::error::{CResult, internal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Installed by the app; the original IPA is kept.
    Ipa,
    /// The app itself (Section 4.6).
    SelfApp,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ipa => "ipa",
            Source::SelfApp => "self",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    pub bundle_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub bundle_id: String,
    pub original_bundle_id: String,
    pub name: String,
    pub version: Option<String>,
    pub team_id: String,
    pub bundles: Vec<BundleEntry>,
    /// Lowercase hex SHA-256 of the signing certificate.
    pub certificate_sha256: Option<String>,
    pub profile_expires: Option<i64>,
    pub installed_at: Option<i64>,
    pub refreshed_at: Option<i64>,
    pub source: Source,
}

const FILE: &str = "apps.json";
const VERSION: f64 = 1.0;

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// Directory holding a record's original IPA.
pub fn app_dir(data_dir: &Path, bundle_id: &str) -> PathBuf {
    data_dir.join("apps").join(bundle_id)
}

pub fn ipa_path(data_dir: &Path, bundle_id: &str) -> PathBuf {
    app_dir(data_dir, bundle_id).join("app.ipa")
}

fn opt_string(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn opt_time(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_f64).map(|n| n as i64)
}

fn time(t: Option<i64>) -> Value {
    t.map_or(Value::Null, |t| Value::Number(t as f64))
}

fn string(s: &Option<String>) -> Value {
    s.as_ref().map_or(Value::Null, |s| Value::from(s.as_str()))
}

impl Record {
    pub fn to_json(&self) -> Value {
        Value::object([
            ("bundle_id", Value::from(self.bundle_id.as_str())),
            (
                "original_bundle_id",
                Value::from(self.original_bundle_id.as_str()),
            ),
            ("name", Value::from(self.name.as_str())),
            ("version", string(&self.version)),
            ("team_id", Value::from(self.team_id.as_str())),
            (
                "bundles",
                Value::Array(
                    self.bundles
                        .iter()
                        .map(|b| {
                            Value::object([
                                ("bundle_id", Value::from(b.bundle_id.as_str())),
                                ("name", Value::from(b.name.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("certificate_sha256", string(&self.certificate_sha256)),
            ("profile_expires", time(self.profile_expires)),
            ("installed_at", time(self.installed_at)),
            ("refreshed_at", time(self.refreshed_at)),
            ("source", Value::from(self.source.as_str())),
        ])
    }

    pub fn from_json(v: &Value) -> Option<Record> {
        let bundles = v
            .get("bundles")?
            .as_array()?
            .iter()
            .map(|b| {
                Some(BundleEntry {
                    bundle_id: opt_string(b, "bundle_id")?,
                    name: opt_string(b, "name").unwrap_or_default(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let source = match v.get("source")?.as_str()? {
            "ipa" => Source::Ipa,
            "self" => Source::SelfApp,
            _ => return None,
        };
        Some(Record {
            bundle_id: opt_string(v, "bundle_id")?,
            original_bundle_id: opt_string(v, "original_bundle_id")?,
            name: opt_string(v, "name").unwrap_or_default(),
            version: opt_string(v, "version"),
            team_id: opt_string(v, "team_id")?,
            bundles,
            certificate_sha256: opt_string(v, "certificate_sha256"),
            profile_expires: opt_time(v, "profile_expires"),
            installed_at: opt_time(v, "installed_at"),
            refreshed_at: opt_time(v, "refreshed_at"),
            source,
        })
    }

    /// `(bundle_id, name)` pairs, as the provisioning helpers take them.
    pub fn needed(&self) -> Vec<(String, String)> {
        self.bundles
            .iter()
            .map(|b| (b.bundle_id.clone(), b.name.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    pub apps: Vec<Record>,
}

impl Registry {
    /// Reads `apps.json`. Missing means empty; malformed is an error so that
    /// it is never overwritten.
    pub fn load(data_dir: &Path) -> CResult<Registry> {
        let p = path(data_dir);
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::default()),
            Err(e) => return Err(internal(format!("cannot read `{}`: {e}", p.display()))),
        };
        let malformed = |why: &str| internal(format!("`{}` is malformed: {why}", p.display()));
        let v = json::parse(&text).map_err(|e| malformed(&e.to_string()))?;
        if v.get("version").and_then(Value::as_f64) != Some(VERSION) {
            return Err(malformed("unsupported version"));
        }
        let apps = v
            .get("apps")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no apps"))?
            .iter()
            .map(Record::from_json)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| malformed("invalid record"))?;
        Ok(Registry { apps })
    }

    /// Writes `apps.json` atomically.
    pub fn save(&self, data_dir: &Path) -> CResult<()> {
        let v = Value::object([
            ("version", Value::Number(VERSION)),
            (
                "apps",
                Value::Array(self.apps.iter().map(Record::to_json).collect()),
            ),
        ]);
        write_atomic(&path(data_dir), v.to_string().as_bytes())
    }

    pub fn get(&self, bundle_id: &str) -> Option<&Record> {
        self.apps.iter().find(|r| r.bundle_id == bundle_id)
    }

    /// Replaces the record with the same `bundle_id`, or appends it.
    pub fn upsert(&mut self, record: Record) {
        match self
            .apps
            .iter_mut()
            .find(|r| r.bundle_id == record.bundle_id)
        {
            Some(r) => *r = record,
            None => self.apps.push(record),
        }
    }

    pub fn remove(&mut self, bundle_id: &str) -> Option<Record> {
        let i = self.apps.iter().position(|r| r.bundle_id == bundle_id)?;
        Some(self.apps.remove(i))
    }
}

/// Writes through a temporary file in the same directory, then renames.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> CResult<()> {
    let fail = |e: std::io::Error| internal(format!("cannot write `{}`: {e}", path.display()));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(fail)?;
        f.write_all(bytes).map_err(fail)?;
        f.sync_all().map_err(fail)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sideload-core-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub(crate) fn record(id: &str, name: &str) -> Record {
        Record {
            bundle_id: id.into(),
            original_bundle_id: "com.example".into(),
            name: name.into(),
            version: Some("1.0".into()),
            team_id: "TEAM".into(),
            bundles: vec![BundleEntry {
                bundle_id: id.into(),
                name: name.into(),
            }],
            certificate_sha256: Some("ab".repeat(32)),
            profile_expires: Some(1_700_000_000),
            installed_at: Some(1_699_000_000),
            refreshed_at: None,
            source: Source::Ipa,
        }
    }

    #[test]
    fn round_trip() {
        let dir = temp_dir("round-trip");
        assert_eq!(Registry::load(&dir).unwrap(), Registry::default());
        let mut reg = Registry::default();
        reg.upsert(record("a.TEAM", "A"));
        reg.upsert(record("b.TEAM", "B"));
        let mut again = record("a.TEAM", "A2");
        again.source = Source::SelfApp;
        again.version = None;
        reg.upsert(again);
        reg.save(&dir).unwrap();
        let loaded = Registry::load(&dir).unwrap();
        assert_eq!(loaded, reg);
        assert_eq!(loaded.apps.len(), 2);
        assert_eq!(loaded.get("a.TEAM").unwrap().name, "A2");
        assert!(!dir.join("apps.json.tmp").exists());
    }

    #[test]
    fn ignores_unknown_fields() {
        let dir = temp_dir("unknown");
        let mut v = record("a.T", "A").to_json();
        if let Value::Object(entries) = &mut v {
            entries.push(("future".into(), Value::Bool(true)));
        }
        let text = format!(r#"{{"version":1,"extra":0,"apps":[{v}]}}"#);
        std::fs::write(path(&dir), text).unwrap();
        assert_eq!(Registry::load(&dir).unwrap().apps, vec![record("a.T", "A")]);
    }

    #[test]
    fn rejects_malformed() {
        let dir = temp_dir("malformed");
        for text in [
            "not json",
            r#"{"version":2,"apps":[]}"#,
            r#"{"version":1,"apps":[{"bundle_id":"x"}]}"#,
        ] {
            std::fs::write(path(&dir), text).unwrap();
            assert_eq!(
                Registry::load(&dir).unwrap_err().code,
                sideload::ErrorCode::InternalError,
                "{text}"
            );
        }
    }

    #[test]
    fn remove_record() {
        let mut reg = Registry::default();
        reg.upsert(record("a", "A"));
        assert!(reg.remove("b").is_none());
        assert_eq!(reg.remove("a").unwrap().bundle_id, "a");
        assert!(reg.apps.is_empty());
    }
}
