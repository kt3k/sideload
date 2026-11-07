//! Version 1 and 2 resource envelopes, with symlink and nested-code seals.
use super::{SignResult, fail};
use crate::{
    crypto::{sha1, sha256},
    formats::plist::{Dictionary, Value},
};
use std::{collections::BTreeMap, fs, path::Path};
#[derive(Clone, Debug)]
pub struct NestedCode {
    pub cdhash: Vec<u8>,
    pub requirement: String,
}
fn dict(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Dictionary(entries.into_iter().collect())
}
fn io(path: &Path, e: impl std::fmt::Display) -> String {
    format!("{}: {e}", path.display())
}
/// `nested` paths and `executable` are relative to the bundle. Never follows symlinks.
pub fn build(
    root: &Path,
    executable: &str,
    nested: &BTreeMap<String, NestedCode>,
) -> SignResult<Vec<u8>> {
    let mut files = Dictionary::new();
    let mut files2 = Dictionary::new();
    fn walk(
        root: &Path,
        rel: &str,
        exe: &str,
        nested: &BTreeMap<String, NestedCode>,
        files: &mut Dictionary,
        files2: &mut Dictionary,
    ) -> SignResult<()> {
        let dir = root.join(rel);
        let mut entries = fs::read_dir(&dir)
            .map_err(|e| io(&dir, e))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| io(&dir, e))?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| fail("resource path is not UTF-8"))?;
            let name = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if name == "_CodeSignature" || name == exe || name == "Info.plist" || name == "PkgInfo"
            {
                continue;
            }
            if let Some(seal) = nested.get(&name) {
                files2.insert(
                    name,
                    dict([
                        ("cdhash", Value::Data(seal.cdhash.clone())),
                        ("requirement", Value::from(seal.requirement.clone())),
                    ]),
                );
                continue;
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).map_err(|e| io(&path, e))?;
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).map_err(|e| io(&path, e))?;
                let target = target
                    .to_str()
                    .ok_or_else(|| io(&path, "symlink target is not UTF-8"))?;
                files2.insert(name, dict([("symlink", Value::from(target))]));
            } else if meta.is_dir() {
                walk(root, &name, exe, nested, files, files2)?;
            } else if meta.is_file() {
                let bytes = fs::read(&path).map_err(|e| io(&path, e))?;
                let h1 = Value::Data(sha1(&bytes).to_vec());
                let h2 = Value::Data(sha256(&bytes).to_vec());
                files.insert(name.clone(), h1.clone());
                files2.insert(name, dict([("hash", h1), ("hash2", h2)]));
            } else {
                return Err(io(&path, "unsupported resource file type"));
            }
        }
        Ok(())
    }
    walk(root, "", executable, nested, &mut files, &mut files2)?;
    let omit = || {
        dict([
            ("omit", Value::Boolean(true)),
            ("weight", Value::Real(20.0)),
        ])
    };
    let mut rules = Dictionary::new();
    rules.insert("^.*", true);
    rules.insert("^Info\\.plist$", omit());
    rules.insert("^PkgInfo$", omit());
    let mut rules2 = rules.clone();
    for name in nested.keys() {
        // Match only the signed entity, rather than treating unrelated files in
        // Frameworks/ or PlugIns/ as code.
        let mut pattern = String::from("^");
        for c in name.chars() {
            if ".+*?()[]{}^$|\\".contains(c) {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('$');
        rules2.insert(
            pattern,
            dict([
                ("nested", Value::Boolean(true)),
                ("weight", Value::Real(10.0)),
            ]),
        );
    }
    let envelope = Dictionary::from_iter([
        ("files", Value::Dictionary(files)),
        ("files2", Value::Dictionary(files2)),
        ("rules", Value::Dictionary(rules)),
        ("rules2", Value::Dictionary(rules2)),
    ]);
    Ok(Value::Dictionary(envelope).to_xml())
}
