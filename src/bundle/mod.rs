//! Bundle Processor (SPEC Sections 4.1.10, 4.2, 11.1).

pub mod ipa;

use std::fs;
use std::path::{Path, PathBuf};

use crate::formats::plist::{self, Dictionary, Value};
use crate::{Error, ErrorCode, Result};

pub const SIDESTORE_BUNDLE_ID: &str = "com.SideStore.SideStore";

fn bundle_invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::BundleInvalid, msg)
}

/// A `.app` or `.appex` directory and its `Info.plist`.
#[derive(Debug, Clone)]
pub struct AppBundle {
    pub path: PathBuf,
    pub info: Dictionary,
    /// Whether `Info.plist` was binary, so it is written back the same way.
    binary_info: bool,
    pub extensions: Vec<AppBundle>,
}

impl AppBundle {
    /// Loads a bundle and, recursively, its `PlugIns/*.appex` and
    /// `Watch/*.app` (SPEC Section 4.1.10).
    pub fn load(path: &Path) -> Result<AppBundle> {
        let info_path = path.join("Info.plist");
        let raw = fs::read(&info_path)
            .map_err(|e| bundle_invalid(format!("cannot read `{}`: {e}", info_path.display())))?;
        let binary_info = raw.starts_with(plist::binary::MAGIC);
        let info = match plist::from_bytes(&raw) {
            Ok(Value::Dictionary(d)) => d,
            Ok(_) => {
                return Err(bundle_invalid(format!(
                    "`{}` is not a dictionary",
                    info_path.display()
                )));
            }
            Err(e) => return Err(bundle_invalid(format!("`{}`: {e}", info_path.display()))),
        };
        let mut bundle = AppBundle {
            path: path.to_path_buf(),
            info,
            binary_info,
            extensions: Vec::new(),
        };
        bundle.bundle_identifier()?;
        for (dir, ext) in [("PlugIns", "appex"), ("Watch", "app")] {
            let sub = path.join(dir);
            if !sub.is_dir() {
                continue;
            }
            let mut children: Vec<PathBuf> = fs::read_dir(&sub)
                .map_err(|e| bundle_invalid(format!("`{}`: {e}", sub.display())))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir() && p.extension().is_some_and(|x| x == ext))
                .collect();
            children.sort();
            for child in children {
                bundle.extensions.push(AppBundle::load(&child)?);
            }
        }
        Ok(bundle)
    }

    pub fn bundle_identifier(&self) -> Result<&str> {
        self.info
            .get("CFBundleIdentifier")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                bundle_invalid(format!(
                    "`{}` has no CFBundleIdentifier",
                    self.path.display()
                ))
            })
    }

    /// `CFBundleName`, falling back to the display name, then the executable.
    pub fn bundle_name(&self) -> String {
        ["CFBundleName", "CFBundleDisplayName", "CFBundleExecutable"]
            .iter()
            .find_map(|k| {
                self.info
                    .get(k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default()
            .to_owned()
    }

    pub fn executable(&self) -> Option<PathBuf> {
        let name = self
            .info
            .get("CFBundleExecutable")
            .and_then(Value::as_str)?;
        Some(self.path.join(name))
    }

    /// This bundle and all nested bundles, depth first, nested bundles
    /// before their parents (the order signing needs).
    pub fn all_bundles_inner_first(&self) -> Vec<&AppBundle> {
        let mut out = Vec::new();
        for e in &self.extensions {
            out.extend(e.all_bundles_inner_first());
        }
        out.push(self);
        out
    }

    pub fn save_info(&self) -> Result<()> {
        let value = Value::Dictionary(self.info.clone());
        let bytes = if self.binary_info {
            value
                .to_binary()
                .map_err(|e| bundle_invalid(e.to_string()))?
        } else {
            value.to_xml()
        };
        let path = self.path.join("Info.plist");
        fs::write(&path, bytes)
            .map_err(|e| bundle_invalid(format!("cannot write `{}`: {e}", path.display())))
    }

    /// `--strip-extensions`: removes `PlugIns/` and `Watch/`.
    pub fn strip_extensions(&mut self) -> Result<()> {
        for dir in ["PlugIns", "Watch"] {
            let p = self.path.join(dir);
            if p.exists() {
                fs::remove_dir_all(&p)
                    .map_err(|e| bundle_invalid(format!("cannot remove `{}`: {e}", p.display())))?;
            }
        }
        self.extensions.clear();
        Ok(())
    }

    /// `--name`.
    pub fn set_display_name(&mut self, name: &str) {
        self.info.insert("CFBundleDisplayName", name);
    }
}

/// SPEC Section 4.2 `Main Bundle ID`.
pub fn main_bundle_id(original: &str, team_id: &str, override_id: Option<&str>) -> String {
    match override_id {
        Some(id) => id.to_owned(),
        None => format!("{original}.{team_id}"),
    }
}

/// Rewrites the bundle identifiers of `app` and every nested bundle
/// (SPEC Section 4.2). Returns the original main identifier.
pub fn rewrite_bundle_ids(app: &mut AppBundle, new_main: &str) -> Result<String> {
    let original = app.bundle_identifier()?.to_owned();
    fn walk(b: &mut AppBundle, original: &str, new_main: &str) -> Result<()> {
        for e in &mut b.extensions {
            let id = e.bundle_identifier()?.to_owned();
            let suffix = id
                .strip_prefix(original)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    bundle_invalid(format!(
                        "extension identifier `{id}` does not extend the main identifier `{original}`"
                    ))
                })?;
            e.info
                .insert("CFBundleIdentifier", format!("{new_main}{suffix}"));
            // Watch apps name their companion app.
            if e.info.contains_key("WKCompanionAppBundleIdentifier") {
                e.info.insert("WKCompanionAppBundleIdentifier", new_main);
            }
            walk(e, original, new_main)?;
        }
        Ok(())
    }
    walk(app, &original, new_main)?;
    app.info.insert("CFBundleIdentifier", new_main);
    Ok(original)
}

/// SPEC Section 4.2 `App ID Name`.
pub fn app_id_name(bundle_name: &str, bundle_id: &str) -> String {
    let name: String = bundle_name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if name.is_empty() {
        bundle_id.to_owned()
    } else {
        name
    }
}

/// SPEC Section 4.2 `App Group ID`.
pub fn app_group_id(main_bundle_id: &str) -> String {
    format!("group.{main_bundle_id}")
}

/// SPEC Section 11.1: SideStore reads its app group from `ALTAppGroups`.
pub fn apply_sidestore_tweaks(app: &mut AppBundle, original_id: &str, group_id: &str) {
    if original_id == SIDESTORE_BUNDLE_ID {
        app.info
            .insert("ALTAppGroups", Value::Array(vec![group_id.into()]));
    }
}

/// Saves `Info.plist` of `app` and every nested bundle.
pub fn save_all(app: &AppBundle) -> Result<()> {
    for b in app.all_bundles_inner_first() {
        b.save_info()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ipa::tests::temp_dir;

    fn write_bundle(path: &Path, id: &str, name: &str, binary: bool) {
        fs::create_dir_all(path).unwrap();
        let d: Dictionary = [
            ("CFBundleIdentifier", Value::from(id)),
            ("CFBundleName", Value::from(name)),
            ("CFBundleExecutable", Value::from(name)),
        ]
        .into_iter()
        .collect();
        let v = Value::Dictionary(d);
        let bytes = if binary {
            v.to_binary().unwrap()
        } else {
            v.to_xml()
        };
        fs::write(path.join("Info.plist"), bytes).unwrap();
    }

    fn sample(dir: &Path) -> PathBuf {
        let app = dir.join("Payload/My App.app");
        write_bundle(&app, "com.example.app", "My App!", false);
        write_bundle(
            &app.join("PlugIns/Widget.appex"),
            "com.example.app.widget",
            "Widget",
            true,
        );
        write_bundle(
            &app.join("Watch/W.app"),
            "com.example.app.watch",
            "W",
            false,
        );
        write_bundle(
            &app.join("Watch/W.app/PlugIns/WE.appex"),
            "com.example.app.watch.ext",
            "WE",
            false,
        );
        app
    }

    #[test]
    fn loads_nested_bundles() {
        let dir = temp_dir("bundle-load");
        let app = AppBundle::load(&sample(&dir)).unwrap();
        let ids: Vec<_> = app
            .all_bundles_inner_first()
            .iter()
            .map(|b| b.bundle_identifier().unwrap().to_owned())
            .collect();
        assert_eq!(
            ids,
            [
                "com.example.app.widget",
                "com.example.app.watch.ext",
                "com.example.app.watch",
                "com.example.app"
            ]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rewrites_ids_and_preserves_plist_format() {
        let dir = temp_dir("bundle-rewrite");
        let path = sample(&dir);
        let mut app = AppBundle::load(&path).unwrap();
        let new_main = main_bundle_id("com.example.app", "TEAM123", None);
        assert_eq!(
            rewrite_bundle_ids(&mut app, &new_main).unwrap(),
            "com.example.app"
        );
        app.set_display_name("Renamed");
        save_all(&app).unwrap();

        let again = AppBundle::load(&path).unwrap();
        let ids: Vec<_> = again
            .all_bundles_inner_first()
            .iter()
            .map(|b| b.bundle_identifier().unwrap().to_owned())
            .collect();
        assert_eq!(
            ids,
            [
                "com.example.app.TEAM123.widget",
                "com.example.app.TEAM123.watch.ext",
                "com.example.app.TEAM123.watch",
                "com.example.app.TEAM123"
            ]
        );
        assert_eq!(
            again.info.get("CFBundleDisplayName").unwrap().as_str(),
            Some("Renamed")
        );
        let widget = fs::read(path.join("PlugIns/Widget.appex/Info.plist")).unwrap();
        assert!(widget.starts_with(plist::binary::MAGIC));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_foreign_extension_ids() {
        let dir = temp_dir("bundle-foreign");
        let app = dir.join("Payload/A.app");
        write_bundle(&app, "com.example.app", "A", false);
        write_bundle(&app.join("PlugIns/X.appex"), "com.other.x", "X", false);
        let mut b = AppBundle::load(&app).unwrap();
        assert_eq!(
            rewrite_bundle_ids(&mut b, "x").unwrap_err().code,
            ErrorCode::BundleInvalid
        );
        // Identical identifier (not strictly longer) is also rejected.
        write_bundle(&app.join("PlugIns/X.appex"), "com.example.app", "X", false);
        let mut b = AppBundle::load(&app).unwrap();
        assert!(rewrite_bundle_ids(&mut b, "x").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strip_and_names() {
        let dir = temp_dir("bundle-strip");
        let path = sample(&dir);
        let mut app = AppBundle::load(&path).unwrap();
        app.strip_extensions().unwrap();
        assert!(
            app.extensions.is_empty()
                && !path.join("PlugIns").exists()
                && !path.join("Watch").exists()
        );
        assert_eq!(app_id_name(&app.bundle_name(), "com.example.app"), "MyApp");
        assert_eq!(app_id_name("!!!", "com.example.app"), "com.example.app");
        assert_eq!(app_group_id("com.example.app.T"), "group.com.example.app.T");
        assert_eq!(main_bundle_id("a", "T", Some("custom.id")), "custom.id");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sidestore_app_groups() {
        let dir = temp_dir("bundle-sidestore");
        let path = dir.join("Payload/SideStore.app");
        write_bundle(&path, SIDESTORE_BUNDLE_ID, "SideStore", false);
        let mut app = AppBundle::load(&path).unwrap();
        apply_sidestore_tweaks(&mut app, SIDESTORE_BUNDLE_ID, "group.x");
        assert_eq!(
            app.info.get("ALTAppGroups"),
            Some(&Value::Array(vec!["group.x".into()]))
        );
        let mut other = AppBundle::load(&path).unwrap();
        apply_sidestore_tweaks(&mut other, "com.example", "group.x");
        assert!(!other.info.contains_key("ALTAppGroups"));
        fs::remove_dir_all(dir).unwrap();
    }
}
