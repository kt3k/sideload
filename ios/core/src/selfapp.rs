//! The `self` record (`ios/SPEC.md` Section 4.6): the app's own bundle.

use std::path::Path;

use sideload::bundle::AppBundle;
use sideload::formats::plist::Value;

use crate::error::{CResult, CoreError};
use crate::profile::ProfileInfo;
use crate::registry::{BundleEntry, Record, Registry, Source};

/// Derives the `self` record from the bundle at `path`.
pub fn derive(path: &Path) -> CResult<Record> {
    let app = AppBundle::load(path)?;
    let bundle_id = app.bundle_identifier()?.to_owned();
    let raw = std::fs::read(path.join("embedded.mobileprovision")).map_err(|e| {
        CoreError::new(
            sideload::ErrorCode::BundleInvalid,
            format!("cannot read the app's embedded.mobileprovision: {e}"),
        )
    })?;
    let profile = ProfileInfo::parse(&raw)?;
    let team_id = profile.team_id.clone().ok_or_else(|| {
        CoreError::new(
            sideload::ErrorCode::BundleInvalid,
            "embedded.mobileprovision has no TeamIdentifier",
        )
    })?;
    let bundles = app
        .all_bundles_inner_first()
        .iter()
        .map(|b| {
            Ok(BundleEntry {
                bundle_id: b.bundle_identifier()?.to_owned(),
                name: b.bundle_name(),
            })
        })
        .collect::<sideload::Result<Vec<_>>>()?;
    let original = bundle_id
        .strip_suffix(&format!(".{team_id}"))
        .unwrap_or(&bundle_id)
        .to_owned();
    Ok(Record {
        name: display_name(&app),
        version: app
            .info
            .get("CFBundleShortVersionString")
            .and_then(Value::as_str)
            .map(str::to_owned),
        original_bundle_id: original,
        bundle_id,
        team_id,
        bundles,
        certificate_sha256: None,
        profile_expires: profile.expires,
        installed_at: None,
        refreshed_at: None,
        source: Source::SelfApp,
    })
}

/// `CFBundleDisplayName`, falling back to `AppBundle::bundle_name`.
pub fn display_name(app: &AppBundle) -> String {
    app.info
        .get("CFBundleDisplayName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| app.bundle_name())
}

/// The `self` record merged with what the registry stored about it: stored
/// refresh state wins, and the expiry is the later of the two.
pub fn merged(derived: Record, registry: &Registry) -> Record {
    match registry.get(&derived.bundle_id) {
        Some(stored) if stored.source == Source::SelfApp => Record {
            profile_expires: match (stored.profile_expires, derived.profile_expires) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            refreshed_at: stored.refreshed_at,
            ..derived
        },
        _ => derived,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::profile::tests::profile;
    use crate::registry::tests::temp_dir;
    use sideload::formats::plist::Dictionary;

    pub(crate) fn write_self_bundle(dir: &Path, expires: f64) -> std::path::PathBuf {
        let app = dir.join("Sideload.app");
        std::fs::create_dir_all(&app).unwrap();
        let mut d = Dictionary::new();
        d.insert("CFBundleIdentifier", "io.github.kt3k.sideload.TEAM1");
        d.insert("CFBundleName", "Sideload");
        d.insert("CFBundleShortVersionString", "0.1.0");
        d.insert("CFBundleExecutable", "Sideload");
        std::fs::write(app.join("Info.plist"), Value::Dictionary(d).to_xml()).unwrap();
        std::fs::write(
            app.join("embedded.mobileprovision"),
            profile("TEAM1", expires, &[b"c"]),
        )
        .unwrap();
        app
    }

    #[test]
    fn derives_self_record() {
        let dir = temp_dir("self");
        let app = write_self_bundle(&dir, 1_800_000_000.0);
        let r = derive(&app).unwrap();
        assert_eq!(r.bundle_id, "io.github.kt3k.sideload.TEAM1");
        assert_eq!(r.original_bundle_id, "io.github.kt3k.sideload");
        assert_eq!(r.team_id, "TEAM1");
        assert_eq!(r.name, "Sideload");
        assert_eq!(r.version.as_deref(), Some("0.1.0"));
        assert_eq!(r.profile_expires, Some(1_800_000_000));
        assert_eq!(r.certificate_sha256, None);
        assert_eq!(r.source, Source::SelfApp);
        assert_eq!(r.bundles.len(), 1);
    }

    #[test]
    fn merge_keeps_later_expiry() {
        let dir = temp_dir("self-merge");
        let derived = derive(&write_self_bundle(&dir, 100.0)).unwrap();
        let mut reg = Registry::default();
        let mut stored = derived.clone();
        stored.profile_expires = Some(500);
        stored.refreshed_at = Some(400);
        reg.upsert(stored);
        let m = merged(derived.clone(), &reg);
        assert_eq!(m.profile_expires, Some(500));
        assert_eq!(m.refreshed_at, Some(400));
        assert_eq!(
            merged(derived, &Registry::default()).profile_expires,
            Some(100)
        );
    }
}
