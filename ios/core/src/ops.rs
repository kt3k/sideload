//! The operations of `ios/SPEC.md` Section 7: install, refresh, forget, list.

use std::collections::BTreeMap;
use std::path::Path;

use sideload::apple::Https;
use sideload::apple::developer::Developer;
use sideload::bundle::{self, AppBundle};
use sideload::commands::{cert_identity, deliver, install as cli};
use sideload::pipeline::Phase;
use sideload::pipeline::workdir::WorkDir;
use sideload::sign::{self, SigningIdentity};
use sideload::{ErrorCode, output};

use crate::account::{self, LoggedIn, TwoFactor};
use crate::config::{Account, Config};
use crate::device::{self, DeviceInfo, Link};
use crate::error::{At, CResult, CoreError, invalid, phase};
use crate::profile::{self, ProfileInfo, certificate_sha256};
use crate::registry::{self, BundleEntry, Record, Registry, Source};
use crate::selfapp;

/// A result plus the session a login created on the way, which the caller
/// must store even when the operation failed later (Section 7.2 step 5).
pub struct Outcome<T> {
    pub result: CResult<T>,
    pub session: Option<String>,
}

fn now() -> i64 {
    sideload::formats::date::now_unix()
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

// ---------------------------------------------------------------- list

/// Every record, `self` first, then by name (Section 7.6).
pub fn all_records(cfg: &Config, reg: &Registry) -> Vec<Record> {
    let mut out = Vec::new();
    if let Some(path) = &cfg.self_bundle {
        match selfapp::derive(path) {
            Ok(derived) => out.push(selfapp::merged(derived, reg)),
            Err(e) => output::warn(format!("cannot read the app's own bundle: {e}")),
        }
    }
    let mut others: Vec<Record> = reg
        .apps
        .iter()
        .filter(|r| r.source == Source::Ipa)
        .filter(|r| out.iter().all(|s| s.bundle_id != r.bundle_id))
        .cloned()
        .collect();
    others.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.bundle_id.cmp(&b.bundle_id))
    });
    out.extend(others);
    out
}

pub fn list(cfg: &Config) -> CResult<Vec<Record>> {
    Ok(all_records(cfg, &Registry::load(&cfg.data_dir)?))
}

// ---------------------------------------------------------------- forget

/// Section 7.5.
pub fn forget(cfg: &Config, bundle_id: &str) -> CResult<()> {
    let mut reg = Registry::load(&cfg.data_dir)?;
    let is_self = all_records(cfg, &reg)
        .iter()
        .any(|r| r.bundle_id == bundle_id && r.source == Source::SelfApp);
    if is_self {
        return Err(invalid("the app itself cannot be forgotten"));
    }
    match reg.remove(bundle_id) {
        Some(r) if r.source == Source::Ipa => {}
        _ => return Err(invalid(format!("no managed app `{bundle_id}`"))),
    }
    reg.save(&cfg.data_dir)?;
    let dir = registry::app_dir(&cfg.data_dir, bundle_id);
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            output::warn(format!("cannot remove `{}`: {e}", dir.display()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- shared steps

/// Extracts and loads the bundle; returns it and its original identifier.
fn prepare_bundle(ipa: &Path, workdir: &Path) -> CResult<(AppBundle, String)> {
    let p = Phase::PreparingBundle.as_str();
    let app_dir = bundle::ipa::extract(ipa, workdir).at(p)?;
    let app = AppBundle::load(&app_dir).at(p)?;
    bundle::validate_bundle_ids(&app).at(p)?;
    let original = app.bundle_identifier().at(p)?.to_owned();
    Ok((app, original))
}

/// `(bundle_id, name)` of the main bundle and every extension.
fn needed_of(app: &AppBundle) -> CResult<Vec<(String, String)>> {
    Ok(app
        .all_bundles_inner_first()
        .iter()
        .map(|b| Ok((b.bundle_identifier()?.to_owned(), b.bundle_name())))
        .collect::<sideload::Result<_>>()?)
}

/// CLI 7.4: refuse before registering anything if the quota is too small.
fn check_quota(
    dev: &mut Developer<Https>,
    team_id: &str,
    needed: &[(String, String)],
) -> CResult<()> {
    let listed = dev.list_app_ids(team_id)?;
    let to_register = needed
        .iter()
        .filter(|(id, _)| !listed.app_ids.iter().any(|a| &a.identifier == id))
        .count();
    if let Some(available) = listed.available_quantity {
        let available = available.max(0) as usize;
        if to_register > available {
            let when = listed
                .app_ids
                .iter()
                .filter_map(|a| a.expiration_date)
                .reduce(f64::min)
                .map(|s| sideload::formats::date::format_iso8601(s as i64))
                .unwrap_or_else(|| "unknown".to_owned());
            return Err(CoreError::new(
                ErrorCode::AppIdQuotaExceeded,
                format!(
                    "need {to_register} App IDs but only {available} available; the soonest frees up on {when}"
                ),
            ));
        }
    }
    Ok(())
}

/// CLI 10.2: register the device if its UDID is not registered.
fn ensure_device(
    dev: &mut Developer<Https>,
    team_id: &str,
    info: &DeviceInfo,
) -> sideload::Result<()> {
    let registered = dev.list_devices(team_id)?;
    if !registered
        .iter()
        .any(|d| d.udid.eq_ignore_ascii_case(&info.udid))
    {
        let name = if info.name.is_empty() {
            &info.udid
        } else {
            &info.name
        };
        output::info(format!("Registering this device ({name})..."));
        dev.add_device(team_id, name, &info.udid)?;
    }
    Ok(())
}

/// `RegisteringAppIds`, `ConfiguringAppGroup`, `FetchingProfiles`, exactly
/// as the CLI does them. Returns bundle identifier -> profile.
fn provision(
    dev: &mut Developer<Https>,
    team_id: &str,
    needed: &[(String, String)],
    main_id: &str,
) -> CResult<BTreeMap<String, Vec<u8>>> {
    output::phase(Phase::RegisteringAppIds);
    let (app_ids, main_name) = cli::register_app_ids(dev, team_id, needed, main_id)
        .at(Phase::RegisteringAppIds.as_str())?;
    output::phase(Phase::ConfiguringAppGroup);
    let group_id = bundle::app_group_id(main_id);
    cli::configure_app_group(dev, team_id, needed, &app_ids, &group_id, &main_name)
        .at(Phase::ConfiguringAppGroup.as_str())?;
    output::phase(Phase::FetchingProfiles);
    cli::fetch_profiles(dev, team_id, needed, &app_ids).at(Phase::FetchingProfiles.as_str())
}

fn parse_profiles(profiles: &BTreeMap<String, Vec<u8>>) -> CResult<Vec<ProfileInfo>> {
    profiles.values().map(|p| ProfileInfo::parse(p)).collect()
}

/// Provision, sign and deliver `app` (already rewritten to `main_id`).
fn sign_and_deliver(
    dev: &mut Developer<Https>,
    team_id: &str,
    app: &mut AppBundle,
    main_id: &str,
    original: &str,
    identity: &SigningIdentity,
    link: &Link,
) -> CResult<Vec<ProfileInfo>> {
    let needed = needed_of(app)?;
    let profiles = provision(dev, team_id, &needed, main_id)?;
    bundle::apply_sidestore_tweaks(app, original, &bundle::app_group_id(main_id));

    let p = Phase::Signing.as_str();
    output::phase(Phase::Signing);
    bundle::save_all(app).at(p)?;
    sign::sign_bundle(app, identity, &profiles, threads()).at(p)?;

    let p = Phase::Delivering.as_str();
    output::phase(Phase::Delivering);
    let values: Vec<Vec<u8>> = profiles.values().cloned().collect();
    deliver::deliver_with(
        &link.conn,
        &link.pairing,
        &app.path,
        &values,
        |pct, status| output::info(format!("Installing: {pct}% ({status})")),
    )
    .at(p)?;
    parse_profiles(&profiles)
}

/// The record of a freshly signed app.
fn record_for(
    app: &AppBundle,
    original: &str,
    team_id: &str,
    identity: &SigningIdentity,
    profiles: &[ProfileInfo],
    installed_at: Option<i64>,
) -> CResult<Record> {
    let mut bundles = app.all_bundles_inner_first();
    bundles.rotate_right(1); // main bundle first
    Ok(Record {
        bundle_id: app.bundle_identifier()?.to_owned(),
        original_bundle_id: original.to_owned(),
        name: selfapp::display_name(app),
        version: app
            .info
            .get("CFBundleShortVersionString")
            .and_then(sideload::formats::plist::Value::as_str)
            .map(str::to_owned),
        team_id: team_id.to_owned(),
        bundles: bundles
            .iter()
            .map(|b| {
                Ok(BundleEntry {
                    bundle_id: b.bundle_identifier()?.to_owned(),
                    name: b.bundle_name(),
                })
            })
            .collect::<sideload::Result<_>>()?,
        certificate_sha256: identity.certificates.first().map(|c| certificate_sha256(c)),
        profile_expires: profile::earliest_expiry(profiles),
        installed_at,
        refreshed_at: None,
        source: Source::Ipa,
    })
}

/// Copies `src` to `dst` through a temporary file (no-op if they are the
/// same file).
fn copy_atomic(src: &Path, dst: &Path) -> CResult<()> {
    let fail = |e: std::io::Error| {
        crate::error::internal(format!(
            "cannot copy `{}` to `{}`: {e}",
            src.display(),
            dst.display()
        ))
    };
    if let (Ok(a), Ok(b)) = (src.canonicalize(), dst.canonicalize()) {
        if a == b {
            return Ok(());
        }
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    let mut tmp = dst.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::copy(src, &tmp).map_err(fail)?;
    std::fs::rename(&tmp, dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

// ---------------------------------------------------------------- install

/// Section 7.3.
pub fn install(
    cfg: &Config,
    account: &Account,
    ipa: &Path,
    two_factor: TwoFactor<'_>,
) -> Outcome<Record> {
    let mut session = None;
    let result = install_inner(cfg, account, ipa, two_factor, &mut session);
    Outcome { result, session }
}

fn install_inner(
    cfg: &Config,
    account: &Account,
    ipa: &Path,
    two_factor: TwoFactor<'_>,
    session: &mut Option<String>,
) -> CResult<Record> {
    output::phase(Phase::PreparingBundle);
    let workdir = WorkDir::create(false).at(Phase::PreparingBundle.as_str())?;
    let (mut app, original) = prepare_bundle(ipa, workdir.path())?;

    output::named_phase(phase::CONNECTING_DEVICE);
    let link = device::connect(cfg).at(phase::CONNECTING_DEVICE)?;

    let mut login = account::log_in(cfg, account, two_factor)?;
    *session = login.new_session.clone();
    let team_id = login.team.team_id.clone();

    let p = Phase::Planning.as_str();
    output::phase(Phase::Planning);
    let main_id = bundle::main_bundle_id(&original, &team_id, None);
    bundle::rewrite_bundle_ids(&mut app, &main_id).at(p)?;
    check_quota(&mut login.dev, &team_id, &needed_of(&app)?).at(p)?;

    output::phase(Phase::RegisteringDevice);
    ensure_device(&mut login.dev, &team_id, &link.info).at(Phase::RegisteringDevice.as_str())?;

    let identity = prepare_identity(cfg, &mut login)?;
    let profiles = sign_and_deliver(
        &mut login.dev,
        &team_id,
        &mut app,
        &main_id,
        &original,
        &identity,
        &link,
    )?;

    let p = Phase::CleaningUp.as_str();
    output::phase(Phase::CleaningUp);
    copy_atomic(ipa, &registry::ipa_path(&cfg.data_dir, &main_id)).at(p)?;
    let record = record_for(&app, &original, &team_id, &identity, &profiles, Some(now())).at(p)?;
    let mut reg = Registry::load(&cfg.data_dir).at(p)?;
    reg.upsert(record.clone());
    reg.save(&cfg.data_dir).at(p)?;
    output::info(format!("Installed {}.", record.name));
    Ok(record)
}

/// CLI 7.3 without `--new-cert`: never revokes.
fn prepare_identity(cfg: &Config, login: &mut LoggedIn) -> CResult<SigningIdentity> {
    output::phase(Phase::PreparingCertificate);
    cert_identity::prepare(
        &mut login.dev,
        &login.team.team_id,
        &cfg.data_dir,
        &login.apple_id,
        false,
    )
    .at(Phase::PreparingCertificate.as_str())
}

// ---------------------------------------------------------------- refresh

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Profiles,
    Resign,
    Skipped,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Profiles => "profiles",
            Action::Resign => "resign",
            Action::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppResult {
    pub bundle_id: String,
    pub name: String,
    /// `None` when the app failed before an action was chosen.
    pub action: Option<Action>,
    pub error: Option<CoreError>,
}

pub struct RefreshOutcome {
    pub apps: Vec<AppResult>,
    /// The first failure, if any (Section 7.4 step 5).
    pub error: Option<CoreError>,
    pub session: Option<String>,
}

/// Which records a refresh selects, and which of those are due
/// (Section 7.4 input).
pub fn select<'a>(
    records: &'a [Record],
    bundle_ids: Option<&[String]>,
    within: Option<i64>,
    now: i64,
) -> CResult<(Vec<&'a Record>, Vec<&'a Record>)> {
    if let Some(ids) = bundle_ids {
        if let Some(missing) = ids
            .iter()
            .find(|id| !records.iter().any(|r| &r.bundle_id == *id))
        {
            return Err(invalid(format!("no managed app `{missing}`")));
        }
    }
    let selected = records
        .iter()
        .filter(|r| bundle_ids.is_none_or(|ids| ids.contains(&r.bundle_id)));
    let (due, skipped): (Vec<_>, Vec<_>) = selected.partition(|r| match within {
        None => true,
        Some(w) => r.profile_expires.is_none_or(|e| e < now.saturating_add(w)),
    });
    Ok((due, skipped))
}

/// Section 7.4.
pub fn refresh(
    cfg: &Config,
    account: &Account,
    bundle_ids: Option<&[String]>,
    within: Option<i64>,
    two_factor: TwoFactor<'_>,
) -> RefreshOutcome {
    let mut out = RefreshOutcome {
        apps: Vec::new(),
        error: None,
        session: None,
    };
    if let Err(e) = refresh_inner(cfg, account, bundle_ids, within, two_factor, &mut out) {
        out.error = Some(e);
    }
    if out.error.is_none() {
        out.error = out.apps.iter().find_map(|a| a.error.clone());
    }
    out
}

fn refresh_inner(
    cfg: &Config,
    account: &Account,
    bundle_ids: Option<&[String]>,
    within: Option<i64>,
    two_factor: TwoFactor<'_>,
    out: &mut RefreshOutcome,
) -> CResult<()> {
    let mut reg = Registry::load(&cfg.data_dir)?;
    let records = all_records(cfg, &reg);
    let (due, skipped) = select(&records, bundle_ids, within, now())?;
    for r in &skipped {
        out.apps.push(AppResult {
            bundle_id: r.bundle_id.clone(),
            name: r.name.clone(),
            action: Some(Action::Skipped),
            error: None,
        });
    }
    if due.is_empty() {
        output::info("Nothing needs a refresh.");
        return Ok(());
    }

    // Steps 1-3 stop the whole run; report the failure on every due app.
    let fail_all = |out: &mut RefreshOutcome, e: &CoreError| {
        for r in &due {
            out.apps.push(AppResult {
                bundle_id: r.bundle_id.clone(),
                name: r.name.clone(),
                action: None,
                error: Some(e.clone()),
            });
        }
    };
    let setup = (|| -> CResult<(Link, LoggedIn)> {
        output::named_phase(phase::CONNECTING_DEVICE);
        let link = device::connect(cfg).at(phase::CONNECTING_DEVICE)?;
        let mut login = account::log_in(cfg, account, &mut *two_factor)?;
        out.session = login.new_session.clone();
        output::phase(Phase::RegisteringDevice);
        ensure_device(&mut login.dev, &login.team.team_id, &link.info)
            .at(Phase::RegisteringDevice.as_str())?;
        Ok((link, login))
    })();
    let (link, mut login) = match setup {
        Ok(v) => v,
        Err(e) => {
            fail_all(out, &e);
            return Err(e);
        }
    };

    let mut identity = None;
    for record in due {
        output::named_phase(phase::REFRESHING_APP);
        output::info(format!("Refreshing {}...", record.name));
        let result =
            refresh_one(cfg, &mut login, &link, record, &mut identity).at(phase::REFRESHING_APP);
        let (action, error) = match result {
            Ok((action, updated)) => {
                reg.upsert(updated);
                match reg.save(&cfg.data_dir) {
                    Ok(()) => (Some(action), None),
                    Err(e) => (Some(action), Some(e)),
                }
            }
            Err(e) => {
                output::warn(format!("{}: {e}", record.name));
                (None, Some(e))
            }
        };
        out.apps.push(AppResult {
            bundle_id: record.bundle_id.clone(),
            name: record.name.clone(),
            action,
            error,
        });
    }
    Ok(())
}

fn refresh_one(
    cfg: &Config,
    login: &mut LoggedIn,
    link: &Link,
    record: &Record,
    identity: &mut Option<SigningIdentity>,
) -> CResult<(Action, Record)> {
    let team_id = login.team.team_id.clone();
    if record.team_id != team_id {
        return Err(CoreError::new(
            ErrorCode::TeamNotFound,
            format!(
                "{} was signed for team {}, but the selected team is {team_id}",
                record.name, record.team_id
            ),
        ));
    }
    let profiles = provision(
        &mut login.dev,
        &team_id,
        &record.needed(),
        &record.bundle_id,
    )?;
    let infos = parse_profiles(&profiles)?;

    if profile::authorizes(&infos, record.certificate_sha256.as_deref()) {
        output::named_phase(phase::INSTALLING_PROFILES);
        let values: Vec<Vec<u8>> = profiles.into_values().collect();
        deliver::install_profiles(&link.conn, &link.pairing, &values)
            .at(phase::INSTALLING_PROFILES)?;
        let mut updated = record.clone();
        updated.profile_expires = profile::earliest_expiry(&infos);
        updated.refreshed_at = Some(now());
        return Ok((Action::Profiles, updated));
    }

    // The profiles do not cover the app's certificate: re-sign.
    let ipa = registry::ipa_path(&cfg.data_dir, &record.bundle_id);
    if record.source != Source::Ipa {
        return Err(CoreError::new(
            ErrorCode::SigningFailed,
            "the profiles do not cover this app's certificate; reinstall it from a computer",
        ));
    }
    if !ipa.is_file() {
        return Err(CoreError::new(
            ErrorCode::SigningFailed,
            "the profiles do not cover this app's certificate and its original IPA is missing; install it again",
        ));
    }
    output::info("The new profiles do not cover the app's certificate; re-signing.");
    if identity.is_none() {
        *identity = Some(prepare_identity(cfg, login)?);
    }
    let identity = identity.as_ref().expect("prepared above");
    output::phase(Phase::PreparingBundle);
    let workdir = WorkDir::create(false).at(Phase::PreparingBundle.as_str())?;
    let (mut app, original) = prepare_bundle(&ipa, workdir.path())?;
    bundle::rewrite_bundle_ids(&mut app, &record.bundle_id).at(Phase::Planning.as_str())?;
    let infos = sign_and_deliver(
        &mut login.dev,
        &team_id,
        &mut app,
        &record.bundle_id,
        &original,
        identity,
        link,
    )?;
    let mut updated = record_for(
        &app,
        &original,
        &team_id,
        identity,
        &infos,
        record.installed_at,
    )?;
    updated.refreshed_at = Some(now());
    Ok((Action::Resign, updated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{record, temp_dir};
    use crate::selfapp::tests::write_self_bundle;

    fn cfg(dir: &Path, self_bundle: Option<std::path::PathBuf>) -> Config {
        Config {
            data_dir: dir.to_path_buf(),
            anisette_server: None,
            anisette_mode: None,
            device_host: "127.0.0.1".into(),
            self_bundle,
        }
    }

    #[test]
    fn list_orders_self_first_then_name() {
        let dir = temp_dir("list");
        let app = write_self_bundle(&dir, 100.0);
        let mut reg = Registry::default();
        reg.upsert(record("z.T", "beta"));
        reg.upsert(record("a.T", "Alpha"));
        reg.save(&dir).unwrap();
        let names: Vec<String> = list(&cfg(&dir, Some(app)))
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(names, ["Sideload", "Alpha", "beta"]);
        assert_eq!(list(&cfg(&dir, None)).unwrap().len(), 2);
    }

    #[test]
    fn forget_rules() {
        let dir = temp_dir("forget");
        let app = write_self_bundle(&dir, 100.0);
        let c = cfg(&dir, Some(app));
        let mut reg = Registry::default();
        reg.upsert(record("a.T", "A"));
        reg.save(&dir).unwrap();
        let ipa = registry::ipa_path(&dir, "a.T");
        std::fs::create_dir_all(ipa.parent().unwrap()).unwrap();
        std::fs::write(&ipa, b"ipa").unwrap();

        assert_eq!(
            forget(&c, "io.github.kt3k.sideload.TEAM1")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArguments
        );
        assert_eq!(
            forget(&c, "nope").unwrap_err().code,
            ErrorCode::InvalidArguments
        );
        forget(&c, "a.T").unwrap();
        assert!(!ipa.exists());
        assert!(Registry::load(&dir).unwrap().apps.is_empty());
    }

    #[test]
    fn selection() {
        let mut soon = record("soon", "S");
        soon.profile_expires = Some(1_000 + 3_600);
        let mut later = record("later", "L");
        later.profile_expires = Some(1_000 + 10 * 86_400);
        let mut unknown = record("unknown", "U");
        unknown.profile_expires = None;
        let records = vec![soon, later, unknown];
        let ids = |v: Vec<&Record>| {
            v.into_iter()
                .map(|r| r.bundle_id.clone())
                .collect::<Vec<_>>()
        };

        let (due, skipped) = select(&records, None, None, 1_000).unwrap();
        assert_eq!(ids(due), ["soon", "later", "unknown"]);
        assert!(skipped.is_empty());

        let (due, skipped) = select(&records, None, Some(2 * 86_400), 1_000).unwrap();
        assert_eq!(ids(due), ["soon", "unknown"]);
        assert_eq!(ids(skipped), ["later"]);

        let only = ["later".to_owned()];
        let (due, _) = select(&records, Some(&only), None, 1_000).unwrap();
        assert_eq!(ids(due), ["later"]);

        let bad = ["missing".to_owned()];
        assert_eq!(
            select(&records, Some(&bad), None, 0).unwrap_err().code,
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn refresh_with_nothing_due_does_not_connect() {
        let dir = temp_dir("refresh-nothing");
        let mut r = record("a.T", "A");
        r.profile_expires = Some(now() + 30 * 86_400);
        let mut reg = Registry::default();
        reg.upsert(r);
        reg.save(&dir).unwrap();
        let mut never = || -> Option<String> { panic!("must not ask") };
        let out = refresh(
            &cfg(&dir, None),
            &Account::default(),
            None,
            Some(2 * 86_400),
            &mut never,
        );
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(out.apps.len(), 1);
        assert_eq!(out.apps[0].action, Some(Action::Skipped));
    }

    #[test]
    fn refresh_stops_without_pairing_and_reports_every_app() {
        let dir = temp_dir("refresh-nopair");
        let mut reg = Registry::default();
        reg.upsert(record("a.T", "A"));
        reg.upsert(record("b.T", "B"));
        reg.save(&dir).unwrap();
        let mut never = || -> Option<String> { panic!("must not ask") };
        let out = refresh(
            &cfg(&dir, None),
            &Account::default(),
            None,
            None,
            &mut never,
        );
        let err = out.error.unwrap();
        assert_eq!(err.code, ErrorCode::DeviceNotPaired);
        assert_eq!(err.phase.as_deref(), Some(phase::CONNECTING_DEVICE));
        assert_eq!(out.apps.len(), 2);
        assert!(
            out.apps
                .iter()
                .all(|a| a.error.is_some() && a.action.is_none())
        );
    }

    #[test]
    fn install_rejects_bad_ipa_before_connecting() {
        let dir = temp_dir("install-bad");
        let ipa = dir.join("bad.ipa");
        std::fs::write(&ipa, b"not a zip").unwrap();
        let mut never = || -> Option<String> { panic!("must not ask") };
        let out = install(&cfg(&dir, None), &Account::default(), &ipa, &mut never);
        let err = out.result.unwrap_err();
        assert_eq!(err.phase.as_deref(), Some("PreparingBundle"));
        assert!(out.session.is_none());
    }

    #[test]
    fn copy_is_atomic_and_idempotent() {
        let dir = temp_dir("copy");
        let src = dir.join("a.ipa");
        std::fs::write(&src, b"x").unwrap();
        let dst = dir.join("apps/b/app.ipa");
        copy_atomic(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"x");
        copy_atomic(&dst, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"x");
    }
}
