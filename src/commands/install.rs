//! `install` (SPEC Section 7, reference algorithm in Section 15.1).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use crate::apple::Transport;
use crate::apple::developer::{self, Developer};
use crate::bundle::{self, AppBundle};
use crate::cli::InstallArgs;
use crate::commands::{cert_identity, deliver, session};
use crate::config::Settings;
use crate::device::usbmuxd::Usbmuxd;
use crate::pipeline::plan::{
    CertificateAction, DeviceAction, InstallPlan, PlannedAppGroup, PlannedAppId,
};
use crate::pipeline::workdir::WorkDir;
use crate::pipeline::{Mode, Phase};
use crate::{Error, ErrorCode, Result, output, sidestore};

pub fn mode(args: &InstallArgs) -> Mode {
    if args.dry_run {
        Mode::DryRun
    } else if args.output.is_some() {
        Mode::Output
    } else {
        Mode::Install
    }
}

/// The device `install` will act on.
struct Target {
    udid: String,
    /// `None` when the device is not connected (allowed only for Output/DryRun).
    device_id: Option<u32>,
}

fn phase<T>(r: Result<T>, p: Phase) -> Result<T> {
    r.map_err(|e| {
        if e.phase.is_none() {
            e.with_phase(p)
        } else {
            e
        }
    })
}

/// SPEC Section 10.1.
fn select_device(udid: Option<&str>, mode: Mode) -> Result<Option<Target>> {
    let connected = match Usbmuxd::connect().and_then(|mut m| m.list_devices()) {
        Ok(d) => d,
        // Install mode needs usbmuxd; report it as unreachable rather than
        // as "no device". Other modes can continue without a device.
        Err(e) if mode == Mode::Install => return Err(e),
        Err(e) => {
            output::warn(format!("could not list connected devices: {e}"));
            Vec::new()
        }
    };
    let no_device = |code: ErrorCode, msg: &str| Err(Error::new(code, msg.to_owned()));
    match udid {
        Some(want) => match connected.iter().find(|d| d.udid == want) {
            Some(d) => Ok(Some(Target {
                udid: want.to_owned(),
                device_id: Some(d.device_id),
            })),
            None if mode == Mode::Install => no_device(
                ErrorCode::DeviceNotConnected,
                "the requested device is not connected",
            ),
            None => Ok(Some(Target {
                udid: want.to_owned(),
                device_id: None,
            })),
        },
        None => match connected.len() {
            1 => Ok(Some(Target {
                udid: connected[0].udid.clone(),
                device_id: Some(connected[0].device_id),
            })),
            0 if mode == Mode::Install => {
                no_device(ErrorCode::NoDeviceConnected, "no device connected")
            }
            0 => {
                output::warn(
                    "no device connected; the profile will cover already-registered devices only",
                );
                Ok(None)
            }
            _ => no_device(
                ErrorCode::MultipleDevicesConnected,
                "multiple devices are connected; select one with --udid",
            ),
        },
    }
}

pub fn run(args: &InstallArgs, settings: &Settings) -> Result<ExitCode> {
    output::phase(Phase::ValidatingArguments);
    validate_arguments(args).map_err(|e| e.with_phase(Phase::ValidatingArguments))?;
    let mode = mode(args);
    let workdir = WorkDir::create(args.keep_temp)?;

    output::phase(Phase::SelectingDevice);
    let target = phase(
        select_device(args.udid.as_deref(), mode),
        Phase::SelectingDevice,
    )?;

    // Obtain the IPA (download for --sidestore, otherwise the argument).
    let ipa = if args.sidestore {
        output::phase(Phase::DownloadingApp);
        let client = sidestore::http_client().map_err(|e| e.with_phase(Phase::DownloadingApp))?;
        sidestore::download_latest(&client, workdir.path())
            .map_err(|e| e.with_phase(Phase::DownloadingApp))?
            .0
    } else {
        args.ipa.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArguments,
                "missing argument <ipa> (or use --sidestore)",
            )
            .with_phase(Phase::ValidatingArguments)
        })?
    };

    // Extract and adjust the bundle (SPEC Section 11.1). Everything that can
    // be checked locally is checked here, before credentials (SPEC 7.2).
    output::phase(Phase::PreparingBundle);
    let app_dir = phase(
        bundle::ipa::extract(&ipa, workdir.path()),
        Phase::PreparingBundle,
    )?;
    let mut app = phase(AppBundle::load(&app_dir), Phase::PreparingBundle)?;
    if args.strip_extensions {
        phase(app.strip_extensions(), Phase::PreparingBundle)?;
    }
    if let Some(name) = &args.name {
        app.set_display_name(name);
    }
    phase(bundle::validate_bundle_ids(&app), Phase::PreparingBundle)?;
    let original_main_id = phase(
        app.bundle_identifier().map(str::to_owned),
        Phase::PreparingBundle,
    )?;

    // PreparingAnisette + LoggingIn, then pick the team.
    let auth = session::authenticate(settings, true)?;
    let mut dev = auth.dev;
    output::phase(Phase::SelectingTeam);
    let team = phase(
        session::select_team(&mut dev, args.team.as_deref()),
        Phase::SelectingTeam,
    )?;

    // Rewrite identifiers and build the plan (SPEC Sections 7.4, 15.2).
    output::phase(Phase::Planning);
    let main_id =
        bundle::main_bundle_id(&original_main_id, &team.team_id, args.bundle_id.as_deref());
    phase(
        bundle::rewrite_bundle_ids(&mut app, &main_id),
        Phase::Planning,
    )?;
    let plan = phase(
        build_plan(
            &mut dev,
            &team,
            target.as_ref(),
            &app,
            &main_id,
            settings,
            &auth.apple_id,
            args.new_cert,
        ),
        Phase::Planning,
    )?;

    if mode == Mode::DryRun {
        print_plan(&plan);
        return Ok(if plan.feasible() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    if let Some((code, message)) = plan.blocker {
        return Err(Error::new(code, message).with_phase(Phase::Planning));
    }

    // RegisteringDevice (SPEC Section 10.2).
    output::phase(Phase::RegisteringDevice);
    if let (Some(t), DeviceAction::Register) = (&target, &plan.device_action) {
        let name = device_name(t);
        phase(
            dev.add_device(&team.team_id, &name, &t.udid).map(|_| ()),
            Phase::RegisteringDevice,
        )?;
    }

    // PreparingCertificate (SPEC Section 7.3).
    output::phase(Phase::PreparingCertificate);
    let identity = phase(
        cert_identity::prepare(
            &mut dev,
            &team.team_id,
            &settings.config_dir,
            &auth.apple_id,
            args.new_cert,
        ),
        Phase::PreparingCertificate,
    )?;

    // RegisteringAppIds, ConfiguringAppGroup and FetchingProfiles (each
    // announced and tagged inside).
    let profiles = provision_app_ids(
        &mut dev,
        &team.team_id,
        &mut app,
        &main_id,
        &original_main_id,
    )?;

    // Persist Info.plist edits before signing (SPEC Section 11.1).
    output::phase(Phase::Signing);
    phase(bundle::save_all(&app), Phase::Signing)?;
    let profile_map: BTreeMap<String, Vec<u8>> = profiles.clone();
    phase(
        crate::sign::sign_bundle(&app, &identity, &profile_map, settings.thread_count.get()),
        Phase::Signing,
    )?;

    output::phase(Phase::Delivering);
    match mode {
        Mode::Output => {
            let out = args.output.as_ref().expect("Output mode has --output");
            phase(bundle::ipa::repack(workdir.path(), out), Phase::Delivering)?;
            output::info(format!("Wrote signed IPA to {}", out.display()));
        }
        Mode::Install => {
            let t = target
                .as_ref()
                .expect("Install mode has a connected device");
            let device_id = t.device_id.expect("Install mode device is connected");
            let profile_values: Vec<Vec<u8>> = profiles.into_values().collect();
            phase(
                deliver::deliver(device_id, &t.udid, &app.path, &profile_values, |p, s| {
                    output::info(format!("Installing: {p}% ({s})"));
                }),
                Phase::Delivering,
            )?;
        }
        Mode::DryRun => unreachable!("handled above"),
    }

    // CleaningUp: remove the working directory (or report it for
    // --keep-temp) before declaring success.
    output::phase(Phase::CleaningUp);
    drop(workdir);
    output::info("Done.");
    Ok(ExitCode::SUCCESS)
}

fn device_name(target: &Target) -> String {
    // Use the lockdown DeviceName when the device is connected; otherwise
    // fall back to the UDID.
    target
        .device_id
        .and_then(|device_id| {
            let socket = Usbmuxd::connect()
                .ok()?
                .connect_to_device(device_id, crate::device::lockdown::LOCKDOWND_PORT)
                .ok()?;
            crate::device::lockdown::LockdownClient::new(socket)
                .device_name()
                .ok()
        })
        .unwrap_or_else(|| target.udid.clone())
}

/// Builds the Install Plan without changing Apple-side state (SPEC 15.2).
#[allow(clippy::too_many_arguments)]
fn build_plan<T: Transport>(
    dev: &mut Developer<T>,
    team: &developer::Team,
    target: Option<&Target>,
    app: &AppBundle,
    main_id: &str,
    settings: &Settings,
    apple_id: &str,
    new_cert: bool,
) -> Result<InstallPlan> {
    let device_action = match target {
        None => DeviceAction::Skip,
        Some(t) => {
            let registered = dev.list_devices(&team.team_id)?;
            if registered.iter().any(|d| d.udid == t.udid) {
                DeviceAction::None
            } else {
                DeviceAction::Register
            }
        }
    };

    let listed = dev.list_app_ids(&team.team_id)?;
    let needed: Vec<String> = app
        .all_bundles_inner_first()
        .iter()
        .map(|b| b.bundle_identifier().map(str::to_owned))
        .collect::<Result<_>>()?;
    let app_ids: Vec<PlannedAppId> = needed
        .iter()
        .map(|id| PlannedAppId {
            identifier: id.clone(),
            exists: listed.app_ids.iter().any(|a| &a.identifier == id),
        })
        .collect();
    let to_register = app_ids.iter().filter(|a| !a.exists).count();
    // Paid teams omit availableQuantity: that means no App ID quota, as in
    // Sideloader (ulong.max) and isideload (only checked when present).
    let available = listed.available_quantity.map(|a| a.max(0) as u32);

    // Certificate action: inspect the local key and the account's certs.
    let key = cert_identity::read_key_if_present(&settings.config_dir, apple_id);
    let certs = dev.list_development_certs(&team.team_id)?;
    let sideloader: Vec<&developer::Certificate> = certs
        .iter()
        .filter(|c| c.machine_name.as_deref() == Some(cert_identity::MACHINE_NAME))
        .collect();
    let certificate_action = cert_identity::plan_action(&sideloader, key.as_ref(), new_cert);

    let group_id = bundle::app_group_id(main_id);
    let groups = dev.list_app_groups(&team.team_id)?;
    let app_group = PlannedAppGroup {
        exists: groups.iter().any(|g| g.identifier == group_id),
        identifier: group_id,
    };

    let blocker = if let Some(available) = available.filter(|&a| to_register as u32 > a) {
        let soonest = listed
            .app_ids
            .iter()
            .filter_map(|a| a.expiration_date)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let when = soonest
            .map(|s| crate::formats::date::format_iso8601(s as i64))
            .unwrap_or_else(|| "unknown".to_owned());
        Some((
            ErrorCode::AppIdQuotaExceeded,
            format!(
                "need {to_register} App IDs but only {available} available; the soonest frees up on {when}"
            ),
        ))
    } else {
        None
    };

    Ok(InstallPlan {
        team_id: team.team_id.clone(),
        team_name: team.name.clone().unwrap_or_default(),
        device_udid: target.map(|t| t.udid.clone()),
        device_action,
        certificate_action,
        app_ids,
        available_quantity: available,
        max_quantity: listed.max_quantity.map(|m| m as u32),
        app_group,
        blocker,
    })
}

/// Registers missing App IDs, enables and assigns the App Group, and
/// downloads each App ID's provisioning profile. Returns a map from bundle
/// identifier to profile bytes.
fn provision_app_ids<T: Transport>(
    dev: &mut Developer<T>,
    team_id: &str,
    app: &mut AppBundle,
    main_id: &str,
    original_main_id: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let needed: Vec<(String, String)> = app
        .all_bundles_inner_first()
        .iter()
        .map(|b| Ok((b.bundle_identifier()?.to_owned(), b.bundle_name())))
        .collect::<Result<_>>()?;

    output::phase(Phase::RegisteringAppIds);
    let (app_ids, main_name) = phase(
        register_app_ids(dev, team_id, &needed, main_id),
        Phase::RegisteringAppIds,
    )?;

    output::phase(Phase::ConfiguringAppGroup);
    let group_id = bundle::app_group_id(main_id);
    phase(
        configure_app_group(dev, team_id, &needed, &app_ids, &group_id, &main_name),
        Phase::ConfiguringAppGroup,
    )?;

    // SideStore reads its app group from ALTAppGroups (SPEC Section 11.1).
    bundle::apply_sidestore_tweaks(app, original_main_id, &group_id);

    output::phase(Phase::FetchingProfiles);
    phase(
        fetch_profiles(dev, team_id, &needed, &app_ids),
        Phase::FetchingProfiles,
    )
}

/// Registers the missing App IDs, then re-lists them to get each one's
/// `appIdId` and features. Also returns the main App ID's name.
fn register_app_ids<T: Transport>(
    dev: &mut Developer<T>,
    team_id: &str,
    needed: &[(String, String)],
    main_id: &str,
) -> Result<(Vec<developer::AppId>, String)> {
    let existing = dev.list_app_ids(team_id)?;
    let mut main_name = None;
    for (identifier, name) in needed {
        let app_id_name = bundle::app_id_name(name, identifier);
        if identifier == main_id {
            main_name = Some(app_id_name.clone());
        }
        if !existing.app_ids.iter().any(|a| &a.identifier == identifier) {
            output::info(format!("Registering App ID {identifier}..."));
            dev.add_app_id(team_id, identifier, &app_id_name)?;
        }
    }
    let app_ids = dev.list_app_ids(team_id)?.app_ids;
    for (identifier, _) in needed {
        if !app_ids.iter().any(|a| &a.identifier == identifier) {
            return Err(Error::new(
                ErrorCode::AppleApiError,
                format!("App ID {identifier} missing after registration"),
            ));
        }
    }
    let main_name = main_name.unwrap_or_else(|| bundle::app_id_name("", main_id));
    Ok((app_ids, main_name))
}

fn find_app_id<'a>(app_ids: &'a [developer::AppId], identifier: &str) -> &'a developer::AppId {
    app_ids
        .iter()
        .find(|a| a.identifier == identifier)
        .expect("checked by register_app_ids")
}

/// Enables App Groups on every App ID, creates or reuses the App Group,
/// and assigns it to each App ID.
fn configure_app_group<T: Transport>(
    dev: &mut Developer<T>,
    team_id: &str,
    needed: &[(String, String)],
    app_ids: &[developer::AppId],
    group_id: &str,
    main_app_id_name: &str,
) -> Result<()> {
    // Enable the App Group feature on each App ID.
    for (identifier, _) in needed {
        let app_id = find_app_id(app_ids, identifier);
        if app_id
            .features
            .get(developer::APP_GROUP_FEATURE)
            .and_then(crate::formats::plist::Value::as_bool)
            != Some(true)
        {
            let features = crate::formats::plist::Dictionary::from_iter([(
                developer::APP_GROUP_FEATURE,
                true,
            )]);
            dev.update_app_id(team_id, &app_id.app_id_id, features)?;
        }
    }

    // Create the App Group if needed, and assign it to each App ID. The
    // assignment takes the group's server-side ID (`applicationGroup`), not
    // its `group.<id>` identifier, as Sideloader and isideload do.
    let existing_group = dev
        .list_app_groups(team_id)?
        .into_iter()
        .find(|g| g.identifier == group_id);
    let group = match existing_group {
        Some(g) => g,
        None => {
            output::info(format!("Creating App Group {group_id}..."));
            let name = bundle::app_group_name(main_app_id_name);
            dev.add_app_group(team_id, group_id, &name)?
        }
    };
    for (identifier, _) in needed {
        let app_id = find_app_id(app_ids, identifier);
        dev.assign_app_group(team_id, &app_id.app_id_id, &group.application_group)?;
    }
    Ok(())
}

/// Downloads each App ID's own provisioning profile (SPEC Section 7; a fix
/// over upstream, which reused the main profile everywhere).
fn fetch_profiles<T: Transport>(
    dev: &mut Developer<T>,
    team_id: &str,
    needed: &[(String, String)],
    app_ids: &[developer::AppId],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut profiles = BTreeMap::new();
    for (identifier, _) in needed {
        let app_id = find_app_id(app_ids, identifier);
        output::debug(format!("fetching profile for {identifier}"));
        let profile = dev.download_team_provisioning_profile(team_id, &app_id.app_id_id)?;
        profiles.insert(identifier.clone(), profile.encoded_profile);
    }
    Ok(profiles)
}

fn quota(q: Option<u32>) -> String {
    q.map_or_else(|| "unlimited".to_owned(), |q| q.to_string())
}

fn print_plan(plan: &InstallPlan) {
    let device = match (&plan.device_udid, &plan.device_action) {
        (Some(u), DeviceAction::Register) => format!("{u} (will be registered)"),
        (Some(u), _) => format!("{u} (registered)"),
        (None, _) => "skipped (no device)".to_owned(),
    };
    let cert = match &plan.certificate_action {
        CertificateAction::Reuse { serial } => format!("reuse {serial}"),
        CertificateAction::Create => "will create new".to_owned(),
        CertificateAction::RevokeAndCreate { serials } => {
            format!(
                "will revoke {} and create new",
                if serials.is_empty() {
                    "none".to_owned()
                } else {
                    serials.join(", ")
                }
            )
        }
    };
    let need = plan.app_ids.len();
    let registered = plan.app_ids.iter().filter(|a| a.exists).count();
    let to_register = plan.app_ids_to_register();
    println!("Team:         {} ({})", plan.team_name, plan.team_id);
    println!("Device:       {device}");
    println!("Certificate:  {cert}");
    println!(
        "App IDs:      need {need}, already registered {registered}, will register {to_register} (available: {} / max: {})",
        quota(plan.available_quantity),
        quota(plan.max_quantity)
    );
    for a in &plan.app_ids {
        println!(
            "  - {} ({})",
            a.identifier,
            if a.exists { "exists" } else { "new" }
        );
    }
    println!(
        "App Group:    {} ({})",
        plan.app_group.identifier,
        if plan.app_group.exists {
            "exists"
        } else {
            "new"
        }
    );
    match &plan.blocker {
        None => println!("Result:       OK"),
        Some((code, message)) => println!("Result:       NG: {code} {message}"),
    }
}

/// SPEC Section 5.6 (the parts specific to `install`; `--output`/`--dry-run`
/// exclusivity and `--thread-count` are checked by the parser, the anisette
/// URL by `Settings::resolve`).
pub fn validate_arguments(args: &InstallArgs) -> Result<()> {
    if let Some(ipa) = &args.ipa {
        validate_ipa_path(ipa)?;
    }
    if let Some(output) = &args.output {
        let parent = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if !parent.is_dir() {
            return Err(Error::new(
                ErrorCode::OutputWriteFailed,
                format!("output directory `{}` does not exist", parent.display()),
            ));
        }
    }
    if let Some(id) = &args.bundle_id {
        validate_bundle_id(id)?;
    }
    Ok(())
}

pub fn validate_ipa_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(Error::new(
            ErrorCode::IpaNotFound,
            format!("`{}` does not exist", path.display()),
        ));
    }
    if !path.is_file() {
        return Err(Error::new(
            ErrorCode::IpaInvalid,
            format!("`{}` is not a regular file", path.display()),
        ));
    }
    if path.extension().and_then(|e| e.to_str()) != Some("ipa") {
        return Err(Error::new(
            ErrorCode::IpaInvalid,
            format!("`{}` is not an .ipa file", path.display()),
        ));
    }
    Ok(())
}

pub fn validate_bundle_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArguments,
            format!("invalid bundle identifier `{id}` (allowed: A-Z a-z 0-9 . -)"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir =
                std::env::temp_dir().join(format!("sideload-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ipa_validation() {
        let dir = TempDir::new("ipa");
        let ipa = dir.0.join("a.ipa");
        std::fs::write(&ipa, b"").unwrap();
        let zip = dir.0.join("a.zip");
        std::fs::write(&zip, b"").unwrap();

        assert!(validate_ipa_path(&ipa).is_ok());
        assert_eq!(
            validate_ipa_path(&dir.0.join("missing.ipa"))
                .unwrap_err()
                .code,
            ErrorCode::IpaNotFound
        );
        assert_eq!(
            validate_ipa_path(&zip).unwrap_err().code,
            ErrorCode::IpaInvalid
        );
        assert_eq!(
            validate_ipa_path(&dir.0).unwrap_err().code,
            ErrorCode::IpaInvalid
        );
    }

    #[test]
    fn output_parent_must_exist() {
        let dir = TempDir::new("out");
        let ipa = dir.0.join("a.ipa");
        std::fs::write(&ipa, b"").unwrap();
        let mut args = InstallArgs {
            ipa: Some(ipa),
            ..Default::default()
        };

        args.output = Some(dir.0.join("signed.ipa"));
        assert!(validate_arguments(&args).is_ok());

        args.output = Some(dir.0.join("nope").join("signed.ipa"));
        assert_eq!(
            validate_arguments(&args).unwrap_err().code,
            ErrorCode::OutputWriteFailed
        );
    }

    #[test]
    fn bundle_id_validation() {
        assert!(validate_bundle_id("com.example.App-1").is_ok());
        for bad in ["", "com.example.app_1", "com.ex ample", "com.例"] {
            assert_eq!(
                validate_bundle_id(bad).unwrap_err().code,
                ErrorCode::InvalidArguments,
                "{bad}"
            );
        }
    }

    #[test]
    fn modes() {
        let mut a = InstallArgs::default();
        assert_eq!(mode(&a), Mode::Install);
        a.output = Some("x".into());
        assert_eq!(mode(&a), Mode::Output);
        a.output = None;
        a.dry_run = true;
        assert_eq!(mode(&a), Mode::DryRun);
    }

    // ---- build_plan / provision_app_ids against a scripted Developer API ----

    use crate::anisette::{AnisetteData, AnisetteProvider};
    use crate::apple::gsa::Session;
    use crate::formats::plist::{Dictionary, Value};
    use crate::net::NetResult;
    use crate::net::http::{Request, Response};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct NoAnisette;
    impl AnisetteProvider for NoAnisette {
        fn headers(&mut self) -> Result<AnisetteData> {
            Ok(AnisetteData::default())
        }
    }

    /// Replies per Developer Services action; records (action, request).
    #[derive(Default)]
    struct Script {
        replies: BTreeMap<&'static str, Dictionary>,
        calls: Vec<(String, Value)>,
    }
    struct Wire(Rc<RefCell<Script>>);
    impl Transport for Wire {
        fn send(&mut self, r: &Request) -> NetResult<Response> {
            let action = r
                .url
                .rsplit('/')
                .next()
                .unwrap()
                .split(".action")
                .next()
                .unwrap()
                .to_owned();
            let body = crate::formats::plist::from_bytes(&r.body).unwrap();
            let mut script = self.0.borrow_mut();
            script.calls.push((action.clone(), body));
            let mut reply = script
                .replies
                .get(action.as_str())
                .cloned()
                .unwrap_or_default();
            reply.insert("resultCode", 0i64);
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: Value::Dictionary(reply).to_xml(),
                url: r.url.clone(),
            })
        }
    }

    fn dict<const N: usize>(e: [(&str, Value); N]) -> Dictionary {
        e.into_iter().collect()
    }

    fn developer(script: &Rc<RefCell<Script>>) -> Developer<Wire> {
        Developer::with_transport(
            Session {
                adsid: "1".into(),
                token: "T".into(),
                expiry: None,
            },
            Box::new(NoAnisette),
            Wire(script.clone()),
        )
    }

    fn sample_app(dir: &Path) -> AppBundle {
        let path = dir.join("Payload/A.app");
        std::fs::create_dir_all(&path).unwrap();
        let info = dict([
            ("CFBundleIdentifier", Value::from("com.example.a.TEAM")),
            ("CFBundleName", Value::from("A")),
            ("CFBundleExecutable", Value::from("A")),
        ]);
        std::fs::write(path.join("Info.plist"), Value::Dictionary(info).to_xml()).unwrap();
        AppBundle::load(&path).unwrap()
    }

    fn settings(dir: &Path) -> Settings {
        Settings {
            debug: false,
            thread_count: std::num::NonZeroUsize::MIN,
            anisette_server: None,
            config_dir: dir.to_path_buf(),
        }
    }

    fn team() -> developer::Team {
        developer::Team {
            team_id: "TEAM".into(),
            name: Some("Me".into()),
            kind: None,
        }
    }

    fn app_id(available: Option<i64>, existing: &[&str]) -> Dictionary {
        let ids: Vec<Value> = existing
            .iter()
            .map(|id| {
                Value::Dictionary(dict([
                    ("appIdId", Value::from(format!("ID-{id}"))),
                    ("identifier", Value::from(*id)),
                    ("name", Value::from("A")),
                    ("features", Value::Dictionary(Dictionary::new())),
                ]))
            })
            .collect();
        let mut d = dict([("appIds", Value::Array(ids))]);
        if let Some(a) = available {
            d.insert("availableQuantity", a);
            d.insert("maxQuantity", 10i64);
        }
        d
    }

    fn base_script(app_ids: Dictionary) -> Rc<RefCell<Script>> {
        let mut s = Script::default();
        s.replies.insert("listAppIds", app_ids);
        s.replies
            .insert("listDevices", dict([("devices", Value::Array(vec![]))]));
        s.replies.insert(
            "listAllDevelopmentCerts",
            dict([("certificates", Value::Array(vec![]))]),
        );
        s.replies.insert(
            "listApplicationGroups",
            dict([("applicationGroupList", Value::Array(vec![]))]),
        );
        Rc::new(RefCell::new(s))
    }

    #[test]
    fn missing_quota_means_unlimited_paid_team() {
        let dir = TempDir::new("plan-paid");
        let app = sample_app(&dir.0);
        let script = base_script(app_id(None, &[]));
        let plan = build_plan(
            &mut developer(&script),
            &team(),
            None,
            &app,
            "com.example.a.TEAM",
            &settings(&dir.0),
            "a@b.c",
            false,
        )
        .unwrap();
        assert!(
            plan.feasible(),
            "paid teams report no quota and must not be blocked"
        );
        assert_eq!(plan.available_quantity, None);
        assert_eq!(quota(plan.available_quantity), "unlimited");
    }

    #[test]
    fn exhausted_free_quota_blocks_without_changes() {
        let dir = TempDir::new("plan-free");
        let app = sample_app(&dir.0);
        let script = base_script(app_id(Some(0), &[]));
        let plan = build_plan(
            &mut developer(&script),
            &team(),
            None,
            &app,
            "com.example.a.TEAM",
            &settings(&dir.0),
            "a@b.c",
            false,
        )
        .unwrap();
        assert_eq!(
            plan.blocker.as_ref().map(|b| b.0),
            Some(ErrorCode::AppIdQuotaExceeded)
        );
        // Planning only reads.
        let actions: Vec<String> = script.borrow().calls.iter().map(|c| c.0.clone()).collect();
        assert!(actions.iter().all(|a| a.starts_with("list")), "{actions:?}");
    }

    #[test]
    fn app_group_is_assigned_by_its_server_side_id() {
        let dir = TempDir::new("plan-group");
        let mut app = sample_app(&dir.0);
        let script = base_script(app_id(Some(10), &["com.example.a.TEAM"]));
        script.borrow_mut().replies.insert(
            "addApplicationGroup",
            dict([(
                "applicationGroup",
                Value::Dictionary(dict([
                    ("applicationGroup", Value::from("SERVER-GROUP-ID")),
                    ("identifier", Value::from("group.com.example.a.TEAM")),
                ])),
            )]),
        );
        script.borrow_mut().replies.insert(
            "updateAppId",
            dict([(
                "appId",
                Value::Dictionary(dict([
                    ("appIdId", Value::from("ID-com.example.a.TEAM")),
                    ("identifier", Value::from("com.example.a.TEAM")),
                    ("name", Value::from("A")),
                    ("features", Value::Dictionary(Dictionary::new())),
                ])),
            )]),
        );
        script.borrow_mut().replies.insert(
            "downloadTeamProvisioningProfile",
            dict([(
                "provisioningProfile",
                Value::Dictionary(dict([
                    ("provisioningProfileId", Value::from("P")),
                    ("appIdId", Value::from("ID-com.example.a.TEAM")),
                    ("encodedProfile", Value::Data(b"profile".to_vec())),
                ])),
            )]),
        );
        let profiles = provision_app_ids(
            &mut developer(&script),
            "TEAM",
            &mut app,
            "com.example.a.TEAM",
            "com.example.a",
        )
        .unwrap();
        assert_eq!(
            profiles.get("com.example.a.TEAM").map(Vec::as_slice),
            Some(&b"profile"[..])
        );
        let calls = &script.borrow().calls;
        let assign = calls
            .iter()
            .find(|c| c.0 == "assignApplicationGroupToAppId")
            .expect("assigned");
        assert_eq!(
            assign.1.get("applicationGroups").and_then(Value::as_str),
            Some("SERVER-GROUP-ID")
        );
        assert_eq!(
            assign.1.get("appIdId").and_then(Value::as_str),
            Some("ID-com.example.a.TEAM")
        );
    }
}
