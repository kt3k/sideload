//! `install` (SPEC Section 7, reference algorithm in Section 15.1).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use crate::apple::Https;
use crate::apple::developer::{self, Developer};
use crate::bundle::{self, AppBundle};
use crate::cli::InstallArgs;
use crate::commands::{cert_identity, deliver, session};
use crate::config::Settings;
use crate::crypto::rsa_keygen::RsaPrivateKey;
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
        Err(e) => {
            output::debug(format!("could not list connected devices: {e}"));
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
    validate_arguments(args).map_err(|e| e.with_phase(Phase::ValidatingArguments))?;
    let mode = mode(args);
    let workdir = WorkDir::create(args.keep_temp)?;

    let target = phase(
        select_device(args.udid.as_deref(), mode),
        Phase::SelectingDevice,
    )?;

    // Obtain the IPA (download for --sidestore, otherwise the argument).
    let ipa = if args.sidestore {
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

    // Extract and adjust the bundle (SPEC Section 11.1).
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
    let original_main_id = phase(
        app.bundle_identifier().map(str::to_owned),
        Phase::PreparingBundle,
    )?;

    // Log in and pick the team.
    let auth = session::authenticate(settings, Some(Phase::LoggingIn))?;
    let mut dev = auth.dev;
    let team = phase(
        session::select_team(&mut dev, args.team.as_deref()),
        Phase::SelectingTeam,
    )?;

    // Rewrite identifiers and build the plan (SPEC Sections 7.4, 15.2).
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
    if let (Some(t), DeviceAction::Register) = (&target, &plan.device_action) {
        let name = device_name(t);
        phase(
            dev.add_device(&team.team_id, &name, &t.udid).map(|_| ()),
            Phase::RegisteringDevice,
        )?;
    }

    // PreparingCertificate (SPEC Section 7.3).
    let identity = cert_identity::prepare(
        &mut dev,
        &team.team_id,
        &settings.config_dir,
        &auth.apple_id,
        args.new_cert,
    )?;

    // RegisteringAppIds + ConfiguringAppGroup + FetchingProfiles.
    let profiles = phase(
        provision_app_ids(
            &mut dev,
            &team.team_id,
            &mut app,
            &main_id,
            &original_main_id,
        ),
        Phase::RegisteringAppIds,
    )?;

    // Persist Info.plist edits before signing (SPEC Section 11.1).
    phase(bundle::save_all(&app), Phase::Signing)?;

    output::info("Signing...");
    let profile_map: BTreeMap<String, Vec<u8>> = profiles.clone();
    phase(
        crate::sign::sign_bundle(&app, &identity, &profile_map, settings.thread_count.get()),
        Phase::Signing,
    )?;

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
fn build_plan(
    dev: &mut Developer<Https>,
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
    let available = listed.available_quantity.unwrap_or(0).max(0) as u32;

    // Certificate action: inspect the local key and the account's certs.
    let key = read_key_if_present(settings, apple_id);
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

    let blocker = if to_register as u32 > available {
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
        max_quantity: listed.max_quantity.unwrap_or(0) as u32,
        app_group,
        blocker,
    })
}

fn read_key_if_present(settings: &Settings, apple_id: &str) -> Option<RsaPrivateKey> {
    let path = cert_identity::key_path(&settings.config_dir, apple_id);
    let pem = std::fs::read_to_string(path).ok()?;
    RsaPrivateKey::from_pem(&pem).ok()
}

/// Registers missing App IDs, enables and assigns the App Group, and
/// downloads each App ID's provisioning profile. Returns a map from bundle
/// identifier to profile bytes.
fn provision_app_ids(
    dev: &mut Developer<Https>,
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

    let existing = dev.list_app_ids(team_id)?;
    for (identifier, name) in &needed {
        if !existing.app_ids.iter().any(|a| &a.identifier == identifier) {
            output::info(format!("Registering App ID {identifier}..."));
            dev.add_app_id(team_id, identifier, &bundle::app_id_name(name, identifier))?;
        }
    }

    // Re-list to get appIdId and current features for every needed App ID.
    let app_ids = dev.list_app_ids(team_id)?.app_ids;
    let group_id = bundle::app_group_id(main_id);
    let group_name = format!("app group for {main_id}");

    // Enable the App Group feature on each App ID.
    for (identifier, _) in &needed {
        let app_id = app_ids
            .iter()
            .find(|a| &a.identifier == identifier)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::AppleApiError,
                    format!("App ID {identifier} missing after registration"),
                )
            })?;
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

    // Create the App Group if needed, and assign it to each App ID.
    let groups = dev.list_app_groups(team_id)?;
    if !groups.iter().any(|g| g.identifier == group_id) {
        output::info(format!("Creating App Group {group_id}..."));
        dev.add_app_group(team_id, &group_id, &group_name)?;
    }
    for (identifier, _) in &needed {
        let app_id = app_ids
            .iter()
            .find(|a| &a.identifier == identifier)
            .expect("checked above");
        dev.assign_app_group(team_id, &app_id.app_id_id, &group_id)?;
    }

    // SideStore reads its app group from ALTAppGroups (SPEC Section 11.1).
    bundle::apply_sidestore_tweaks(app, original_main_id, &group_id);

    // Download each App ID's own provisioning profile (SPEC Section 7, fix
    // over upstream which reused the main profile everywhere).
    let mut profiles = BTreeMap::new();
    for (identifier, _) in &needed {
        let app_id = app_ids
            .iter()
            .find(|a| &a.identifier == identifier)
            .expect("checked above");
        output::debug(format!("fetching profile for {identifier}"));
        let profile = dev
            .download_team_provisioning_profile(team_id, &app_id.app_id_id)
            .map_err(|e| {
                if e.phase.is_none() {
                    e.with_phase(Phase::FetchingProfiles)
                } else {
                    e
                }
            })?;
        profiles.insert(identifier.clone(), profile.encoded_profile);
    }
    Ok(profiles)
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
        plan.available_quantity, plan.max_quantity
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
}
