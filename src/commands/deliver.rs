//! Deliver a signed bundle to a connected device (SPEC Section 10.3):
//! upload to `PublicStaging` over AFC, install the profiles with misagent,
//! and install the app with installation_proxy.
//!
//! This path requires a real paired device and cannot be exercised by unit
//! tests; the per-service protocol logic it drives is tested separately.

use std::path::Path;

use crate::device::afc::AfcClient;
use crate::device::installation_proxy::{self, InstallationProxyClient};
use crate::device::lockdown::{self, DeviceStream, LockdownClient};
use crate::device::misagent::{self, MisagentClient};
use crate::device::pairing::PairingRecord;
use crate::device::usbmuxd::Usbmuxd;
use crate::{Error, ErrorCode, Result};

const AFC_SERVICE: &str = "com.apple.afc";
const STAGING: &str = "PublicStaging";

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::DeviceTransportError, msg.to_string())
}

/// Reads the device's pairing record from usbmuxd.
pub fn pairing_record(udid: &str) -> Result<PairingRecord> {
    let mut mux = Usbmuxd::connect()?;
    let bytes = mux.read_pair_record(udid)?.ok_or_else(|| {
        Error::new(
            ErrorCode::DeviceNotPaired,
            format!("device {udid} is not paired; trust this computer on the device"),
        )
    })?;
    PairingRecord::parse(&bytes)
}

/// Opens a lockdownd TLS session to `device_id`.
fn open_lockdown(device_id: u32, pairing: &PairingRecord) -> Result<LockdownClient> {
    let socket = Usbmuxd::connect()?.connect_to_device(device_id, lockdown::LOCKDOWND_PORT)?;
    let mut client = LockdownClient::new(socket);
    client.query_type()?;
    client.start_session(pairing)?;
    Ok(client)
}

/// Starts `service` and opens a new device connection to it, wrapping it in
/// TLS when the service requires it.
fn open_service(
    lockdown: &mut LockdownClient,
    device_id: u32,
    service: &str,
    escrow_bag: Option<&[u8]>,
) -> Result<DeviceStream> {
    let info = lockdown.start_service(service, escrow_bag)?;
    let socket = Usbmuxd::connect()?.connect_to_device(device_id, info.port)?;
    if info.ssl {
        let config = lockdown
            .service_tls_config()
            .ok_or_else(|| transport_err("no TLS session for a secure service"))?;
        lockdown::wrap_tls(socket, config)
    } else {
        Ok(DeviceStream::Plain(socket))
    }
}

/// Uploads the `.app` directory tree under `remote_dir` over AFC.
fn upload_tree<S: std::io::Read + std::io::Write>(
    afc: &mut AfcClient<S>,
    local: &Path,
    remote: &str,
) -> Result<()> {
    afc.make_directory(remote)?;
    let mut entries: Vec<_> = std::fs::read_dir(local)
        .map_err(|e| transport_err(format!("{}: {e}", local.display())))?
        .filter_map(std::result::Result::ok)
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let remote_child = format!("{remote}/{name}");
        let meta = std::fs::symlink_metadata(entry.path())
            .map_err(|e| transport_err(format!("{}: {e}", entry.path().display())))?;
        if meta.is_dir() {
            upload_tree(afc, &entry.path(), &remote_child)?;
        } else if meta.is_file() {
            let data = std::fs::read(entry.path())
                .map_err(|e| transport_err(format!("{}: {e}", entry.path().display())))?;
            afc.write_file(&remote_child, &data)?;
        } else {
            return Err(transport_err(format!(
                "unsupported file type in bundle: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Delivers `app_dir` (a signed `.app`) to the device, installing `profiles`
/// first. `progress` receives installation_proxy progress.
pub fn deliver(
    device_id: u32,
    udid: &str,
    app_dir: &Path,
    profiles: &[Vec<u8>],
    mut progress: impl FnMut(u64, &str),
) -> Result<()> {
    let pairing = pairing_record(udid)?;
    let mut lockdown = open_lockdown(device_id, &pairing)?;

    // Upload the signed bundle to PublicStaging.
    let afc_stream = open_service(&mut lockdown, device_id, AFC_SERVICE, None)?;
    let mut afc = AfcClient::new(afc_stream);
    let app_name = app_dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| transport_err("bundle has no name"))?;
    let remote_app = format!("{STAGING}/{app_name}");
    if afc.exists(STAGING)? {
        afc.remove_path_and_contents(STAGING)?;
    }
    afc.make_directory(STAGING)?;
    upload_tree(&mut afc, app_dir, &remote_app)?;

    // Install the provisioning profiles.
    let misagent_stream = open_service(
        &mut lockdown,
        device_id,
        misagent::SERVICE,
        pairing.escrow_bag.as_deref(),
    )?;
    let mut misagent = MisagentClient::new(misagent_stream);
    for profile in profiles {
        misagent.install(profile)?;
    }

    // Install the staged app.
    let ip_stream = open_service(&mut lockdown, device_id, installation_proxy::SERVICE, None)?;
    let mut installer = InstallationProxyClient::new(ip_stream);
    installer.install(&remote_app, |p, s| progress(p, s))?;
    Ok(())
}
