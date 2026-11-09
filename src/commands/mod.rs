//! Command handlers (Coordination layer).

pub mod cert_identity;
pub mod deliver;
pub mod diagnostics;
pub mod install;
pub mod pairing_file;
pub mod session;
#[cfg(test)]
mod test_support;
pub mod version;

use std::process::ExitCode;

use crate::Result;
use crate::cli::Command;
use crate::config::Settings;

pub fn dispatch(command: Command, settings: &Settings) -> Result<ExitCode> {
    use diagnostics as d;
    match command {
        Command::Install(args) => install::run(&args, settings),
        Command::TeamList => d::team_list(settings),
        Command::DeviceList { team, udid } => d::device_list(settings, team, udid),
        Command::DeviceDelete { team, device_id } => d::device_delete(settings, team, &device_id),
        Command::CertList { team } => d::cert_list(settings, team),
        Command::CertRevoke {
            team,
            serial_number,
        } => d::cert_revoke(settings, team, &serial_number),
        Command::AppIdList { team } => d::app_id_list(settings, team),
        Command::AppIdDelete { team, identifier } => d::app_id_delete(settings, team, &identifier),
        Command::SidestorePairingFile { udid } => pairing_file::run(udid.as_deref()),
        Command::Logout => session::logout(),
        Command::Version => version::run(),
        Command::Help(text) => {
            print!("{text}");
            Ok(ExitCode::SUCCESS)
        }
    }
}
