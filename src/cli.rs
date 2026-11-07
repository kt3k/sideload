//! CLI Front End (SPEC Section 5): argument parsing, dispatch, exit codes.

use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;

use lexopt::prelude::*;

use crate::commands;
use crate::config::{GlobalOptions, Os, ProcessEnv, Settings};
use crate::output;
use crate::{Error, ErrorCode, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallArgs {
    /// `None` only with `sidestore`.
    pub ipa: Option<PathBuf>,
    /// `-s`: install the latest SideStore release (SPEC Section 7.7).
    pub sidestore: bool,
    pub udid: Option<String>,
    pub team: Option<String>,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub strip_extensions: bool,
    pub bundle_id: Option<String>,
    pub name: Option<String>,
    pub new_cert: bool,
    pub keep_temp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Install(InstallArgs),
    TeamList,
    DeviceList {
        team: Option<String>,
        udid: Option<String>,
    },
    DeviceDelete {
        team: Option<String>,
        device_id: String,
    },
    CertList {
        team: Option<String>,
    },
    CertRevoke {
        team: Option<String>,
        serial_number: String,
    },
    AppIdList {
        team: Option<String>,
    },
    AppIdDelete {
        team: Option<String>,
        identifier: String,
    },
    Version,
    Help(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub global: GlobalOptions,
    pub command: Command,
}

/// Process entry point: parse, run, print errors, map to exit codes
/// (SPEC Section 5.5).
pub fn main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    match run(args) {
        Ok(code) => code,
        Err(err) => {
            output::error(&err);
            ExitCode::from(1)
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<ExitCode> {
    let inv = parse(args)?;
    if let Command::Help(text) = inv.command {
        print!("{text}");
        return Ok(ExitCode::SUCCESS);
    }
    if inv.command == Command::Version {
        return commands::version::run();
    }
    output::set_debug(inv.global.debug);
    let settings = Settings::resolve(&inv.global, &ProcessEnv, Os::current())?;
    commands::dispatch(inv.command, &settings)
}

fn usage_error(err: lexopt::Error) -> Error {
    Error::new(ErrorCode::InvalidArguments, err.to_string())
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArguments, msg)
}

/// Parses the full argv (including the program name).
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation> {
    let mut p = lexopt::Parser::from_iter(args);
    let mut global = GlobalOptions::default();

    // Global options come before the subcommand (SPEC Section 5.3).
    let command_word = loop {
        match p.next().map_err(usage_error)? {
            Some(Short('h') | Long("help")) => {
                return Ok(Invocation {
                    global,
                    command: Command::Help(help::TOP),
                });
            }
            Some(Short('d') | Long("debug")) => global.debug = true,
            Some(Long("thread-count")) => {
                let n: usize = p
                    .value()
                    .map_err(usage_error)?
                    .parse()
                    .map_err(usage_error)?;
                global.thread_count = Some(
                    NonZeroUsize::new(n)
                        .ok_or_else(|| invalid("--thread-count must be a positive integer"))?,
                );
            }
            Some(Long("anisette-server")) => {
                global.anisette_server = Some(
                    p.value()
                        .map_err(usage_error)?
                        .string()
                        .map_err(usage_error)?,
                );
            }
            Some(Value(word)) => break word.string().map_err(usage_error)?,
            Some(other) => return Err(usage_error(other.unexpected())),
            None => return Err(invalid("missing command (see `sideload --help`)")),
        }
    };

    let command = match command_word.as_str() {
        "install" => parse_install(&mut p)?,
        "team" => match subcommand(&mut p, "team", help::TEAM)? {
            Sub::Help(h) => Command::Help(h),
            Sub::Name(s) if s == "list" => {
                no_more_args(&mut p, help::TEAM)?.unwrap_or(Command::TeamList)
            }
            Sub::Name(s) => return Err(unknown_sub("team", &s)),
        },
        "device" => match subcommand(&mut p, "device", help::DEVICE)? {
            Sub::Help(h) => Command::Help(h),
            Sub::Name(s) if s == "list" => {
                let mut team = None;
                let mut udid = None;
                let mut help = false;
                while let Some(arg) = p.next().map_err(usage_error)? {
                    match arg {
                        Short('h') | Long("help") => help = true,
                        Long("team") => team = Some(string_value(&mut p)?),
                        Long("udid") => udid = Some(string_value(&mut p)?),
                        other => return Err(usage_error(other.unexpected())),
                    }
                }
                if help {
                    Command::Help(help::DEVICE)
                } else {
                    Command::DeviceList { team, udid }
                }
            }
            Sub::Name(s) if s == "delete" => {
                match team_and_positional(&mut p, help::DEVICE, "<device_id>")? {
                    Ok((team, device_id)) => Command::DeviceDelete { team, device_id },
                    Err(h) => Command::Help(h),
                }
            }
            Sub::Name(s) => return Err(unknown_sub("device", &s)),
        },
        "cert" => match subcommand(&mut p, "cert", help::CERT)? {
            Sub::Help(h) => Command::Help(h),
            Sub::Name(s) if s == "list" => match team_only(&mut p, help::CERT)? {
                Ok(team) => Command::CertList { team },
                Err(h) => Command::Help(h),
            },
            Sub::Name(s) if s == "revoke" => {
                match team_and_positional(&mut p, help::CERT, "<serial_number>")? {
                    Ok((team, serial_number)) => Command::CertRevoke {
                        team,
                        serial_number,
                    },
                    Err(h) => Command::Help(h),
                }
            }
            Sub::Name(s) => return Err(unknown_sub("cert", &s)),
        },
        "app-id" => match subcommand(&mut p, "app-id", help::APP_ID)? {
            Sub::Help(h) => Command::Help(h),
            Sub::Name(s) if s == "list" => match team_only(&mut p, help::APP_ID)? {
                Ok(team) => Command::AppIdList { team },
                Err(h) => Command::Help(h),
            },
            Sub::Name(s) if s == "delete" => {
                match team_and_positional(&mut p, help::APP_ID, "<identifier>")? {
                    Ok((team, identifier)) => Command::AppIdDelete { team, identifier },
                    Err(h) => Command::Help(h),
                }
            }
            Sub::Name(s) => return Err(unknown_sub("app-id", &s)),
        },
        "version" => no_more_args(&mut p, help::TOP)?.unwrap_or(Command::Version),
        other => {
            return Err(invalid(format!(
                "unknown command `{other}` (see `sideload --help`)"
            )));
        }
    };

    Ok(Invocation { global, command })
}

enum Sub {
    Name(String),
    Help(&'static str),
}

fn subcommand(p: &mut lexopt::Parser, parent: &str, help: &'static str) -> Result<Sub> {
    match p.next().map_err(usage_error)? {
        Some(Value(v)) => Ok(Sub::Name(v.string().map_err(usage_error)?)),
        Some(Short('h') | Long("help")) => Ok(Sub::Help(help)),
        Some(other) => Err(usage_error(other.unexpected())),
        None => Err(invalid(format!(
            "missing subcommand for `{parent}`\n\n{help}"
        ))),
    }
}

fn unknown_sub(parent: &str, sub: &str) -> Error {
    invalid(format!("unknown subcommand `{parent} {sub}`"))
}

fn string_value(p: &mut lexopt::Parser) -> Result<String> {
    p.value()
        .map_err(usage_error)?
        .string()
        .map_err(usage_error)
}

/// Accepts only `--help`; returns `Some(Help)` if given.
fn no_more_args(p: &mut lexopt::Parser, help: &'static str) -> Result<Option<Command>> {
    let mut want_help = false;
    while let Some(arg) = p.next().map_err(usage_error)? {
        match arg {
            Short('h') | Long("help") => want_help = true,
            other => return Err(usage_error(other.unexpected())),
        }
    }
    Ok(want_help.then_some(Command::Help(help)))
}

fn team_only(
    p: &mut lexopt::Parser,
    help: &'static str,
) -> Result<std::result::Result<Option<String>, &'static str>> {
    let mut team = None;
    while let Some(arg) = p.next().map_err(usage_error)? {
        match arg {
            Short('h') | Long("help") => return Ok(Err(help)),
            Long("team") => team = Some(string_value(p)?),
            other => return Err(usage_error(other.unexpected())),
        }
    }
    Ok(Ok(team))
}

fn team_and_positional(
    p: &mut lexopt::Parser,
    help: &'static str,
    what: &str,
) -> Result<std::result::Result<(Option<String>, String), &'static str>> {
    let mut team = None;
    let mut positional = None;
    while let Some(arg) = p.next().map_err(usage_error)? {
        match arg {
            Short('h') | Long("help") => return Ok(Err(help)),
            Long("team") => team = Some(string_value(p)?),
            Value(v) if positional.is_none() => positional = Some(v.string().map_err(usage_error)?),
            other => return Err(usage_error(other.unexpected())),
        }
    }
    let positional = positional.ok_or_else(|| invalid(format!("missing argument {what}")))?;
    Ok(Ok((team, positional)))
}

fn parse_install(p: &mut lexopt::Parser) -> Result<Command> {
    let mut a = InstallArgs::default();
    let mut ipa = None;
    while let Some(arg) = p.next().map_err(usage_error)? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help(help::INSTALL)),
            Long("udid") => a.udid = Some(string_value(p)?),
            Long("team") => a.team = Some(string_value(p)?),
            Short('o') | Long("output") => a.output = Some(p.value().map_err(usage_error)?.into()),
            Short('s') | Long("sidestore") => a.sidestore = true,
            Long("dry-run") => a.dry_run = true,
            Long("strip-extensions") => a.strip_extensions = true,
            Long("bundle-id") => a.bundle_id = Some(string_value(p)?),
            Long("name") => a.name = Some(string_value(p)?),
            Long("new-cert") => a.new_cert = true,
            Long("keep-temp") => a.keep_temp = true,
            Value(v) if ipa.is_none() => ipa = Some(PathBuf::from(v)),
            other => return Err(usage_error(other.unexpected())),
        }
    }
    a.ipa = ipa;
    match (&a.ipa, a.sidestore) {
        (Some(_), true) => return Err(invalid("<ipa> and --sidestore cannot be combined")),
        (None, false) => return Err(invalid("missing argument <ipa> (or use --sidestore)")),
        _ => {}
    }
    if a.output.is_some() && a.dry_run {
        return Err(invalid("--output and --dry-run cannot be combined"));
    }
    Ok(Command::Install(a))
}

pub mod help {
    pub const TOP: &str = "\
Sideload iOS apps onto a device with an Apple developer account.

Usage: sideload [global options] <command>

Commands:
  install <ipa>              Install an IPA onto a device
  install -s                 Install the latest SideStore release

  team list                  Check login and look up team IDs
  device list                Registered and connected devices
  device delete <device_id>  Unregister a device
  cert list                  List development certificates
  cert revoke <serial>       Revoke a development certificate
  app-id list                List App IDs and remaining quota
  app-id delete <id>         Delete an App ID

  version                    Print the version

Global options:
  -d, --debug                Verbose logging
      --thread-count <N>     Signing parallelism (default: number of CPUs)
      --anisette-server <URL>
                             Use a remote anisette-v3 server instead of local ADI.
                             The server is a third party that generates Anisette
                             data containing device identifiers.

Environment:
  SIDELOADER_CONFIG_DIR       Configuration directory
  SIDELOADER_ANISETTE_SERVER  Default for --anisette-server
  SIDELOADER_APPLE_ID         Apple ID (skips the prompt)
  SIDELOADER_APPLE_PASSWORD   Password (skips the prompt). It may be readable by
                              other processes of the same user.
";

    pub const INSTALL: &str = "\
Install an IPA onto a device.

Usage:
  sideload install <ipa> [options]
  sideload install -s [options]

Options:
  -s, --sidestore          Download the latest SideStore release from GitHub
                           (SideStore/SideStore) and install it instead of <ipa>
      --udid <UDID>        Target device
      --team <TEAM_ID>     Team to use (default: first team)
  -o, --output <PATH>      Write the signed IPA instead of installing it
      --dry-run            Print the plan only; change nothing
      --strip-extensions   Remove app extensions and Watch apps (saves App IDs)
      --bundle-id <ID>     Use this main bundle identifier as-is
      --name <NAME>        Rewrite CFBundleDisplayName
      --new-cert           Revoke all Sideloader certificates and create a new one.
                           Apps signed with revoked certificates stop launching.
      --keep-temp          Keep the working directory and print its path
";

    pub const TEAM: &str = "\
Usage: sideload team list
";

    pub const DEVICE: &str = "\
Usage:
  sideload device list [--team <TEAM_ID>] [--udid <UDID>]
  sideload device delete [--team <TEAM_ID>] <device_id>

<device_id> is the identifier shown by `device list`, not the UDID.
";

    pub const CERT: &str = "\
Usage:
  sideload cert list [--team <TEAM_ID>]
  sideload cert revoke [--team <TEAM_ID>] <serial_number>

Apps signed with a revoked certificate stop launching.
";

    pub const APP_ID: &str = "\
Usage:
  sideload app-id list [--team <TEAM_ID>]
  sideload app-id delete [--team <TEAM_ID>] <identifier>

Deleting an App ID does not restore quota.
";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> Result<Invocation> {
        parse(
            std::iter::once("sideload")
                .chain(args.iter().copied())
                .map(OsString::from),
        )
    }

    fn cmd(args: &[&str]) -> Command {
        parse_str(args).unwrap().command
    }

    fn err_code(args: &[&str]) -> ErrorCode {
        parse_str(args).unwrap_err().code
    }

    #[test]
    fn install_with_all_options() {
        let c = cmd(&[
            "install",
            "app.ipa",
            "--udid",
            "U",
            "--team",
            "T",
            "-o",
            "out.ipa",
            "--strip-extensions",
            "--bundle-id",
            "com.x",
            "--name",
            "X",
            "--new-cert",
            "--keep-temp",
        ]);
        let Command::Install(a) = c else { panic!() };
        assert_eq!(a.ipa, Some(PathBuf::from("app.ipa")));
        assert_eq!(a.udid.as_deref(), Some("U"));
        assert_eq!(a.team.as_deref(), Some("T"));
        assert_eq!(a.output, Some(PathBuf::from("out.ipa")));
        assert!(a.strip_extensions && a.new_cert && a.keep_temp && !a.dry_run);
        assert_eq!(a.bundle_id.as_deref(), Some("com.x"));
        assert_eq!(a.name.as_deref(), Some("X"));
    }

    #[test]
    fn output_and_dry_run_conflict() {
        assert_eq!(
            err_code(&["install", "a.ipa", "-o", "x", "--dry-run"]),
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn global_options_before_command() {
        let inv = parse_str(&[
            "-d",
            "--thread-count",
            "2",
            "--anisette-server",
            "https://a",
            "team",
            "list",
        ])
        .unwrap();
        assert!(inv.global.debug);
        assert_eq!(inv.global.thread_count, NonZeroUsize::new(2));
        assert_eq!(inv.global.anisette_server.as_deref(), Some("https://a"));
        assert_eq!(inv.command, Command::TeamList);
    }

    #[test]
    fn global_options_after_command_are_rejected() {
        assert_eq!(
            err_code(&["team", "list", "--debug"]),
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn thread_count_must_be_positive() {
        assert_eq!(
            err_code(&["--thread-count", "0", "version"]),
            ErrorCode::InvalidArguments
        );
        assert_eq!(
            err_code(&["--thread-count", "x", "version"]),
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn diagnostic_commands() {
        assert_eq!(
            cmd(&["device", "list"]),
            Command::DeviceList {
                team: None,
                udid: None
            }
        );
        assert_eq!(
            cmd(&["device", "delete", "--team", "T", "ABC"]),
            Command::DeviceDelete {
                team: Some("T".into()),
                device_id: "ABC".into()
            }
        );
        assert_eq!(cmd(&["cert", "list"]), Command::CertList { team: None });
        assert_eq!(
            cmd(&["cert", "revoke", "123"]),
            Command::CertRevoke {
                team: None,
                serial_number: "123".into()
            }
        );
        assert_eq!(
            cmd(&["app-id", "list", "--team", "T"]),
            Command::AppIdList {
                team: Some("T".into())
            }
        );
        assert_eq!(
            cmd(&["app-id", "delete", "com.x"]),
            Command::AppIdDelete {
                team: None,
                identifier: "com.x".into()
            }
        );
        assert_eq!(cmd(&["version"]), Command::Version);
    }

    #[test]
    fn team_list_rejects_team_option() {
        assert_eq!(
            err_code(&["team", "list", "--team", "T"]),
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn removed_upstream_commands_are_rejected() {
        for c in [
            &["sign"][..],
            &["trollsign", "x"],
            &["tool", "list"],
            &["cert", "submit", "x"],
            &["app-id", "add", "a", "b"],
            &["device", "add", "a", "b"],
        ] {
            assert_eq!(err_code(c), ErrorCode::InvalidArguments, "{c:?}");
        }
    }

    #[test]
    fn missing_arguments() {
        assert_eq!(err_code(&[]), ErrorCode::InvalidArguments);
        assert_eq!(err_code(&["cert", "revoke"]), ErrorCode::InvalidArguments);
    }

    #[test]
    fn sidestore_option() {
        for flag in ["-s", "--sidestore"] {
            let Command::Install(a) = cmd(&["install", flag, "--udid", "U"]) else {
                panic!()
            };
            assert!(a.sidestore);
            assert_eq!(a.ipa, None);
            assert_eq!(a.udid.as_deref(), Some("U"));
        }
        assert_eq!(err_code(&["install"]), ErrorCode::InvalidArguments);
        assert_eq!(
            err_code(&["install", "a.ipa", "-s"]),
            ErrorCode::InvalidArguments
        );
    }

    #[test]
    fn help() {
        assert_eq!(cmd(&["--help"]), Command::Help(help::TOP));
        assert_eq!(cmd(&["install", "--help"]), Command::Help(help::INSTALL));
        assert_eq!(
            cmd(&["device", "delete", "-h"]),
            Command::Help(help::DEVICE)
        );
    }
}
