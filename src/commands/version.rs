//! `version` (SPEC Section 8.8). No login, no device communication.

use std::process::ExitCode;

use crate::Result;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run() -> Result<ExitCode> {
    println!("{VERSION}");
    Ok(ExitCode::SUCCESS)
}
