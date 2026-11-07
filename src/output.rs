//! Logging, progress and error output (SPEC Section 12).
//!
//! Command results go to stdout; logs, progress and errors go to stderr.
//! Secrets (SPEC Section 14.2) must never be passed to these functions.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::Error;
use crate::pipeline::Phase;

static DEBUG: AtomicBool = AtomicBool::new(false);

pub fn set_debug(enabled: bool) {
    DEBUG.store(enabled, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

pub fn info(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    eprintln!("warning: {}", msg.as_ref());
}

pub fn debug(msg: impl AsRef<str>) {
    if debug_enabled() {
        eprintln!("debug: {}", msg.as_ref());
    }
}

pub fn error(err: &Error) {
    eprintln!("{err}");
}

/// Announces the start of an `install` phase (SPEC Section 12): one line per
/// phase with its position, e.g. `[8/16] Planning`. Phases that do not apply
/// (such as `DownloadingApp` without `--sidestore`) are not announced.
pub fn phase(p: Phase) {
    eprintln!("[{}/{}] {}", p.number(), Phase::COUNT, p.as_str());
}
