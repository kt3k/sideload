//! Logging, progress and error output (SPEC Section 12).
//!
//! Command results go to stdout; logs, progress and errors go to stderr.
//! Secrets (SPEC Section 14.2) must never be passed to these functions.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::Error;

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

// TODO: progress reporting for `install` (phase name + overall percentage;
// one line per phase when stderr is not a terminal).
