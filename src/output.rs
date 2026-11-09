//! Logging, progress and error output (SPEC Section 12).
//!
//! Command results go to stdout; logs, progress and errors go to stderr.
//! Secrets (SPEC Section 14.2) must never be passed to these functions.
//!
//! An embedding application (the on-device app, `ios/SPEC.md` Section 9.3)
//! can install a [`Sink`] to receive these messages instead of stderr.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::Error;
use crate::pipeline::Phase;

static DEBUG: AtomicBool = AtomicBool::new(false);

/// Kind of message passed to a [`Sink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warn,
    /// The message is a phase name (`Phase::as_str`).
    Phase,
}

/// Receives log messages in place of stderr.
pub type Sink = Arc<dyn Fn(Level, &str) + Send + Sync>;

static SINK: RwLock<Option<Sink>> = RwLock::new(None);

/// Routes messages to `sink` (or back to stderr with `None`).
pub fn set_sink(sink: Option<Sink>) {
    if let Ok(mut s) = SINK.write() {
        *s = sink;
    }
}

/// Sends to the sink if one is installed; returns false otherwise.
fn to_sink(level: Level, msg: &str) -> bool {
    let sink = SINK.read().ok().and_then(|s| s.clone());
    match sink {
        Some(sink) => {
            sink(level, msg);
            true
        }
        None => false,
    }
}

pub fn set_debug(enabled: bool) {
    DEBUG.store(enabled, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

pub fn info(msg: impl AsRef<str>) {
    if !to_sink(Level::Info, msg.as_ref()) {
        eprintln!("{}", msg.as_ref());
    }
}

pub fn warn(msg: impl AsRef<str>) {
    if !to_sink(Level::Warn, msg.as_ref()) {
        eprintln!("warning: {}", msg.as_ref());
    }
}

pub fn debug(msg: impl AsRef<str>) {
    if debug_enabled() && !to_sink(Level::Debug, msg.as_ref()) {
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
    if !to_sink(Level::Phase, p.as_str()) {
        eprintln!("[{}/{}] {}", p.number(), Phase::COUNT, p.as_str());
    }
}

/// Announces a phase outside SPEC Section 7.2, such as the on-device app's
/// `ConnectingDevice` (`ios/SPEC.md` Section 6).
pub fn named_phase(name: &str) {
    if !to_sink(Level::Phase, name) {
        eprintln!("[{name}]");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn sink_receives_messages() {
        let got: Arc<Mutex<Vec<(Level, String)>>> = Arc::default();
        let g = got.clone();
        set_sink(Some(Arc::new(move |l, m| {
            g.lock().unwrap().push((l, m.to_owned()))
        })));
        info("hello");
        warn("careful");
        phase(Phase::Signing);
        set_sink(None);
        let got = got.lock().unwrap();
        // Other tests may log concurrently; look for ours only.
        assert!(got.contains(&(Level::Info, "hello".into())));
        assert!(got.contains(&(Level::Warn, "careful".into())));
        assert!(got.contains(&(Level::Phase, "Signing".into())));
    }
}
