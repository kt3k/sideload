//! The C interface of the Core (`ios/SPEC.md` Section 13,
//! `include/sideload_core.h`).

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::{Arc, Mutex};

use sideload::output::{self, Level};

use crate::api;

/// Callbacks supplied by the caller. Either may be null. `log` may be called
/// from any thread while `sideload_call` runs.
#[repr(C)]
pub struct SideloadCallbacks {
    pub context: *mut c_void,
    pub log: Option<extern "C" fn(context: *mut c_void, level: i32, message: *const c_char)>,
    /// Returns a code (or `resend`) allocated with `malloc`, which the core
    /// frees; NULL cancels.
    pub two_factor_code: Option<extern "C" fn(context: *mut c_void) -> *mut c_char>,
}

/// Levels passed to `log`.
pub const LEVEL_DEBUG: i32 = 0;
pub const LEVEL_INFO: i32 = 1;
pub const LEVEL_WARN: i32 = 2;
pub const LEVEL_PHASE: i32 = 3;

/// Serializes calls (Section 8): the log sink is process-wide.
static CALL: Mutex<()> = Mutex::new(());

struct LogTarget {
    context: *mut c_void,
    log: extern "C" fn(*mut c_void, i32, *const c_char),
}

// SAFETY: the caller promises (header) that `log` is thread-safe for the
// duration of the call; the sink is removed before `sideload_call` returns.
unsafe impl Send for LogTarget {}
unsafe impl Sync for LogTarget {}

fn level_code(level: Level) -> i32 {
    match level {
        Level::Debug => LEVEL_DEBUG,
        Level::Info => LEVEL_INFO,
        Level::Warn => LEVEL_WARN,
        Level::Phase => LEVEL_PHASE,
    }
}

fn c_string(s: &str) -> CString {
    CString::new(s.replace('\0', " ")).expect("NULs removed")
}

/// Runs one request. Returns a JSON response to release with
/// `sideload_string_free`; never NULL.
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string. The callbacks
/// must be valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sideload_call(
    request: *const c_char,
    callbacks: SideloadCallbacks,
) -> *mut c_char {
    let request = if request.is_null() {
        String::new()
    } else {
        // SAFETY: the caller guarantees a valid C string.
        unsafe { CStr::from_ptr(request) }
            .to_string_lossy()
            .into_owned()
    };
    let guard = CALL.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(log) = callbacks.log {
        let target = Arc::new(LogTarget {
            context: callbacks.context,
            log,
        });
        output::set_sink(Some(Arc::new(move |level, msg| {
            let msg = c_string(msg);
            (target.log)(target.context, level_code(level), msg.as_ptr());
        })));
    }
    let context = callbacks.context;
    let two_factor = callbacks.two_factor_code;
    let mut ask = move || -> Option<String> {
        let f = two_factor?;
        let p = f(context);
        if p.is_null() {
            return None;
        }
        // SAFETY: the callback returns a malloc'd C string it hands over.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { libc::free(p.cast()) };
        Some(s)
    };
    let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        api::handle(&request, &mut ask)
    }))
    .unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"internal_error","phase":null,"message":"the core panicked"}}"#
            .to_owned()
    });
    output::set_sink(None);
    drop(guard);
    c_string(&response).into_raw()
}

/// Releases a string returned by `sideload_call`.
///
/// # Safety
/// `s` must be NULL or a pointer returned by `sideload_call`, released once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sideload_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from `CString::into_raw` in `sideload_call`.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn collect(context: *mut c_void, level: i32, message: *const c_char) {
        // SAFETY: the test passes a Mutex<Vec<..>> as context.
        let log = unsafe { &*(context as *const Mutex<Vec<(i32, String)>>) };
        let msg = unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned();
        log.lock().unwrap().push((level, msg));
    }

    #[test]
    fn calls_through_c_abi() {
        let log: Mutex<Vec<(i32, String)>> = Mutex::new(Vec::new());
        let req = CString::new(r#"{"op":"version"}"#).unwrap();
        let cb = SideloadCallbacks {
            context: &log as *const _ as *mut c_void,
            log: Some(collect),
            two_factor_code: None,
        };
        let out = unsafe { sideload_call(req.as_ptr(), cb) };
        let text = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { sideload_string_free(out) };
        assert!(text.starts_with(r#"{"ok":true"#), "{text}");

        let cb = SideloadCallbacks {
            context: std::ptr::null_mut(),
            log: None,
            two_factor_code: None,
        };
        let out = unsafe { sideload_call(std::ptr::null(), cb) };
        let text = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { sideload_string_free(out) };
        assert!(text.contains("invalid_arguments"), "{text}");
        unsafe { sideload_string_free(std::ptr::null_mut()) };
    }
}
