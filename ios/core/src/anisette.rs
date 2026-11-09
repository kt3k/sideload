//! Scoped bridge to an on-device engine supplied by the iOS host.
use std::cell::Cell;
use std::ffi::{c_char, c_void};

use sideload::anisette::{AnisetteData, AnisetteProvider};
use sideload::formats::json::{self, Value};
use sideload::{Error, ErrorCode, Result};

pub type HeadersCallback = extern "C" fn(*mut c_void) -> *mut c_char;
type Target = (*mut c_void, HeadersCallback);
thread_local! { static TARGET: Cell<Option<Target>> = const { Cell::new(None) }; }

/// Removed on normal return and unwinding. Providers never outlive a core call.
pub(crate) struct Scope(Option<Target>);
impl Scope {
    pub(crate) fn enter(context: *mut c_void, callback: Option<HeadersCallback>) -> Self {
        Self(TARGET.with(|slot| slot.replace(callback.map(|f| (context, f)))))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        TARGET.with(|slot| slot.set(self.0));
    }
}

pub(crate) struct OnDevice;
fn unavailable(message: &str) -> Error {
    Error::new(ErrorCode::AnisetteUnavailable, message)
}
impl OnDevice {
    pub(crate) fn new() -> Result<Self> {
        if TARGET.with(|slot| slot.get().is_none()) {
            return Err(unavailable(
                "on-device Anisette engine unavailable; configure a remote server in Settings",
            ));
        }
        Ok(Self)
    }
}
impl AnisetteProvider for OnDevice {
    fn headers(&mut self) -> Result<AnisetteData> {
        let (context, callback) = TARGET
            .with(|slot| slot.get())
            .ok_or_else(|| unavailable("on-device Anisette callback is outside its call scope"))?;
        let raw = callback(context);
        if raw.is_null() {
            return Err(unavailable("on-device Anisette generation failed"));
        }
        // SAFETY: the host hands over a malloc-allocated NUL-terminated string.
        // Never include the response (including engine errors) in diagnostics.
        let length = unsafe { libc::strnlen(raw, 65537) };
        let parsed = if length <= 65536 {
            let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length) };
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|s| json::parse(s).ok())
        } else {
            None
        };
        unsafe { libc::free(raw.cast()) };
        decode(parsed.as_ref())
    }
}

fn decode(value: Option<&Value>) -> Result<AnisetteData> {
    let invalid = || unavailable("on-device Anisette returned invalid headers");
    let Some(Value::Object(entries)) = value.and_then(|v| v.get("headers")) else {
        return Err(invalid());
    };
    const ALLOWED: &[&str] = &[
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Mme-Device-Id",
        "X-Mme-Client-Info",
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "X-Apple-Locale",
        "X-Apple-I-SRL-NO",
        "User-Agent",
    ];
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in entries {
        let canonical = ALLOWED
            .iter()
            .find(|s| s.eq_ignore_ascii_case(name))
            .ok_or_else(invalid)?;
        let value = value.as_str().ok_or_else(invalid)?;
        if value.is_empty()
            || value.len() > 8192
            || value.chars().any(char::is_control)
            || headers.iter().any(|(k, _)| k == canonical)
        {
            return Err(invalid());
        }
        headers.push(((*canonical).to_owned(), value.to_owned()));
    }
    for required in &ALLOWED[..9] {
        if !headers.iter().any(|(k, _)| k == required) {
            return Err(invalid());
        }
    }
    Ok(AnisetteData { headers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    fn valid() -> Value {
        json::parse(r#"{"headers":{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"machine","X-Apple-I-MD-RINFO":"1","X-Apple-I-MD-LU":"user","X-Mme-Device-Id":"device","X-Mme-Client-Info":"client","X-Apple-I-Client-Time":"date","X-Apple-I-TimeZone":"UTC","X-Apple-Locale":"en_US"}}"#).unwrap()
    }
    #[test]
    fn validates_without_disclosing_secrets() {
        let mut v = valid();
        assert!(!format!("{:?}", decode(Some(&v)).unwrap()).contains("otp"));
        let Value::Object(ref mut outer) = v else {
            unreachable!()
        };
        let Value::Object(ref mut fields) = outer[0].1 else {
            unreachable!()
        };
        fields.push(("Authorization".into(), Value::String("secret".into())));
        assert!(!decode(Some(&v)).unwrap_err().to_string().contains("secret"));
        assert!(decode(None).is_err());
    }
    #[test]
    fn rejects_missing_duplicate_and_injected_headers() {
        for extra in [
            r#", "x-apple-i-md":"duplicate""#,
            r#", "User-Agent":"a\r\nb""#,
        ] {
            let text = valid().to_string();
            let text = format!("{}{}{}", &text[..text.len() - 2], extra, "}}");
            assert!(decode(Some(&json::parse(&text).unwrap())).is_err());
        }
        assert!(
            decode(Some(
                &json::parse(r#"{"headers":{"X-Apple-I-MD":"otp"}}"#).unwrap()
            ))
            .is_err()
        );
    }
    extern "C" fn generate(context: *mut c_void) -> *mut c_char {
        let count = unsafe { &mut *(context as *mut usize) };
        *count += 1;
        let text = CString::new(valid().to_string()).unwrap();
        unsafe { libc::strdup(text.as_ptr()) }
    }
    #[test]
    fn fresh_generation_and_scope_cleanup() {
        assert!(OnDevice::new().is_err());
        let mut count = 0usize;
        let mut provider;
        {
            let _scope = Scope::enter((&mut count as *mut usize).cast(), Some(generate));
            provider = OnDevice::new().unwrap();
            provider.headers().unwrap();
            provider.headers().unwrap();
        }
        assert_eq!(count, 2);
        assert!(provider.headers().is_err());
        assert!(OnDevice::new().is_err());
    }
    extern "C" fn failure(_: *mut c_void) -> *mut c_char {
        std::ptr::null_mut()
    }
    extern "C" fn response(context: *mut c_void) -> *mut c_char {
        let text = unsafe { &*(context as *const CString) };
        unsafe { libc::strdup(text.as_ptr()) }
    }
    #[test]
    fn rejects_malformed_oversized_and_non_utf8_callback_results() {
        for bytes in [b"{secret".to_vec(), vec![b'a'; 65537], vec![0xff]] {
            let text = CString::new(bytes).unwrap();
            let _scope = Scope::enter((&text as *const CString).cast_mut().cast(), Some(response));
            let error = OnDevice::new().unwrap().headers().unwrap_err();
            assert_eq!(error.code, ErrorCode::AnisetteUnavailable);
            assert!(!error.to_string().contains("secret"));
        }
    }
    #[test]
    fn null_result_and_unwind_clear_the_scope() {
        let result = std::panic::catch_unwind(|| {
            let _scope = Scope::enter(std::ptr::null_mut(), Some(failure));
            assert!(OnDevice::new().unwrap().headers().is_err());
            {
                let _nested = Scope::enter(std::ptr::null_mut(), None);
                assert!(OnDevice::new().is_err());
            }
            assert!(OnDevice::new().is_ok());
            panic!("simulated engine failure");
        });
        assert!(result.is_err());
        assert!(OnDevice::new().is_err());
    }
}
