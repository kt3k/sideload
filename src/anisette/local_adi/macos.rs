//! macOS native Anisette through AOSKit/AuthKit. No Android ELF, foreign TLS,
//! downloaded libraries, or Objective-C dependency crates are needed.
use super::provisioning::error;
use crate::{
    Result,
    anisette::{AnisetteData, AnisetteProvider},
    formats::date,
};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    marker::PhantomData,
    rc::Rc,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
type Object = *mut c_void;
#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Object;
    fn sel_registerName(name: *const c_char) -> Object;
    fn objc_msgSend();
    fn objc_autoreleasePoolPush() -> Object;
    fn objc_autoreleasePoolPop(pool: Object);
}
fn selector(name: &str) -> Object {
    let name = CString::new(name).expect("static selector");
    unsafe { sel_registerName(name.as_ptr()) }
}
unsafe fn send0(receiver: Object, name: &str) -> Object {
    let call: unsafe extern "C" fn(Object, Object) -> Object =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { call(receiver, selector(name)) }
}
unsafe fn send1(receiver: Object, name: &str, arg: Object) -> Object {
    let call: unsafe extern "C" fn(Object, Object, Object) -> Object =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { call(receiver, selector(name), arg) }
}
unsafe fn responds(receiver: Object, name: &str) -> bool {
    if receiver.is_null() {
        return false;
    }
    let call: unsafe extern "C" fn(Object, Object, Object) -> i8 =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { call(receiver, selector("respondsToSelector:"), selector(name)) != 0 }
}
struct Pool(Object);
impl Pool {
    fn new() -> Self {
        Self(unsafe { objc_autoreleasePoolPush() })
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        unsafe {
            objc_autoreleasePoolPop(self.0);
        }
    }
}
#[derive(Clone)]
struct Classes {
    aos: usize,
    device: usize,
    string: usize,
}
static CLASSES: OnceLock<std::result::Result<Classes, String>> = OnceLock::new();
fn classes() -> Result<Classes> {
    CLASSES
        .get_or_init(|| {
            // Loaded once and intentionally kept resident: Objective-C registers class
            // metadata globally, so unloading these framework images is unsafe.
            for path in [
                "/System/Library/Frameworks/Foundation.framework/Foundation",
                "/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit",
                "/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit",
            ] {
                let path = CString::new(path).unwrap();
                if unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) }
                    .is_null()
                {
                    return Err("cannot load macOS Anisette frameworks".into());
                }
            }
            let class = |name: &str| {
                let name = CString::new(name).unwrap();
                let c = unsafe { objc_getClass(name.as_ptr()) };
                if c.is_null() {
                    Err("macOS Anisette class is unavailable".to_owned())
                } else {
                    Ok(c as usize)
                }
            };
            let c = Classes {
                aos: class("AOSUtilities")?,
                device: class("AKDevice")?,
                string: class("NSString")?,
            };
            if !unsafe { responds(c.aos as Object, "retrieveOTPHeadersForDSID:") }
                || !unsafe { responds(c.device as Object, "currentDevice") }
            {
                return Err("macOS Anisette API is unavailable".into());
            }
            Ok(c)
        })
        .as_ref()
        .cloned()
        .map_err(error)
}
unsafe fn ns_string(class: usize, text: &str) -> Result<Object> {
    let s = CString::new(text).map_err(|_| error("NUL in framework key"))?;
    let out = unsafe {
        send1(
            class as Object,
            "stringWithUTF8String:",
            s.as_ptr() as Object,
        )
    };
    if out.is_null() {
        return Err(error("cannot create framework string"));
    }
    Ok(out)
}
unsafe fn string(receiver: Object, name: &str) -> Result<String> {
    if !unsafe { responds(receiver, name) } {
        return Err(error(format!("macOS API missing {name}")));
    }
    let s = unsafe { send0(receiver, name) };
    unsafe { utf8(s) }
}
unsafe fn utf8(s: Object) -> Result<String> {
    if !unsafe { responds(s, "UTF8String") } {
        return Err(error("macOS API returned a non-string"));
    }
    let p = unsafe { send0(s, "UTF8String") } as *const c_char;
    if p.is_null() {
        return Err(error("macOS API returned an empty string"));
    }
    let text = unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| error("invalid macOS Anisette string"))?;
    if text.is_empty() || text.len() > 8192 || text.chars().any(char::is_control) {
        return Err(error("invalid macOS Anisette header value"));
    }
    Ok(text.to_owned())
}
/// Bound to its creating thread; every request has a local autorelease pool.
pub struct MacOs {
    classes: Classes,
    _thread: PhantomData<Rc<()>>,
}
impl MacOs {
    pub fn new() -> Result<Self> {
        Ok(Self {
            classes: classes()?,
            _thread: PhantomData,
        })
    }
}
impl AnisetteProvider for MacOs {
    fn headers(&mut self) -> Result<AnisetteData> {
        let _pool = Pool::new();
        let c = &self.classes;
        let otp_headers = unsafe {
            send1(
                c.aos as Object,
                "retrieveOTPHeadersForDSID:",
                ns_string(c.string, "-2")?,
            )
        };
        if !unsafe { responds(otp_headers, "objectForKey:") } {
            return Err(error(
                "AOSKit returned no OTP headers; sign into iCloud or use a remote server",
            ));
        }
        let lookup = |names: &[&str]| -> Result<String> {
            for name in names {
                let key = unsafe { ns_string(c.string, name)? };
                let value = unsafe { send1(otp_headers, "objectForKey:", key) };
                if !value.is_null() {
                    return unsafe { utf8(value) };
                }
            }
            Err(error("AOSKit response missing OTP field"))
        };
        let otp = lookup(&["X-Apple-MD", "X-Apple-I-MD"])?;
        let mid = lookup(&["X-Apple-MD-M", "X-Apple-I-MD-M"])?;
        for value in [&otp, &mid] {
            if crate::formats::base64::decode(value).is_err() {
                return Err(error("AOSKit returned invalid OTP encoding"));
            }
        }
        let device = unsafe { send0(c.device as Object, "currentDevice") };
        if device.is_null() {
            return Err(error("AuthKit currentDevice is unavailable"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("invalid system clock"))?
            .as_secs();
        let mut headers = vec![
            ("X-Apple-I-MD".into(), otp),
            ("X-Apple-I-MD-M".into(), mid),
            ("X-Apple-I-MD-RINFO".into(), "17106176".into()),
            ("X-Apple-I-MD-LU".into(), unsafe {
                string(device, "localUserUUID")
            }?),
            ("X-Mme-Device-Id".into(), unsafe {
                string(device, "uniqueDeviceIdentifier")
            }?),
            ("X-Mme-Client-Info".into(), unsafe {
                string(device, "serverFriendlyDescription")
            }?),
            (
                "X-Apple-I-Client-Time".into(),
                date::format_iso8601(now as i64),
            ),
            ("X-Apple-I-TimeZone".into(), "UTC".into()),
            ("X-Apple-Locale".into(), "en_US".into()),
            ("User-Agent".into(), "akd/1.0".into()),
        ];
        let serial = unsafe { string(c.aos as Object, "machineSerialNumber") }
            .unwrap_or_else(|_| "0".into());
        headers.push(("X-Apple-I-SRL-NO".into(), serial));
        Ok(AnisetteData { headers })
    }
}
