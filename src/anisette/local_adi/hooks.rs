//! Linux bionic compatibility hooks. ADI calls are serialized on the owning
//! thread; Android pthread objects must never be passed to glibc pthread APIs.
use super::loader::Library;
use std::{
    cell::Cell,
    ffi::{CStr, c_char, c_void},
};
thread_local! {static CORE:Cell<*const Library>=const {Cell::new(std::ptr::null())};}
pub fn with_core<T>(core: &Library, call: impl FnOnce() -> T) -> T {
    struct Reset(*const Library);
    impl Drop for Reset {
        fn drop(&mut self) {
            CORE.with(|c| c.set(self.0));
        }
    }
    let old = CORE.with(|c| c.replace(core));
    let _reset = Reset(old);
    call()
}
unsafe extern "C" fn open_library(name: *const c_char, _flags: i32) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    if name.ends_with(b"libCoreADI.so") {
        CORE.with(|c| c.get() as *mut c_void)
    } else {
        std::ptr::null_mut()
    }
}
unsafe extern "C" fn symbol(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    CORE.with(|c| {
        let core = c.get();
        if core.is_null() || core as *mut c_void != handle {
            return std::ptr::null_mut();
        }
        let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
            return std::ptr::null_mut();
        };
        unsafe { &*core }.symbol(name).unwrap_or(0) as *mut c_void
    })
}
unsafe extern "C" fn zero() -> i32 {
    0
}
unsafe extern "C" fn no_thread() -> i32 {
    libc::ENOSYS
}
unsafe extern "C" fn once(flag: *mut i32, init: unsafe extern "C" fn()) -> i32 {
    if flag.is_null() {
        return libc::EINVAL;
    }
    if unsafe { *flag } == 0 {
        unsafe {
            *flag = 1;
            init();
            *flag = 2;
        }
    }
    0
}
unsafe extern "C" fn property(_name: *const c_char, value: *mut c_char) -> i32 {
    let bytes = b"no s/n number\0";
    if !value.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), value.cast(), bytes.len());
        }
    }
    (bytes.len() - 1) as i32
}
unsafe extern "C" fn random() -> u32 {
    match crate::crypto::random_bytes(4) {
        Ok(bytes) => u32::from_ne_bytes(bytes.try_into().unwrap()),
        Err(_) => std::process::abort(),
    }
}
unsafe extern "C" fn unresolved() -> ! {
    eprintln!("Local ADI called an unsupported Android import");
    std::process::abort()
}
pub fn unresolved_address() -> usize {
    unresolved as *const () as usize
}
pub fn resolve(name: &str) -> Option<usize> {
    Some(match name {
        "dlopen" => open_library as *const () as usize,
        "dlsym" => symbol as *const () as usize,
        "dlclose" | "__cxa_atexit" | "__cxa_finalize" => zero as *const () as usize,
        "__system_property_get" => property as *const () as usize,
        "__errno" => libc::__errno_location as *const () as usize,
        "arc4random" => random as *const () as usize,
        "pthread_once" => once as *const () as usize,
        "pthread_create" => no_thread as *const () as usize,
        name if name.starts_with("pthread_mutex_") || name.starts_with("pthread_rwlock_") => {
            zero as *const () as usize
        }
        // This list is intentionally narrow: only functions with matching Linux
        // ABI and object layout may fall through to the host dynamic linker.
        "open" | "close" | "read" | "write" | "mkdir" | "chmod" | "umask" | "ftruncate"
        | "lstat" | "fstat" | "malloc" | "calloc" | "realloc" | "free" | "strncpy" | "strcpy"
        | "strlen" | "strcmp" | "strncmp" | "memcpy" | "memmove" | "memset" | "memcmp"
        | "gettimeofday" | "__stack_chk_fail" | "abort" => {
            let name = std::ffi::CString::new(name).ok()?;
            let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
            if p.is_null() {
                return None;
            }
            p as usize
        }
        _ => return None,
    })
}
