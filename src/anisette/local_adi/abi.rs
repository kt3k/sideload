//! Android calls use System V on x86_64, including when the host is Windows.
macro_rules! native_function {
    ($(#[$attr:meta])* $vis:vis unsafe fn $name:ident($($args:tt)*) -> $ret:ty $body:block) => {
        #[cfg(target_arch="x86_64")]
        $(#[$attr])* $vis unsafe extern "sysv64" fn $name($($args)*) -> $ret $body
        #[cfg(not(target_arch="x86_64"))]
        $(#[$attr])* $vis unsafe extern "C" fn $name($($args)*) -> $ret $body
    }
}
macro_rules! native_type {
    ($name:ident($($args:ty),*) -> $ret:ty) => {
        #[cfg(target_arch="x86_64")] type $name = unsafe extern "sysv64" fn($($args),*) -> $ret;
        #[cfg(not(target_arch="x86_64"))] type $name = unsafe extern "C" fn($($args),*) -> $ret;
    }
}
pub(super) use {native_function, native_type};

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    #[allow(clippy::too_many_arguments)]
    unsafe extern "win64" fn host(
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
        g: u64,
        h: u64,
    ) -> u64 {
        a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h
    }
    native_function! {
        #[allow(clippy::too_many_arguments)]
        unsafe fn android(a:u64,b:u64,c:u64,d:u64,e:u64,f:u64,g:u64,h:u64)->u64 {unsafe{host(a,b,c,d,e,f,g,h)}}
    }
    #[test]
    fn sysv_to_windows_register_and_stack_arguments() {
        native_type!(Call(u64,u64,u64,u64,u64,u64,u64,u64)->u64);
        let call: Call = android;
        assert_eq!(unsafe { call(1, 2, 3, 4, 5, 6, 7, 8) }, 204);
    }
}
