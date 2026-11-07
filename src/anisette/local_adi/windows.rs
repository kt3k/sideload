//! System V -> Windows CRT adapters for Android x86_64 ADI. Never expose a
//! Windows-ABI function address directly to Android code. Paths are UTF-8 in
//! Android and converted to UTF-16 before calling the CRT.
use super::abi::native_function;
use std::{
    cell::Cell,
    ffi::{CStr, c_char, c_void},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg_attr(not(target_feature = "crt-static"), link(name = "msvcrt"))]
#[cfg_attr(target_feature = "crt-static", link(name = "libcmt"))]
unsafe extern "C" {
    fn _errno() -> *mut i32;
    fn _wmkdir(path: *const u16) -> i32;
    fn _wchmod(path: *const u16, mode: i32) -> i32;
    fn _umask(mode: i32) -> i32;
    fn _chsize_s(fd: i32, length: i64) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileAttributesW(path: *const u16) -> u32;
}
thread_local! {static ERRNO:Cell<i32>=const {Cell::new(0)};}
fn set_errno(code: i32) {
    ERRNO.with(|e| e.set(code));
}
fn errno_from_crt() {
    let e = unsafe { *_errno() };
    set_errno(match e {
        38 => 36,
        40 => 38,
        41 => 39,
        42 => 84,
        other => other,
    });
}
fn status(n: i32) -> i32 {
    if n < 0 {
        errno_from_crt();
    }
    n
}
unsafe fn wide(path: *const c_char) -> Option<Vec<u16>> {
    if path.is_null() {
        set_errno(14);
        return None;
    }
    let Ok(text) = unsafe { CStr::from_ptr(path) }.to_str() else {
        set_errno(84);
        return None;
    };
    Some(text.encode_utf16().chain([0]).collect())
}
// Android's Linux x86_64 stat layout (144 bytes), independent of CRT stat64.
#[repr(C)]
#[derive(Default, Debug)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}
#[repr(C)]
#[derive(Default, Debug)]
struct AndroidStat {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    pad: u32,
    rdevice: u64,
    size: i64,
    block_size: i64,
    blocks: i64,
    access: Timespec,
    modified: Timespec,
    changed: Timespec,
    reserved: [i64; 3],
}
impl AndroidStat {
    fn from_crt(s: &libc::stat) -> Self {
        Self {
            device: s.st_dev as u64,
            inode: s.st_ino as u64,
            links: s.st_nlink as u64,
            mode: s.st_mode as u32,
            size: s.st_size,
            block_size: 4096,
            blocks: s.st_size.saturating_add(511) / 512,
            access: Timespec {
                seconds: s.st_atime,
                nanoseconds: 0,
            },
            modified: Timespec {
                seconds: s.st_mtime,
                nanoseconds: 0,
            },
            changed: Timespec {
                seconds: s.st_ctime,
                nanoseconds: 0,
            },
            ..Default::default()
        }
    }
}
#[repr(C)]
struct AndroidTimeval {
    seconds: i64,
    microseconds: i64,
}
fn open_flags(flags: i32) -> Option<i32> {
    // Reject operations the CRT cannot reproduce instead of treating Android
    // bits as CRT flags (O_CREAT in Android is O_TEMPORARY in the CRT).
    let allowed = 3 | 0x40 | 0x80 | 0x200 | 0x400 | 0x80000 | 0x20000;
    if flags & !allowed != 0 || flags & 3 == 3 {
        return None;
    }
    Some(
        (flags & 3)
            | libc::O_BINARY
            | libc::O_NOINHERIT
            | if flags & 0x40 != 0 { libc::O_CREAT } else { 0 }
            | if flags & 0x80 != 0 { libc::O_EXCL } else { 0 }
            | if flags & 0x200 != 0 { libc::O_TRUNC } else { 0 }
            | if flags & 0x400 != 0 {
                libc::O_APPEND
            } else {
                0
            },
    )
}
native_function! {
    unsafe fn errno() -> *mut i32 {
        ERRNO.with(Cell::as_ptr)
    }
}
native_function! {
    unsafe fn open(path: *const c_char, flags: i32, mode: u32) -> i32 {
        let Some(path) = (unsafe { wide(path) }) else {
            return -1;
        };
        let Some(native) = open_flags(flags) else {
            set_errno(22);
            return -1;
        };
        if flags & 0x20000 != 0 {
            let attrs = unsafe { GetFileAttributesW(path.as_ptr()) };
            if attrs != u32::MAX && attrs & 0x400 != 0 {
                set_errno(40);
                return -1;
            }
        }
        let mode = if mode & 0o400 != 0 { libc::S_IREAD } else { 0 }
            | if mode & 0o200 != 0 { libc::S_IWRITE } else { 0 };
        status(unsafe { libc::wopen(path.as_ptr(), native, mode) })
    }
}
native_function! {
    unsafe fn close(fd: i32) -> i32 {
        status(unsafe { libc::close(fd) })
    }
}
native_function! {
    unsafe fn read(fd: i32, bytes: *mut c_void, count: usize) -> isize {
        if count > i32::MAX as usize {
            set_errno(22);
            return -1;
        }
        status(unsafe { libc::read(fd, bytes, count as u32) }) as isize
    }
}
native_function! {
    unsafe fn write(fd: i32, bytes: *const c_void, count: usize) -> isize {
        if count > i32::MAX as usize {
            set_errno(22);
            return -1;
        }
        status(unsafe { libc::write(fd, bytes, count as u32) }) as isize
    }
}
native_function! {
    unsafe fn mkdir(path: *const c_char, _mode: u32) -> i32 {
        let Some(path) = (unsafe { wide(path) }) else {
            return -1;
        };
        status(unsafe { _wmkdir(path.as_ptr()) })
    }
}
native_function! {
    unsafe fn chmod(path: *const c_char, mode: u32) -> i32 {
        let Some(path) = (unsafe { wide(path) }) else {
            return -1;
        };
        let mode = if mode & 0o400 != 0 { libc::S_IREAD } else { 0 }
            | if mode & 0o200 != 0 { libc::S_IWRITE } else { 0 };
        status(unsafe { _wchmod(path.as_ptr(), mode) })
    }
}
native_function! {
    unsafe fn umask(mode: u32) -> u32 {
        let old = unsafe { _umask(mode as i32 & 0o600) };
        old as u32
    }
}
native_function! {
    unsafe fn truncate(fd: i32, length: i64) -> i32 {
        if length < 0 {
            set_errno(22);
            return -1;
        }
        let n = unsafe { _chsize_s(fd, length) };
        if n == 0 {
            0
        } else {
            errno_from_crt();
            -1
        }
    }
}
native_function! {
    unsafe fn lstat(path: *const c_char, out: *mut AndroidStat) -> i32 {
        if out.is_null() {
            set_errno(14);
            return -1;
        }
        let Some(path) = (unsafe { wide(path) }) else {
            return -1;
        };
        let mut native = std::mem::MaybeUninit::uninit();
        let n = status(unsafe { libc::wstat(path.as_ptr(), native.as_mut_ptr()) });
        if n != 0 {
            return n;
        }
        let mut translated = AndroidStat::from_crt(&unsafe { native.assume_init() });
        let attrs = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attrs != u32::MAX && attrs & 0x400 != 0 {
            translated.mode = (translated.mode & !0xf000) | 0xa000;
        }
        unsafe {
            out.write(translated);
        }
        0
    }
}
native_function! {
    unsafe fn fstat(fd: i32, out: *mut AndroidStat) -> i32 {
        if out.is_null() {
            set_errno(14);
            return -1;
        }
        let mut native = std::mem::MaybeUninit::uninit();
        let n = status(unsafe { libc::fstat(fd, native.as_mut_ptr()) });
        if n != 0 {
            return n;
        }
        unsafe {
            out.write(AndroidStat::from_crt(&native.assume_init()));
        }
        0
    }
}
native_function! {
    unsafe fn gettimeofday(out: *mut AndroidTimeval, _zone: *mut c_void) -> i32 {
        if out.is_null() {
            return 0;
        }
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            set_errno(22);
            return -1;
        };
        unsafe {
            out.write(AndroidTimeval {
                seconds: now.as_secs() as i64,
                microseconds: now.subsec_micros() as i64,
            });
        }
        0
    }
}
native_function! {
    unsafe fn malloc(n: usize) -> *mut c_void {
        unsafe { libc::malloc(n) }
    }
}
native_function! {
    unsafe fn calloc(n: usize, size: usize) -> *mut c_void {
        unsafe { libc::calloc(n, size) }
    }
}
native_function! {
    unsafe fn realloc(p: *mut c_void, n: usize) -> *mut c_void {
        unsafe { libc::realloc(p, n) }
    }
}
native_function! {
    unsafe fn free(p: *mut c_void) -> () {
        unsafe { libc::free(p) }
    }
}
native_function! {
    unsafe fn memcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void {
        unsafe { libc::memcpy(d, s, n) }
    }
}
native_function! {
    unsafe fn memmove(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void {
        unsafe { libc::memmove(d, s, n) }
    }
}
native_function! {
    unsafe fn memset(d: *mut c_void, v: i32, n: usize) -> *mut c_void {
        unsafe { libc::memset(d, v, n) }
    }
}
native_function! {
    unsafe fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
        unsafe { libc::memcmp(a, b, n) }
    }
}
native_function! {
    unsafe fn strlen(p: *const c_char) -> usize {
        unsafe { libc::strlen(p) }
    }
}
native_function! {
    unsafe fn strcmp(a: *const c_char, b: *const c_char) -> i32 {
        unsafe { libc::strcmp(a, b) }
    }
}
native_function! {
    unsafe fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> i32 {
        unsafe { libc::strncmp(a, b, n) }
    }
}
native_function! {
    unsafe fn strcpy(d: *mut c_char, s: *const c_char) -> *mut c_char {
        unsafe { libc::strcpy(d, s) }
    }
}
native_function! {
    unsafe fn strncpy(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char {
        unsafe { libc::strncpy(d, s, n) }
    }
}
native_function! {
    unsafe fn abort() -> ! {
        std::process::abort()
    }
}
pub fn resolve(name: &str) -> Option<usize> {
    Some(match name {
        "__errno" => errno as *const () as usize,
        "open" => open as *const () as usize,
        "close" => close as *const () as usize,
        "read" => read as *const () as usize,
        "write" => write as *const () as usize,
        "mkdir" => mkdir as *const () as usize,
        "chmod" => chmod as *const () as usize,
        "umask" => umask as *const () as usize,
        "ftruncate" => truncate as *const () as usize,
        "lstat" => lstat as *const () as usize,
        "fstat" => fstat as *const () as usize,
        "gettimeofday" => gettimeofday as *const () as usize,
        "malloc" => malloc as *const () as usize,
        "calloc" => calloc as *const () as usize,
        "realloc" => realloc as *const () as usize,
        "free" => free as *const () as usize,
        "memcpy" => memcpy as *const () as usize,
        "memmove" => memmove as *const () as usize,
        "memset" => memset as *const () as usize,
        "memcmp" => memcmp as *const () as usize,
        "strlen" => strlen as *const () as usize,
        "strcmp" => strcmp as *const () as usize,
        "strncmp" => strncmp as *const () as usize,
        "strcpy" => strcpy as *const () as usize,
        "strncpy" => strncpy as *const () as usize,
        "abort" | "__stack_chk_fail" => abort as *const () as usize,
        _ => return None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn android_stat_and_open_flag_layout() {
        assert_eq!(std::mem::size_of::<AndroidStat>(), 144);
        assert_eq!(std::mem::offset_of!(AndroidStat, size), 48);
        assert_eq!(std::mem::offset_of!(AndroidStat, access), 72);
        let flags = open_flags(0x40 | 0x200 | 2).unwrap();
        assert!(flags & libc::O_CREAT != 0);
        assert!(flags & libc::O_TRUNC != 0);
        assert!(flags & libc::O_BINARY != 0);
        assert!(flags & libc::O_TEMPORARY == 0);
        assert!(open_flags(0x10000).is_none());
    }
    #[test]
    fn utf8_file_operations_through_sysv_hooks() {
        let d = crate::pipeline::workdir::WorkDir::create(false).unwrap();
        let path = d.path().join("ADI-日本語.dat");
        let path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let fd = unsafe { open(path.as_ptr(), 0x40 | 0x200 | 2, 0o600) };
        assert!(fd >= 0);
        assert_eq!(unsafe { write(fd, b"data".as_ptr().cast(), 4) }, 4);
        let mut stat = AndroidStat::default();
        assert_eq!(unsafe { fstat(fd, &mut stat) }, 0);
        assert_eq!(stat.size, 4);
        assert_eq!(unsafe { truncate(fd, 2) }, 0);
        assert_eq!(unsafe { close(fd) }, 0);
        assert_eq!(
            std::fs::read(d.path().join("ADI-日本語.dat")).unwrap(),
            b"da"
        );
    }
}
