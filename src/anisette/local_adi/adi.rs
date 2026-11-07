//! Typed ADI entry points. Mappings are owned by Adi and calls remain on its
//! constructing thread. Returned native buffers are copied and disposed.
use super::{AdiResult, fail, hooks, loader::Library, provisioning::Engine};
use std::{
    ffi::{CString, c_void},
    path::Path,
};
pub struct Adi {
    core: Library,
    store: Library,
}
const DSID: u64 = u64::MAX - 1;
fn status(code: i32, operation: &str) -> AdiResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(fail(format!("{operation} failed with ADI code {code}")))
    }
}
impl Adi {
    pub fn open(lib: &Path, android_id: &str) -> AdiResult<Self> {
        let read = |name: &str| {
            let p = lib.join(name);
            let m = std::fs::metadata(&p).map_err(|_| fail(format!("missing {name}")))?;
            if m.len() > 32 * 1024 * 1024 {
                return Err(fail("ADI library exceeds size limit"));
            }
            std::fs::read(&p).map_err(|_| fail(format!("cannot read {name}")))
        };
        let core = Library::load(&read("libCoreADI.so")?, &[])?;
        let store = Library::load(&read("libstoreservicescore.so")?, &[&core])?;
        let adi = Self { core, store };
        for entry in [
            "aslgmuibau",
            "rsegvyrt87",
            "uv5t6nhkui",
            "fy34trz2st",
            "jk24uiwqrg",
            "qi864985u0",
        ] {
            adi.address(entry)?;
        }
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(lib.as_os_str().as_bytes())
            .map_err(|_| fail("NUL in ADI library path"))?;
        let identifier = CString::new(android_id).map_err(|_| fail("NUL in Android identifier"))?;
        type PathFn = unsafe extern "C" fn(*const i8) -> i32;
        type IdFn = unsafe extern "C" fn(*const i8, u32) -> i32;
        let load: PathFn = unsafe { std::mem::transmute(adi.address("kq56gsgHG6")?) };
        let provisioning: PathFn = unsafe { std::mem::transmute(adi.address("nf92ngaK92")?) };
        let set_id: IdFn = unsafe { std::mem::transmute(adi.address("Sph98paBcz")?) };
        hooks::with_core(&adi.core, || unsafe {
            status(load(path.as_ptr()), "load library path")?;
            status(provisioning(path.as_ptr()), "set provisioning path")?;
            status(
                set_id(identifier.as_ptr(), android_id.len() as u32),
                "set Android identifier",
            )
        })?;
        Ok(adi)
    }
    fn address(&self, symbol: &str) -> AdiResult<usize> {
        self.store
            .symbol(symbol)
            .ok_or_else(|| fail(format!("missing ADI entry point {symbol}")))
    }
    fn dispose(&self, p: *mut u8) -> AdiResult<()> {
        if !p.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) -> i32 =
                unsafe { std::mem::transmute(self.address("jk24uiwqrg")?) };
            unsafe {
                f(p.cast());
            }
        }
        Ok(())
    }
    unsafe fn copy(&self, p: *mut u8, len: u32) -> AdiResult<Vec<u8>> {
        if p.is_null() || len == 0 || len > 4 * 1024 * 1024 {
            self.dispose(p)?;
            return Err(fail("invalid ADI output buffer"));
        }
        let out = unsafe { std::slice::from_raw_parts(p, len as usize) }.to_vec();
        self.dispose(p)?;
        Ok(out)
    }
}
impl Engine for Adi {
    fn is_provisioned(&mut self) -> AdiResult<bool> {
        let f: unsafe extern "C" fn(u64) -> i32 =
            unsafe { std::mem::transmute(self.address("aslgmuibau")?) };
        let code = hooks::with_core(&self.core, || unsafe { f(DSID) });
        match code {
            0 => Ok(true),
            -45061 => Ok(false),
            n => Err(fail(format!("query provisioning failed with ADI code {n}"))),
        }
    }
    fn start(&mut self, spim: &[u8]) -> AdiResult<(Vec<u8>, u32)> {
        type F = unsafe extern "C" fn(u64, *const u8, u32, *mut *mut u8, *mut u32, *mut u32) -> i32;
        let f: F = unsafe { std::mem::transmute(self.address("rsegvyrt87")?) };
        hooks::with_core(&self.core, || {
            let (mut p, mut len, mut session) = (std::ptr::null_mut(), 0, 0);
            let code = unsafe {
                f(
                    DSID,
                    spim.as_ptr(),
                    spim.len().try_into().map_err(|_| fail("spim too large"))?,
                    &mut p,
                    &mut len,
                    &mut session,
                )
            };
            if code != 0 {
                self.dispose(p)?;
                return Err(fail(format!(
                    "provisioning start failed with ADI code {code}"
                )));
            }
            match unsafe { self.copy(p, len) } {
                Ok(cpim) => Ok((cpim, session)),
                Err(error) => {
                    let destroy: unsafe extern "C" fn(u32) -> i32 =
                        unsafe { std::mem::transmute(self.address("fy34trz2st")?) };
                    unsafe {
                        destroy(session);
                    }
                    Err(error)
                }
            }
        })
    }
    fn finish(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> AdiResult<()> {
        type F = unsafe extern "C" fn(u32, *const u8, u32, *const u8, u32) -> i32;
        let f: F = unsafe { std::mem::transmute(self.address("uv5t6nhkui")?) };
        hooks::with_core(&self.core, || unsafe {
            status(
                f(
                    session,
                    ptm.as_ptr(),
                    ptm.len().try_into().map_err(|_| fail("ptm too large"))?,
                    tk.as_ptr(),
                    tk.len().try_into().map_err(|_| fail("tk too large"))?,
                ),
                "provisioning finish",
            )
        })
    }
    fn destroy(&mut self, session: u32) {
        if let Ok(address) = self.address("fy34trz2st") {
            let f: unsafe extern "C" fn(u32) -> i32 = unsafe { std::mem::transmute(address) };
            hooks::with_core(&self.core, || unsafe { f(session) });
        }
    }
    fn otp(&mut self) -> AdiResult<(Vec<u8>, Vec<u8>)> {
        type F = unsafe extern "C" fn(u64, *mut *mut u8, *mut u32, *mut *mut u8, *mut u32) -> i32;
        let f: F = unsafe { std::mem::transmute(self.address("qi864985u0")?) };
        hooks::with_core(&self.core, || {
            let (mut mid, mut mid_len, mut otp, mut otp_len) =
                (std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
            let code = unsafe { f(DSID, &mut mid, &mut mid_len, &mut otp, &mut otp_len) };
            if code != 0 {
                self.dispose(mid)?;
                self.dispose(otp)?;
                return Err(fail(format!("OTP request failed with ADI code {code}")));
            }
            let m = unsafe { self.copy(mid, mid_len) };
            let o = unsafe { self.copy(otp, otp_len) };
            Ok((m?, o?))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::workdir::WorkDir;
    #[test]
    #[ignore = "set SIDELOAD_ADI_LIBRARY_DIR to Apple APK library directory"]
    fn native_adi_initialization_smoke() {
        let source =
            std::env::var_os("SIDELOAD_ADI_LIBRARY_DIR").expect("set SIDELOAD_ADI_LIBRARY_DIR");
        let d = WorkDir::create(false).unwrap();
        for name in ["libstoreservicescore.so", "libCoreADI.so"] {
            std::fs::copy(Path::new(&source).join(name), d.path().join(name)).unwrap();
        }
        let mut adi = Adi::open(d.path(), "0123456789abcdef").unwrap();
        assert!(!adi.is_provisioned().unwrap());
    }
}
