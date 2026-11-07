//! Executable memory abstraction: POSIX mmap on Linux, VirtualAlloc on Windows.
use super::{AdiResult, fail};
use std::ffi::c_void;
pub const EXEC: u32 = 1;
pub const WRITE: u32 = 2;
pub const READ: u32 = 4;
pub struct Mapping {
    pub pointer: *mut c_void,
    pub length: usize,
    pub page: usize,
}
#[cfg(windows)]
#[repr(C)]
struct SystemInfo {
    architecture: u16,
    reserved: u16,
    page_size: u32,
    min: *mut c_void,
    max: *mut c_void,
    mask: usize,
    processors: u32,
    processor_type: u32,
    granularity: u32,
    level: u16,
    revision: u16,
}
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
    fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    fn GetSystemInfo(info: *mut SystemInfo);
    fn GetCurrentProcess() -> *mut c_void;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}
impl Mapping {
    pub fn new(span: usize) -> AdiResult<Self> {
        #[cfg(unix)]
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        #[cfg(windows)]
        let page = {
            let mut info = std::mem::MaybeUninit::<SystemInfo>::uninit();
            unsafe {
                GetSystemInfo(info.as_mut_ptr());
                info.assume_init().page_size as usize
            }
        };
        if page < 4096 || !page.is_power_of_two() {
            return Err(fail("unsupported host page size"));
        }
        let length = span
            .checked_add(page - 1)
            .map(|n| n & !(page - 1))
            .filter(|n| *n > 0)
            .ok_or_else(|| fail("invalid mapping span"))?;
        #[cfg(unix)]
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        #[cfg(windows)]
        let pointer = unsafe { VirtualAlloc(std::ptr::null_mut(), length, 0x1000 | 0x2000, 0x04) };
        #[cfg(unix)]
        let failed = pointer == libc::MAP_FAILED;
        #[cfg(windows)]
        let failed = pointer.is_null();
        if failed {
            return Err(fail("cannot allocate ADI memory"));
        }
        Ok(Self {
            pointer,
            length,
            page,
        })
    }
    pub fn protect(&self, offset: usize, length: usize, flags: u32) -> AdiResult<()> {
        if offset % self.page != 0
            || length % self.page != 0
            || offset.checked_add(length).is_none_or(|n| n > self.length)
        {
            return Err(fail("invalid memory protection range"));
        }
        if flags & EXEC != 0 && flags & WRITE != 0 {
            return Err(fail("writable executable ADI pages are forbidden"));
        }
        let address = unsafe { self.pointer.cast::<u8>().add(offset) }.cast();
        #[cfg(unix)]
        let result = unsafe {
            libc::mprotect(
                address,
                length,
                if flags & READ != 0 {
                    libc::PROT_READ
                } else {
                    0
                } | if flags & WRITE != 0 {
                    libc::PROT_WRITE
                } else {
                    0
                } | if flags & EXEC != 0 {
                    libc::PROT_EXEC
                } else {
                    0
                },
            )
        } == 0;
        #[cfg(windows)]
        let result = {
            let protection = match flags & 7 {
                0 => 0x01,
                READ => 0x02,
                WRITE | 6 => 0x04,
                EXEC => 0x10,
                5 => 0x20,
                _ => return Err(fail("invalid Windows protection flags")),
            };
            let mut old = 0;
            (unsafe { VirtualProtect(address, length, protection, &mut old) }) != 0
        };
        if !result {
            return Err(fail("cannot protect ADI memory"));
        }
        Ok(())
    }
    pub fn flush_code(&self, offset: usize, length: usize) -> AdiResult<()> {
        if offset.checked_add(length).is_none_or(|n| n > self.length) {
            return Err(fail("invalid instruction cache range"));
        }
        #[cfg(windows)]
        if unsafe {
            FlushInstructionCache(
                GetCurrentProcess(),
                self.pointer.cast::<u8>().add(offset).cast(),
                length,
            )
        } == 0
        {
            return Err(fail("cannot flush ADI instruction cache"));
        }
        #[cfg(all(unix, target_arch = "aarch64"))]
        unsafe {
            let base = self.pointer as usize + offset;
            let end = base + length;
            let ctr: u64;
            core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr);
            let dl = 4usize << ((ctr >> 16) & 15);
            let il = 4usize << (ctr & 15);
            for a in (base & !(dl - 1)..end).step_by(dl) {
                core::arch::asm!("dc cvau, {}",in(reg)a);
            }
            core::arch::asm!("dsb ish");
            for a in (base & !(il - 1)..end).step_by(il) {
                core::arch::asm!("ic ivau, {}",in(reg)a);
            }
            core::arch::asm!("dsb ish", "isb");
        }
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::munmap(self.pointer, self.length);
        }
        #[cfg(windows)]
        unsafe {
            VirtualFree(self.pointer, 0, 0x8000);
        }
    }
}
