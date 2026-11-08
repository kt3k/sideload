//! Login Keychain access through Security.framework's generic-password
//! API. Items are keyed by service `sideload` and the Apple ID as account.
//! The stored value is never logged.

use std::ffi::c_void;
use std::io;

use super::SERVICE;

type OsStatus = i32;
type ItemRef = *mut c_void;

const ERR_SEC_SUCCESS: OsStatus = 0;
const ERR_SEC_ITEM_NOT_FOUND: OsStatus = -25300;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainFindGenericPassword(
        keychain_or_array: *const c_void,
        service_name_length: u32,
        service_name: *const u8,
        account_name_length: u32,
        account_name: *const u8,
        password_length: *mut u32,
        password_data: *mut *mut c_void,
        item_ref: *mut ItemRef,
    ) -> OsStatus;
    fn SecKeychainAddGenericPassword(
        keychain: *const c_void,
        service_name_length: u32,
        service_name: *const u8,
        account_name_length: u32,
        account_name: *const u8,
        password_length: u32,
        password_data: *const c_void,
        item_ref: *mut ItemRef,
    ) -> OsStatus;
    fn SecKeychainItemModifyAttributesAndData(
        item_ref: ItemRef,
        attr_list: *const c_void,
        length: u32,
        data: *const c_void,
    ) -> OsStatus;
    fn SecKeychainItemFreeContent(attr_list: *mut c_void, data: *mut c_void) -> OsStatus;
    fn SecKeychainItemDelete(item_ref: ItemRef) -> OsStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: *const c_void);
}

fn fail(what: &str, status: OsStatus) -> io::Error {
    io::Error::other(format!("Keychain {what} failed (OSStatus {status})"))
}

fn len(s: &[u8]) -> io::Result<u32> {
    u32::try_from(s.len()).map_err(|_| io::Error::other("Keychain value too large"))
}

/// Finds the item; with `want_data`, also copies its data.
fn find(account: &str, want_data: bool) -> io::Result<Option<(ItemRef, Option<Vec<u8>>)>> {
    let mut data_len = 0u32;
    let mut data: *mut c_void = std::ptr::null_mut();
    let mut item: ItemRef = std::ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            std::ptr::null(),
            len(SERVICE.as_bytes())?,
            SERVICE.as_ptr(),
            len(account.as_bytes())?,
            account.as_ptr(),
            if want_data {
                &mut data_len
            } else {
                std::ptr::null_mut()
            },
            if want_data {
                &mut data
            } else {
                std::ptr::null_mut()
            },
            &mut item,
        )
    };
    match status {
        ERR_SEC_SUCCESS => {
            let bytes = (want_data && !data.is_null()).then(|| {
                let v = unsafe { std::slice::from_raw_parts(data as *const u8, data_len as usize) }
                    .to_vec();
                unsafe { SecKeychainItemFreeContent(std::ptr::null_mut(), data) };
                v
            });
            Ok(Some((item, bytes)))
        }
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        s => Err(fail("lookup", s)),
    }
}

struct Item(ItemRef);
impl Drop for Item {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

pub fn read(account: &str) -> io::Result<Option<Vec<u8>>> {
    Ok(find(account, true)?.and_then(|(item, data)| {
        drop(Item(item));
        data
    }))
}

pub fn write(account: &str, data: &[u8]) -> io::Result<()> {
    if let Some((item, _)) = find(account, false)? {
        let item = Item(item);
        let status = unsafe {
            SecKeychainItemModifyAttributesAndData(
                item.0,
                std::ptr::null(),
                len(data)?,
                data.as_ptr() as *const c_void,
            )
        };
        return match status {
            ERR_SEC_SUCCESS => Ok(()),
            s => Err(fail("update", s)),
        };
    }
    let status = unsafe {
        SecKeychainAddGenericPassword(
            std::ptr::null(),
            len(SERVICE.as_bytes())?,
            SERVICE.as_ptr(),
            len(account.as_bytes())?,
            account.as_ptr(),
            len(data)?,
            data.as_ptr() as *const c_void,
            std::ptr::null_mut(),
        )
    };
    match status {
        ERR_SEC_SUCCESS => Ok(()),
        s => Err(fail("add", s)),
    }
}

pub fn delete(account: &str) -> io::Result<bool> {
    let Some((item, _)) = find(account, false)? else {
        return Ok(false);
    };
    let item = Item(item);
    match unsafe { SecKeychainItemDelete(item.0) } {
        ERR_SEC_SUCCESS => Ok(true),
        s => Err(fail("delete", s)),
    }
}
