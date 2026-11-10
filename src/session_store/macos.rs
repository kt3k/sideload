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

// ---------------------------------------------------------------- listing
//
// Listing uses SecItemCopyMatching, which returns attributes only (never
// the stored data), so it does not trigger a Keychain access prompt.

type CfRef = *const c_void;
type CfIndex = isize;
type CfTypeId = usize;
const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

/// Opaque CFDictionary callback tables; only their addresses are used.
#[repr(C)]
struct Callbacks {
    _private: [u8; 0],
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CfRef;
    static kSecClassGenericPassword: CfRef;
    static kSecAttrService: CfRef;
    static kSecAttrAccount: CfRef;
    static kSecMatchLimit: CfRef;
    static kSecMatchLimitAll: CfRef;
    static kSecReturnAttributes: CfRef;
    fn SecItemCopyMatching(query: CfRef, result: *mut CfRef) -> OsStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: CfRef;
    static kCFTypeDictionaryKeyCallBacks: Callbacks;
    static kCFTypeDictionaryValueCallBacks: Callbacks;
    fn CFDictionaryCreate(
        allocator: CfRef,
        keys: *const CfRef,
        values: *const CfRef,
        count: CfIndex,
        key_callbacks: *const Callbacks,
        value_callbacks: *const Callbacks,
    ) -> CfRef;
    fn CFStringCreateWithBytes(
        allocator: CfRef,
        bytes: *const u8,
        count: CfIndex,
        encoding: u32,
        external: u8,
    ) -> CfRef;
    fn CFGetTypeID(cf: CfRef) -> CfTypeId;
    fn CFArrayGetTypeID() -> CfTypeId;
    fn CFDictionaryGetTypeID() -> CfTypeId;
    fn CFStringGetTypeID() -> CfTypeId;
    fn CFArrayGetCount(array: CfRef) -> CfIndex;
    fn CFArrayGetValueAtIndex(array: CfRef, index: CfIndex) -> CfRef;
    fn CFDictionaryGetValue(dict: CfRef, key: CfRef) -> CfRef;
    fn CFStringGetLength(s: CfRef) -> CfIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CfIndex, encoding: u32) -> CfIndex;
    fn CFStringGetCString(s: CfRef, buffer: *mut u8, size: CfIndex, encoding: u32) -> u8;
}

/// Releases a CoreFoundation object on drop (null is ignored).
struct Owned(CfRef);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn cf_string_to_rust(s: CfRef) -> Option<String> {
    if s.is_null() || unsafe { CFGetTypeID(s) != CFStringGetTypeID() } {
        return None;
    }
    let size = unsafe { CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), UTF8) } + 1;
    let mut buf = vec![0u8; usize::try_from(size).ok()?];
    if unsafe { CFStringGetCString(s, buf.as_mut_ptr(), size, UTF8) } == 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// The account names (Apple IDs) of every item with service `sideload`.
pub fn accounts() -> io::Result<Vec<String>> {
    let service = Owned(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            SERVICE.as_ptr(),
            SERVICE.len() as CfIndex,
            UTF8,
            0,
        )
    });
    if service.0.is_null() {
        return Err(io::Error::other("Keychain query setup failed"));
    }
    let (keys, values) = unsafe {
        (
            [
                kSecClass,
                kSecAttrService,
                kSecMatchLimit,
                kSecReturnAttributes,
            ],
            [
                kSecClassGenericPassword,
                service.0,
                kSecMatchLimitAll,
                kCFBooleanTrue,
            ],
        )
    };
    let query = Owned(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as CfIndex,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    });
    if query.0.is_null() {
        return Err(io::Error::other("Keychain query setup failed"));
    }
    let mut result: CfRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.0, &mut result) };
    let result = Owned(result);
    match status {
        ERR_SEC_SUCCESS => {}
        ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        s => return Err(fail("listing", s)),
    }
    if result.0.is_null() || unsafe { CFGetTypeID(result.0) != CFArrayGetTypeID() } {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..unsafe { CFArrayGetCount(result.0) } {
        let item = unsafe { CFArrayGetValueAtIndex(result.0, i) };
        if item.is_null() || unsafe { CFGetTypeID(item) != CFDictionaryGetTypeID() } {
            continue;
        }
        let account = unsafe { CFDictionaryGetValue(item, kSecAttrAccount) };
        if let Some(name) = cf_string_to_rust(account) {
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    Ok(out)
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
