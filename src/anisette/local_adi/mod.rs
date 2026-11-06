//! Local ADI (SPEC Section 9.1): load `libstoreservicescore.so` and
//! `libCoreADI.so` from the Apple Music for Android APK and call them
//! in-process. See docs/LOCAL_ADI.md for how upstream does it.
//!
//! Layout:
//! - `download`: fetch the APK and extract the two libraries for this arch.
//! - `elf`: minimal ELF64 parser (program headers, dynamic section, symbols,
//!   relocations).
//! - `loader`: map PT_LOAD segments, apply relocations, resolve imports
//!   against `hooks`.
//! - `hooks`: libc / bionic replacements exposed to the Android library.
//! - `adi`: typed wrappers over the obfuscated ADI entry points.
//! - `provisioning`: device identity (`device.json`) and the
//!   midStartProvisioning / midFinishProvisioning exchange.
//!
//! TODO: implement.

pub mod adi;
pub mod download;
pub mod elf;
pub mod hooks;
pub mod loader;
pub mod provisioning;
