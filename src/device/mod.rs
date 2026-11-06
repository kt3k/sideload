//! Device Client (SPEC Section 10).
//!
//! - `usbmuxd`: list devices, read pair records, connect to device ports
//!   (Unix socket `/var/run/usbmuxd`, TCP 27015 on Windows).
//! - `lockdown`: lockdownd session (TLS with the pair record), device name,
//!   StartService.
//! - `afc`, `installation_proxy`, `misagent`: services used by delivery
//!   (SPEC Section 10.3).
//!
//! Reference: idevice (MIT). TODO: implement.

pub mod afc;
pub mod installation_proxy;
pub mod lockdown;
pub mod misagent;
pub mod usbmuxd;
