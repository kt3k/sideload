//! Device Client (SPEC Section 10).
//!
//! - `usbmuxd`: list devices, read pair records, connect to device ports
//!   (Unix socket `/var/run/usbmuxd`, TCP 27015 on Windows).
//! - `lockdown`: lockdownd session (TLS with the pair record), device name,
//!   StartService.
//! - `afc`, `installation_proxy`, `misagent`: services used by delivery
//!   (SPEC Section 10.3).
//! - `house_arrest`: AFC into an app's container (SPEC Section 10.4).
//!
//! - `pairing`: parse usbmuxd pairing records.
//! - `connect`: reach a device port through usbmuxd or over TCP.
//!
//! Reference: idevice (MIT).

pub mod afc;
pub mod connect;
pub mod house_arrest;
pub mod installation_proxy;
pub mod lockdown;
pub mod misagent;
pub mod pairing;
pub mod usbmuxd;
