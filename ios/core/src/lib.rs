//! Core of the Sideload iOS app (`ios/SPEC.md`): install IPAs onto the
//! device the app runs on and refresh them, over the loopback VPN.
//!
//! - `api`: the JSON Core Interface (Section 9); `ffi`: its C ABI.
//! - `ops`: install, refresh, forget, list (Section 7).
//! - `account`: login (7.2); `device`: the Device Link (3.3, 7.1).
//! - `registry`, `selfapp`, `profile`: the domain model (Section 4).

pub mod account;
pub mod api;
pub mod config;
pub mod device;
pub mod error;
pub mod ffi;
pub mod ops;
pub mod profile;
pub mod registry;
pub mod selfapp;
