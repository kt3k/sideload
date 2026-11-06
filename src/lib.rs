//! Sideload CLI. See `SPEC.md` for the behavior contract and
//! `docs/ARCHITECTURE.md` for the module map.

// Interface layer (SPEC Section 3.2)
pub mod cli;
pub mod output;

// Configuration layer
pub mod config;
pub mod credentials;

// Coordination layer
pub mod commands;
pub mod pipeline;

// Integration layer
pub mod anisette;
pub mod apple;
pub mod device;
pub mod net;
pub mod sidestore;

// Artifact layer
pub mod bundle;
pub mod sign;

// Shared building blocks (in-tree replacements for external crates)
pub mod crypto;
pub mod formats;

pub mod error;

pub use error::{Error, ErrorCode, Result};
