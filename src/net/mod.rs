//! Networking shared by every integration (Apple services, anisette
//! servers, GitHub releases).

pub mod http;
pub mod websocket;

use std::fmt;

/// A transport failure (DNS, TCP, TLS, malformed HTTP). HTTP error
/// statuses are not errors at this layer; callers inspect `Response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetError(pub String);

impl NetError {
    pub fn transport(msg: impl Into<String>) -> Self {
        NetError(msg.into())
    }

    fn context(self, host: &str) -> Self {
        NetError(format!("{host}: {}", self.0))
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NetError {}

pub type NetResult<T> = Result<T, NetError>;
