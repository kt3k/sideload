//! Errors of the core: the CLI's error codes (SPEC Section 13.1) plus the
//! phase as a name, because the app has phases the CLI does not
//! (`ios/SPEC.md` Section 6).

use sideload::{Error, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub code: ErrorCode,
    pub phase: Option<String>,
    pub message: String,
}

pub type CResult<T> = Result<T, CoreError>;

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> CoreError {
        CoreError {
            code,
            phase: None,
            message: message.into(),
        }
    }

    /// Sets the phase unless one is already set.
    pub fn at(mut self, phase: &str) -> CoreError {
        if self.phase.is_none() {
            self.phase = Some(phase.to_owned());
        }
        self
    }
}

impl From<Error> for CoreError {
    fn from(e: Error) -> CoreError {
        CoreError {
            code: e.code,
            phase: e.phase.map(|p| p.as_str().to_owned()),
            message: e.message,
        }
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.phase {
            Some(p) => write!(f, "error[{}] ({p}): {}", self.code, self.message),
            None => write!(f, "error[{}]: {}", self.code, self.message),
        }
    }
}

/// Tags an error with the phase it happened in.
pub trait At<T> {
    fn at(self, phase: &str) -> CResult<T>;
}

impl<T> At<T> for sideload::Result<T> {
    fn at(self, phase: &str) -> CResult<T> {
        self.map_err(|e| CoreError::from(e).at(phase))
    }
}

impl<T> At<T> for CResult<T> {
    fn at(self, phase: &str) -> CResult<T> {
        self.map_err(|e| e.at(phase))
    }
}

pub fn internal(message: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::InternalError, message)
}

pub fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::InvalidArguments, message)
}

/// Phase names of `ios/SPEC.md` Section 6 that the CLI does not have.
pub mod phase {
    pub const CONNECTING_DEVICE: &str = "ConnectingDevice";
    pub const REFRESHING_APP: &str = "RefreshingApp";
    pub const INSTALLING_PROFILES: &str = "InstallingProfiles";
}

#[cfg(test)]
mod tests {
    use super::*;
    use sideload::pipeline::Phase;

    #[test]
    fn keeps_first_phase() {
        let e: CResult<()> =
            Err(Error::new(ErrorCode::SigningFailed, "x").with_phase(Phase::Signing)).at("Other");
        let e = e.unwrap_err();
        assert_eq!(e.phase.as_deref(), Some("Signing"));
        assert_eq!(e.to_string(), "error[signing_failed] (Signing): x");
        let e = CoreError::new(ErrorCode::InternalError, "y")
            .at("A")
            .at("B");
        assert_eq!(e.phase.as_deref(), Some("A"));
    }
}
