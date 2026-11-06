//! Error codes and the error type (SPEC Section 13.1).

use std::fmt;

use crate::pipeline::Phase;

/// Error codes from SPEC Section 13.1. `as_str` returns the stable
/// snake_case name printed in `error[<code>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Argument / Input Failures
    InvalidArguments,
    IpaNotFound,
    IpaInvalid,
    BundleInvalid,
    OutputWriteFailed,
    // Authentication Failures
    AdiDownloadFailed,
    AnisetteUnavailable,
    CredentialsUnavailable,
    LoginFailed,
    TwoFactorFailed,
    // Account Resource Failures
    TeamNotFound,
    DeviceLimitReached,
    DeviceNotFound,
    CertificateLimitReached,
    CertificateNotFound,
    AppIdQuotaExceeded,
    AppIdNotFound,
    AmbiguousMatch,
    ProfileDownloadFailed,
    AppleApiError,
    AppleTransportError,
    // Device Failures
    NoDeviceConnected,
    MultipleDevicesConnected,
    DeviceNotConnected,
    DeviceNotPaired,
    DeviceTransportError,
    InstallFailed,
    // Artifact Failures
    SigningFailed,
    // Unexpected Failures
    InternalError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            InvalidArguments => "invalid_arguments",
            IpaNotFound => "ipa_not_found",
            IpaInvalid => "ipa_invalid",
            BundleInvalid => "bundle_invalid",
            OutputWriteFailed => "output_write_failed",
            AdiDownloadFailed => "adi_download_failed",
            AnisetteUnavailable => "anisette_unavailable",
            CredentialsUnavailable => "credentials_unavailable",
            LoginFailed => "login_failed",
            TwoFactorFailed => "two_factor_failed",
            TeamNotFound => "team_not_found",
            DeviceLimitReached => "device_limit_reached",
            DeviceNotFound => "device_not_found",
            CertificateLimitReached => "certificate_limit_reached",
            CertificateNotFound => "certificate_not_found",
            AppIdQuotaExceeded => "app_id_quota_exceeded",
            AppIdNotFound => "app_id_not_found",
            AmbiguousMatch => "ambiguous_match",
            ProfileDownloadFailed => "profile_download_failed",
            AppleApiError => "apple_api_error",
            AppleTransportError => "apple_transport_error",
            NoDeviceConnected => "no_device_connected",
            MultipleDevicesConnected => "multiple_devices_connected",
            DeviceNotConnected => "device_not_connected",
            DeviceNotPaired => "device_not_paired",
            DeviceTransportError => "device_transport_error",
            InstallFailed => "install_failed",
            SigningFailed => "signing_failed",
            InternalError => "internal_error",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error reported to the user as `error[<code>] (<phase>): <message>`
/// (SPEC Section 12). `phase` is set only by `install`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    pub phase: Option<Phase>,
    pub message: String,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error {
            code,
            phase: None,
            message: message.into(),
        }
    }

    pub fn with_phase(mut self, phase: Phase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Placeholder for functionality the scaffold does not implement yet.
    pub fn not_implemented(what: &str) -> Self {
        Error::new(
            ErrorCode::InternalError,
            format!("{what} is not implemented yet"),
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.phase {
            Some(phase) => write!(f, "error[{}] ({}): {}", self.code, phase, self.message),
            None => write!(f, "error[{}]: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_without_phase() {
        let e = Error::new(ErrorCode::TeamNotFound, "No matching team found.");
        assert_eq!(
            e.to_string(),
            "error[team_not_found]: No matching team found."
        );
    }

    #[test]
    fn display_with_phase() {
        let e = Error::new(ErrorCode::SigningFailed, "bad").with_phase(Phase::Signing);
        assert_eq!(e.to_string(), "error[signing_failed] (Signing): bad");
    }
}
