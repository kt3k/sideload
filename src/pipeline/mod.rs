//! Install pipeline (SPEC Section 7).
//!
//! The phases are implemented in `commands::install`; this module owns the
//! shared vocabulary (phases, modes) and the Install Plan.

pub mod plan;

use std::fmt;

/// Install phases, in execution order (SPEC Section 7.2). The names are part
/// of the output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    ValidatingArguments,
    PreparingBundle,
    SelectingDevice,
    PreparingAnisette,
    LoggingIn,
    SelectingTeam,
    Planning,
    RegisteringDevice,
    PreparingCertificate,
    RegisteringAppIds,
    ConfiguringAppGroup,
    FetchingProfiles,
    Signing,
    Delivering,
    CleaningUp,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        use Phase::*;
        match self {
            ValidatingArguments => "ValidatingArguments",
            PreparingBundle => "PreparingBundle",
            SelectingDevice => "SelectingDevice",
            PreparingAnisette => "PreparingAnisette",
            LoggingIn => "LoggingIn",
            SelectingTeam => "SelectingTeam",
            Planning => "Planning",
            RegisteringDevice => "RegisteringDevice",
            PreparingCertificate => "PreparingCertificate",
            RegisteringAppIds => "RegisteringAppIds",
            ConfiguringAppGroup => "ConfiguringAppGroup",
            FetchingProfiles => "FetchingProfiles",
            Signing => "Signing",
            Delivering => "Delivering",
            CleaningUp => "CleaningUp",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Install modes (SPEC Section 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Install,
    Output,
    DryRun,
}
