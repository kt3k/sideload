//! Install pipeline (SPEC Section 7).
//!
//! The phases are implemented in `commands::install`; this module owns the
//! shared vocabulary (phases, modes) and the Install Plan.

pub mod plan;
pub mod workdir;

use std::fmt;

/// Install phases, in execution order (SPEC Section 7.2). The names are part
/// of the output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    ValidatingArguments,
    SelectingDevice,
    DownloadingApp,
    PreparingBundle,
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
    /// Number of phases in SPEC Section 7.2.
    pub const COUNT: usize = 16;

    /// 1-based position in SPEC Section 7.2 (the enum is declared in order).
    pub fn number(self) -> usize {
        self as usize + 1
    }

    pub fn as_str(self) -> &'static str {
        use Phase::*;
        match self {
            ValidatingArguments => "ValidatingArguments",
            DownloadingApp => "DownloadingApp",
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

#[cfg(test)]
mod tests {
    use super::Phase;

    #[test]
    fn phase_numbers_follow_spec_order() {
        assert_eq!(Phase::ValidatingArguments.number(), 1);
        assert_eq!(Phase::PreparingAnisette.number(), 5);
        assert_eq!(Phase::Planning.number(), 8);
        assert_eq!(Phase::CleaningUp.number(), Phase::COUNT);
    }
}
