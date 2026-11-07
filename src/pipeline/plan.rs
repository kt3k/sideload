//! Install Plan (SPEC Sections 4.1.11, 7.5, 15.2).
//!
//! TODO: `build_plan` once the Developer Service Client exists, and the
//! dry-run printer.

use crate::ErrorCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAction {
    None,
    Register,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAction {
    Reuse { serial: String },
    Create,
    RevokeAndCreate { serials: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAppId {
    pub identifier: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAppGroup {
    pub identifier: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub team_id: String,
    pub team_name: String,
    pub device_udid: Option<String>,
    pub device_action: DeviceAction,
    pub certificate_action: CertificateAction,
    pub app_ids: Vec<PlannedAppId>,
    /// `None`: Apple reported no quota (paid teams).
    pub available_quantity: Option<u32>,
    pub max_quantity: Option<u32>,
    pub app_group: PlannedAppGroup,
    /// `None` when feasible; otherwise the reason (SPEC Section 4.1.11).
    pub blocker: Option<(ErrorCode, String)>,
}

impl InstallPlan {
    pub fn app_ids_to_register(&self) -> usize {
        self.app_ids.iter().filter(|a| !a.exists).count()
    }

    pub fn feasible(&self) -> bool {
        self.blocker.is_none()
    }
}
