//! pam_permit — always succeeds.

use alloc::string::String;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn ok(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("permit"),
        authenticate: Some(ok),
        setcred: Some(ok),
        acct_mgmt: Some(ok),
        open_session: Some(ok),
        close_session: Some(ok),
        chauthtok: Some(ok),
    }
}
