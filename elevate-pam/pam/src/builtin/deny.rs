//! pam_deny — always fails.

use alloc::string::String;

use crate::constants::PAM_AUTH_ERR;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn deny(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    PamStatus::new(PAM_AUTH_ERR)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("deny"),
        authenticate: Some(deny),
        setcred: Some(deny),
        acct_mgmt: Some(deny),
        open_session: Some(deny),
        close_session: Some(deny),
        chauthtok: Some(deny),
    }
}
