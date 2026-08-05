//! pam_rootok — succeed if real UID is 0.

use alloc::string::String;

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn auth(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_AUTH_ERR)
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("rootok"),
        authenticate: Some(auth),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(auth),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
