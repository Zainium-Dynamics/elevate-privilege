//! pam_localuser — check if user exists in local /etc/passwd.

use alloc::string::String;

use crate::constants::{PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn check_local(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let username = match pamh.user() {
        Some(u) => u,
        None => return PamStatus::new(PAM_USER_UNKNOWN),
    };

    let c_user = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return PamStatus::new(PAM_USER_UNKNOWN),
    };

    let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if !pwd.is_null() {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_USER_UNKNOWN)
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("localuser"),
        authenticate: Some(check_local),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(check_local),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
