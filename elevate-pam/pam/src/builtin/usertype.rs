//! pam_usertype — classify user as regular or system user based on UID thresholds.

use alloc::string::String;

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn check_usertype(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let username = match pamh.user() {
        Some(u) => u,
        None => return PamStatus::new(PAM_AUTH_ERR),
    };

    let c_user = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return PamStatus::new(PAM_AUTH_ERR),
    };

    let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pwd.is_null() {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    let uid = unsafe { (*pwd).pw_uid };
    let is_sys = uid < 1000;

    let target_type = args.first().map(|s| s.as_str()).unwrap_or("regular");

    let ok = match target_type {
        "system" | "sys" => is_sys,
        "regular" | "normal" => !is_sys,
        _ => true,
    };

    if ok {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_AUTH_ERR)
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("usertype"),
        authenticate: Some(check_usertype),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(check_usertype),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
