//! pam_nologin — deny non-root when /etc/nologin exists.

use alloc::string::String;
use std::fs;
use std::path::Path;

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("nologin"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: Some(check),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

fn check(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
    let default_path = elevate_paths::get().nologin_file();
    let path = arg_value(args, "file").unwrap_or(&default_path);
    if !Path::new(path).exists() {
        return PamStatus::new(PAM_SUCCESS);
    }

    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };

    // root (uid 0) always allowed
    if is_root_user(&user) {
        return PamStatus::new(PAM_SUCCESS);
    }

    if flags & crate::constants::PAM_SILENT == 0 {
        if let Ok(msg) = fs::read_to_string(path) {
            crate::log::info(pamh, &msg);
        }
    }
    let _ = args;
    PamStatus::new(PAM_AUTH_ERR)
}

fn is_root_user(user: &str) -> bool {
    if user == "root" {
        return true;
    }
    use std::ffi::CString;
    let Ok(c) = CString::new(user) else {
        return false;
    };
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        !pw.is_null() && (*pw).pw_uid == 0
    }
}

#[allow(dead_code)]
fn _unknown() -> PamStatus {
    PamStatus::new(PAM_USER_UNKNOWN)
}
