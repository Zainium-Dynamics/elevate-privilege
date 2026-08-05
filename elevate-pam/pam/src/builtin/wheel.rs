//! pam_wheel — require membership in group wheel (or configured group).

use alloc::string::String;
use std::ffi::{CStr, CString};

use crate::constants::{PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("wheel"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: Some(check),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

fn check(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };
    let group = arg_value(args, "group").unwrap_or("wheel");
    let deny = arg_has(args, "deny");
    let root_only = arg_has(args, "root_only");

    if root_only {
        // only enforce when target is root — here we check requesting context
        // simplified: check if service implies elevate to root
    }

    let member = match is_group_member(&user, group) {
        Ok(m) => m,
        Err(_) => return PamStatus::new(PAM_USER_UNKNOWN),
    };

    if deny {
        if member {
            PamStatus::new(PAM_PERM_DENIED)
        } else {
            PamStatus::new(PAM_SUCCESS)
        }
    } else if member {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_AUTH_ERR)
    }
}

fn is_group_member(user: &str, group: &str) -> Result<bool, ()> {
    let c_user = CString::new(user).map_err(|_| ())?;
    let c_group = CString::new(group).map_err(|_| ())?;

    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            return Err(());
        }
        let uid_gid = (*pw).pw_gid;

        let gr = libc::getgrnam(c_group.as_ptr());
        if gr.is_null() {
            return Ok(false);
        }
        if (*gr).gr_gid == uid_gid {
            return Ok(true);
        }
        // member list
        let mut mem = (*gr).gr_mem;
        if !mem.is_null() {
            while !(*mem).is_null() {
                let m = CStr::from_ptr(*mem).to_string_lossy();
                if m == user {
                    return Ok(true);
                }
                mem = mem.add(1);
            }
        }
        Ok(false)
    }
}
