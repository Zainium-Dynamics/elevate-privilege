//! pam_shells — succeed if user's shell is listed in /etc/shells.

use alloc::string::String;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};
use crate::types::ItemType;

fn check_shell(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let username = match pamh.get_item_str(ItemType::User) {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_AUTH_ERR),
    };

    // Find user's shell from passwd
    let c_user = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return PamStatus::new(PAM_AUTH_ERR),
    };
    let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pwd.is_null() {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    let shell_ptr = unsafe { (*pwd).pw_shell };
    if shell_ptr.is_null() {
        return PamStatus::new(PAM_AUTH_ERR);
    }
    let user_shell = unsafe { std::ffi::CStr::from_ptr(shell_ptr) }.to_string_lossy();

    // Check the configured shells file
    if let Ok(file) = File::open(elevate_paths::get().shells_file()) {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim();
            if !line.starts_with('#') && line == user_shell {
                return PamStatus::new(PAM_SUCCESS);
            }
        }
    }

    PamStatus::new(PAM_AUTH_ERR)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("shells"),
        authenticate: Some(check_shell),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(check_shell),
        open_session: None,
        close_session: None,
        chauthtok: Some(check_shell),
    }
}
