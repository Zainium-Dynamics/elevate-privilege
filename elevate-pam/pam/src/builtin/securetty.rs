//! pam_securetty — root may only log in on secure ttys listed in /etc/securetty.

use alloc::string::String;
use std::fs;
use std::io::{BufRead, BufReader};

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("securetty"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: None,
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
    if user != "root" && !is_uid0(&user) {
        return PamStatus::new(PAM_SUCCESS);
    }

    let tty = match pamh.get_item_str(crate::types::ItemType::Tty) {
        Some(t) => t.to_string(),
        None => return PamStatus::new(PAM_SUCCESS), // no tty — allow (cron etc.)
    };

    let default_file = elevate_paths::get().securetty_file();
    let file = arg_value(args, "file").unwrap_or(&default_file);

    match tty_is_secure(&tty, file) {
        true => PamStatus::new(PAM_SUCCESS),
        false => PamStatus::new(PAM_AUTH_ERR),
    }
}

fn is_uid0(user: &str) -> bool {
    use std::ffi::CString;
    let Ok(c) = CString::new(user) else {
        return false;
    };
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        !pw.is_null() && (*pw).pw_uid == 0
    }
}

fn tty_is_secure(tty: &str, file: &str) -> bool {
    let tty_base = tty.trim_start_matches("/dev/");
    let Ok(f) = fs::File::open(file) else {
        // missing securetty — Linux-PAM historically allows
        return true;
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = line.trim_start_matches("/dev/");
        if entry == tty_base || line == tty {
            return true;
        }
    }
    false
}
