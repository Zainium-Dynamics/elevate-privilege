//! pam_debug — syslog debug log hook.

use alloc::string::String;
use std::ffi::CString;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn log_debug(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = pamh.user().unwrap_or("unknown");
    let service = pamh.service();

    let extra = args.join(" ");
    let msg = format!("pam_debug: service={} user={} extra=[{}]", service, user, extra);
    let c_fmt = CString::new("%s").unwrap();
    let c_msg = CString::new(msg).unwrap();

    unsafe {
        libc::syslog(7, c_fmt.as_ptr(), c_msg.as_ptr()); // 7 = LOG_DEBUG
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("debug"),
        authenticate: Some(log_debug),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(log_debug),
        open_session: Some(log_debug),
        close_session: Some(log_debug),
        chauthtok: Some(log_debug),
    }
}
