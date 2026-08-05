//! pam_warn — syslog warning logger.

use alloc::string::String;
use std::ffi::CString;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn log_warn(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let user = pamh.user().unwrap_or("unknown");
    let service = pamh.service();

    let msg = format!("pam_warn: service={} user={}", service, user);
    let c_fmt = CString::new("%s").unwrap();
    let c_msg = CString::new(msg).unwrap();

    unsafe {
        libc::syslog(4, c_fmt.as_ptr(), c_msg.as_ptr()); // 4 = LOG_WARNING
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("warn"),
        authenticate: Some(log_warn),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(log_warn),
        open_session: Some(log_warn),
        close_session: Some(log_warn),
        chauthtok: Some(log_warn),
    }
}
