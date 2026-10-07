//! pam_umask — set process umask.

use alloc::string::String;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn set_umask(_pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let mut mask: u32 = 0o022;

    for arg in args {
        if let Some(val) = arg.strip_prefix("umask=") {
            if let Ok(m) = u32::from_str_radix(val, 8) {
                mask = m;
            }
        }
    }

    unsafe {
        libc::umask(mask as libc::mode_t);
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("umask"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(set_umask),
        close_session: None,
        chauthtok: None,
    }
}
