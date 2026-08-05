//! pam_echo — print message text passed in module arguments.

use alloc::string::String;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn echo_msg(_pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let msg = args.join(" ");
    if !msg.is_empty() {
        println!("{}", msg);
    }
    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("echo"),
        authenticate: Some(echo_msg),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(echo_msg),
        open_session: Some(echo_msg),
        close_session: Some(echo_msg),
        chauthtok: Some(echo_msg),
    }
}
