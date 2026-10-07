//! pam_mail — check user mail spool and notify session login.

use alloc::string::String;
use std::path::PathBuf;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn check_mail(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let user = match pamh.user() {
        Some(u) => u,
        None => return PamStatus::new(PAM_SUCCESS),
    };

    let spool_path = PathBuf::from("/var/mail").join(user);
    let alt_spool = PathBuf::from("/var/spool/mail").join(user);

    if (spool_path.exists() && spool_path.metadata().map(|m| m.len() > 0).unwrap_or(false))
        || (alt_spool.exists() && alt_spool.metadata().map(|m| m.len() > 0).unwrap_or(false))
    {
        println!("You have mail.");
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("mail"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(check_mail),
        close_session: None,
        chauthtok: None,
    }
}
