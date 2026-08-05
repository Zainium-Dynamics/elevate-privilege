//! pam_motd — display message of the day (/etc/motd).

use alloc::string::String;
use std::fs;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn open_session(_pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let default_path = elevate_paths::get().motd_file();
    let motd_path = args
        .iter()
        .find_map(|a| a.strip_prefix("motd="))
        .unwrap_or(&default_path);

    if let Ok(content) = fs::read_to_string(motd_path) {
        if !content.is_empty() {
            print!("{}", content);
        }
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("motd"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(open_session),
        close_session: None,
        chauthtok: None,
    }
}
