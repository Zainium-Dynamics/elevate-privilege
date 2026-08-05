//! pam_issue — display pre-login notice (/etc/issue).

use alloc::string::String;
use std::fs;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn print_issue(_pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let default_path = elevate_paths::get().issue_file();
    let issue_path = args
        .iter()
        .find_map(|a| a.strip_prefix("file="))
        .unwrap_or(&default_path);

    if let Ok(content) = fs::read_to_string(issue_path) {
        if !content.is_empty() {
            print!("{}", content);
        }
    }

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("issue"),
        authenticate: Some(print_issue),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: None,
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
