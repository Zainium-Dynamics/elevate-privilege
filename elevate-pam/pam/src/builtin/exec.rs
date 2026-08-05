//! pam_exec — execute external program hook.

use alloc::string::String;
use std::process::Command;

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn exec_hook(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    if args.is_empty() {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    let user = pamh.user().unwrap_or_default();

    let cmd_name = &args[0];
    let cmd_args = &args[1..];

    let mut cmd = Command::new(cmd_name);
    cmd.args(cmd_args);
    cmd.env("PAM_USER", user);

    match cmd.status() {
        Ok(status) if status.success() => PamStatus::new(PAM_SUCCESS),
        _ => PamStatus::new(PAM_AUTH_ERR),
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("exec"),
        authenticate: Some(exec_hook),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(exec_hook),
        open_session: Some(exec_hook),
        close_session: Some(exec_hook),
        chauthtok: Some(exec_hook),
    }
}
