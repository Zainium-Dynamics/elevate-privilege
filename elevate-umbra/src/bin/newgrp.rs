//! newgrp CLI — log in to a new group for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/newgrp.c`.

use elevate_umbra::*;
use std::env;
use std::ffi::CString;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: newgrp [GROUP]");
        std::process::exit(E_USAGE);
    }

    let groupname = &args[1];

    let group_p = group_path();
    let group_entries = GroupFile::load(&group_p).unwrap_or_default();

    let grp = group_entries.iter().find(|e| e.name == *groupname);
    if grp.is_none() {
        eprintln!("newgrp: group '{}' does not exist", groupname);
        std::process::exit(E_NOTFOUND);
    }
    let target_gid = grp.unwrap().gid;

    audit::openlog("newgrp");

    // Set real and effective GID
    let ret = unsafe { libc::setgid(target_gid) };
    if ret != 0 {
        eprintln!(
            "newgrp: failed to set GID to {}: {}",
            target_gid,
            std::io::Error::last_os_error()
        );
        audit::audit_user_op("newgrp", "setgid", groupname, Some(target_gid), false);
        std::process::exit(E_NOPERM);
    }

    audit::audit_user_op("newgrp", "setgid", groupname, Some(target_gid), true);
    audit::closelog();

    // Spawn default user shell
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let c_shell = CString::new(shell.clone()).unwrap();

    let shell_arg = if shell.contains('/') {
        format!("-{}", shell.split('/').next_back().unwrap_or("sh"))
    } else {
        format!("-{}", shell)
    };
    let c_arg = CString::new(shell_arg).unwrap();

    let args_ptrs = [c_arg.as_ptr(), std::ptr::null()];
    unsafe {
        libc::execv(c_shell.as_ptr(), args_ptrs.as_ptr());
    }

    eprintln!(
        "newgrp: failed to exec shell {}: {}",
        shell,
        std::io::Error::last_os_error()
    );
    std::process::exit(E_CMD_NOEXEC);
}
