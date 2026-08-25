//! sulogin CLI — Emergency root login shell for system maintenance.
//! Port of shadow-4.17.2 `src/sulogin.c`.

use elevate_crypto::verify_password;
use elevate_umbra::*;
use std::ffi::CString;
use std::io::{self, Write};

fn main() {
    audit::openlog("sulogin");

    let shadow_p = shadow_path();
    let shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();

    let root_entry = shadow_entries.iter().find(|e| e.name == "root");
    if root_entry.is_none() {
        eprintln!("sulogin: no entry for root in shadow file");
        audit::audit_crit("sulogin", "root entry missing");
        std::process::exit(E_NOTFOUND);
    }
    let root_hash = &root_entry.unwrap().hash;

    loop {
        print!("Type root password for maintenance (or press Control-D to continue): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) | Err(_) => {
                println!("\nContinuing boot process...");
                audit::closelog();
                std::process::exit(E_SUCCESS);
            }
            Ok(_) => {}
        }

        let pass = input.trim_end_matches(['\r', '\n']);

        // Verify root password
        if verify_password(pass, root_hash).unwrap_or(false) {
            ratelimit::clear_failed_attempts("root");
            println!("Root password accepted. Launching emergency shell...");
            audit::audit_crit("sulogin", "emergency root shell granted");
            audit::closelog();

            let shell = std::env::var("SUSHELL")
                .unwrap_or_else(|_| format!("{}/bin/sh", elevate_paths::get().prefix));
            let c_shell = CString::new(shell.clone()).unwrap();
            let c_arg = CString::new("-sh").unwrap();
            let args = [c_arg.as_ptr(), std::ptr::null()];

            unsafe {
                libc::execv(c_shell.as_ptr(), args.as_ptr());
            }

            eprintln!(
                "sulogin: failed to execute {}: {}",
                shell,
                io::Error::last_os_error()
            );
            std::process::exit(E_CMD_NOEXEC);
        } else {
            eprintln!("Login incorrect.");
            let delay = ratelimit::enforce_failed_attempt_delay("root");
            if delay >= 300 {
                eprintln!("SECURITY LOCKOUT: High frequency brute-force attack detected! Enforcing 5-minute security penalty...");
            } else if delay >= 30 {
                eprintln!("SECURITY DELAY: Multiple failed password attempts. Enforcing 30-second penalty delay...");
            }
        }
    }
}
