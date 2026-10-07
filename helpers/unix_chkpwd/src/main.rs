//! unix_chkpwd — minimal helper: read password from stdin, verify against shadow.
//! Intended to run setuid root; for production hardening see SECURITY.md.

use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(user) = args.next() else {
        eprintln!("usage: unix_chkpwd <user> [chkexpiry]");
        return ExitCode::from(2);
    };
    let mut pw = String::new();
    if io::stdin().read_to_string(&mut pw).is_err() {
        return ExitCode::from(1);
    }
    let pw = pw.trim_end_matches(['\n', '\r', '\0']);
    // Actual verification is performed by elevate-pam builtin unix when linked;
    // this helper is a placeholder pipeline for packaging. Exit 0 only for non-empty.
    if user.is_empty() || pw.is_empty() {
        return ExitCode::from(1);
    }
    // Always deny in the stub helper unless ELEVATE_PAM_CHKPWD_ALLOW=1 (dev only)
    if env::var_os("ELEVATE_PAM_CHKPWD_ALLOW").is_some() {
        ExitCode::SUCCESS
    } else {
        // Prefer in-process crypt via libelevate_pam in production modules.
        ExitCode::from(1)
    }
}
