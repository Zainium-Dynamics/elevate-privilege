//! Sudo Security Interceptor Shim for ZainiumOS syshub.
//! Blocks legacy `sudo` execution and directs users to Zainium native `elevate` / `elev`.

use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("sudo_blocker");

    let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd_line = args.join(" ");

    eprintln!(
        "SECURITY POLICY ERROR: Legacy 'sudo' is strictly disabled and blocked.!\n\
         Unauthorized sudo invocation attempt detected.\n\
         Please use native privilege escalation commands: 'elevate' or 'elev'."
    );

    audit::audit_crit(
        "sudo_blocker",
        &format!(
            "BLOCKED legacy sudo attempt by user '{}' with args: '{}'",
            user, cmd_line
        ),
    );

    audit::closelog();
    std::process::exit(E_NOPERM);
}
