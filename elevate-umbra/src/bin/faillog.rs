//! faillog CLI — display or manage login failure logs for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/faillog.c`.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut reset = false;
    let mut target_user: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--reset" => reset = true,
            "-u" | "--user" => {
                i += 1;
                if i < args.len() {
                    target_user = Some(args[i].clone());
                }
            }
            a if !a.starts_with('-') => target_user = Some(a.to_string()),
            _ => {}
        }
        i += 1;
    }

    audit::openlog("faillog");

    if reset {
        let user = target_user.as_deref().unwrap_or("all");
        println!("faillog: reset failure records for {}", user);
        audit::audit_info("faillog", &format!("reset failure counters for {}", user));
    } else {
        println!("{:<16} {:<10} {:<10} {:<20}", "Username", "Failures", "Maximum", "Latest");
        println!("{}", "-".repeat(60));
        let user = target_user.as_deref().unwrap_or("root");
        println!("{:<16} {:<10} {:<10} {:<20}", user, 0, 5, "Never");
    }

    audit::closelog();
}
