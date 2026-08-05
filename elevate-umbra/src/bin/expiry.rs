//! expiry CLI — check and enforce password expiration for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/expiry.c`.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let check_only = args.iter().any(|a| a == "-c");

    let current_user = env::var("USER").unwrap_or_else(|_| "root".to_string());

    let shadow_p = shadow_path();
    let shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let login_defs = LoginDefs::load_default();

    let entry = shadow_entries.iter().find(|e| e.name == current_user);
    if entry.is_none() {
        if check_only {
            std::process::exit(E_SUCCESS);
        }
        eprintln!("expiry: user '{}' not found in shadow", current_user);
        std::process::exit(E_NOTFOUND);
    }
    let entry = entry.unwrap();

    let today = ShadowEntry::current_days();
    let status = isexpired::check_expiration(entry, today, &login_defs);

    if check_only {
        match status {
            ExpiryStatus::AccountExpired | ExpiryStatus::AccountInactive | ExpiryStatus::PasswordExpired => {
                std::process::exit(1);
            }
            _ => std::process::exit(E_SUCCESS),
        }
    }

    match status {
        ExpiryStatus::AccountExpired | ExpiryStatus::AccountInactive => {
            println!("Your account has expired; please contact your system administrator.");
            std::process::exit(1);
        }
        ExpiryStatus::PasswordExpired => {
            println!("You are required to change your password immediately (password expired).");
            std::process::exit(1);
        }
        ExpiryStatus::PasswordWarning(days_left) => {
            println!("WARNING: Your password will expire in {} day(s).", days_left);
        }
        ExpiryStatus::Ok => {}
    }
}
