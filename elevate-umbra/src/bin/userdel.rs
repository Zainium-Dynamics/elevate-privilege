//! userdel CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;
use std::path::Path;

fn main() {
    audit::openlog("userdel");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: userdel [options] LOGIN");
        eprintln!("Options:");
        eprintln!("  -r, --remove         remove home directory and mail spool");
        eprintln!("  -f, --force          force removal even if user is logged in");
        std::process::exit(E_USAGE);
    }

    let mut username = String::new();
    let mut remove_home = false;
    let mut force = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-r" | "--remove" => remove_home = true,
            "-f" | "--force" => force = true,
            a if !a.starts_with('-') => username = a.to_string(),
            _ => {}
        }
    }

    if username.is_empty() {
        eprintln!("userdel: username required");
        std::process::exit(E_USAGE);
    }

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    let _lock_p = match FileLock::acquire(&passwd_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("userdel: {}", e);
            std::process::exit(E_NOPERM);
        }
    };
    let _lock_s = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("userdel: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();

    let user_info = passwd_entries
        .iter()
        .find(|e| e.name == username)
        .map(|e| (e.uid, e.dir.clone()));

    if user_info.is_none() {
        eprintln!("userdel: user '{}' does not exist", username);
        audit::audit_user_op("userdel", "del", &username, None, false);
        std::process::exit(E_NOTFOUND);
    }
    let (uid, target_home) = user_info.unwrap();

    // Check user_busy unless --force
    if !force && user_busy::user_busy(&username, uid) {
        eprintln!(
            "userdel: user '{}' is currently logged in or running processes",
            username
        );
        audit::audit_user_op("userdel", "del", &username, Some(uid), false);
        std::process::exit(E_BAD_ARG);
    }

    passwd_entries.retain(|e| e.name != username);
    shadow_entries.retain(|e| e.name != username);

    if let Err(e) = PasswdFile::save(&passwd_p, &passwd_entries) {
        eprintln!("userdel: failed to update passwd: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("userdel: failed to update shadow: {}", e);
        std::process::exit(1);
    }

    if remove_home {
        let home_path = Path::new(&target_home);
        if home_path.is_dir() {
            if let Err(e) = copydir::remove_tree(home_path, true) {
                eprintln!(
                    "userdel: warning: cannot remove home directory {}: {}",
                    target_home, e
                );
            }
        }
    }

    // Remove subuid / subgid ranges
    let subuid_p = subuid_path();
    let subgid_p = subgid_path();
    let _ = SubIdFile::remove_user_range(&subuid_p, &username);
    let _ = SubIdFile::remove_user_range(&subgid_p, &username);

    audit::audit_user_op("userdel", "del", &username, Some(uid), true);
    println!("userdel: deleted user '{}'", username);
    audit::closelog();
}
