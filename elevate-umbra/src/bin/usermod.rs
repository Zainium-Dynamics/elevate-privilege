//! usermod CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("usermod");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: usermod [options] LOGIN");
        eprintln!("Options:");
        eprintln!("  -s, --shell SHELL     new login shell");
        eprintln!("  -d, --home DIR        new home directory");
        eprintln!("  -u, --uid UID         new user ID");
        eprintln!("  -g, --gid GID         new primary group ID");
        eprintln!("  -c, --comment COMMENT new GECOS comment field");
        eprintln!("  -l, --login NEW_LOGIN new user name");
        eprintln!("  -L, --lock            lock the user's password");
        eprintln!("  -U, --unlock          unlock the user's password");
        std::process::exit(E_USAGE);
    }

    let mut username = String::new();
    let mut new_shell: Option<String> = None;
    let mut new_home: Option<String> = None;
    let mut new_uid: Option<u32> = None;
    let mut new_gid: Option<u32> = None;
    let mut new_comment: Option<String> = None;
    let mut new_login: Option<String> = None;
    let mut lock_password = false;
    let mut unlock_password = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--shell" => {
                i += 1;
                if i < args.len() {
                    new_shell = Some(args[i].clone());
                }
            }
            "-d" | "--home" => {
                i += 1;
                if i < args.len() {
                    new_home = Some(args[i].clone());
                }
            }
            "-u" | "--uid" => {
                i += 1;
                if i < args.len() {
                    new_uid = args[i].parse().ok();
                }
            }
            "-g" | "--gid" => {
                i += 1;
                if i < args.len() {
                    new_gid = args[i].parse().ok();
                }
            }
            "-c" | "--comment" => {
                i += 1;
                if i < args.len() {
                    new_comment = Some(args[i].clone());
                }
            }
            "-l" | "--login" => {
                i += 1;
                if i < args.len() {
                    new_login = Some(args[i].clone());
                }
            }
            "-L" | "--lock" => lock_password = true,
            "-U" | "--unlock" => unlock_password = true,
            arg if !arg.starts_with('-') => username = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    if username.is_empty() {
        eprintln!("usermod: username required");
        std::process::exit(E_USAGE);
    }

    if let Some(ref nl) = new_login {
        if let Err(reason) = chkname::is_valid_user_name(nl) {
            eprintln!("usermod: invalid new username '{}': {}", nl, reason);
            audit::audit_user_op("usermod", "mod", &username, None, false);
            std::process::exit(E_BAD_ARG);
        }
    }

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    let _lock_p = match FileLock::acquire(&passwd_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("usermod: {}", e);
            std::process::exit(E_NOPERM);
        }
    };
    let _lock_s = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("usermod: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();

    let p_idx = passwd_entries.iter().position(|e| e.name == username);
    if p_idx.is_none() {
        eprintln!("usermod: user '{}' does not exist", username);
        audit::audit_user_op("usermod", "mod", &username, None, false);
        std::process::exit(E_NOTFOUND);
    }
    let p_idx = p_idx.unwrap();

    // Check new login name for conflicts BEFORE mutating
    let updated_name = if let Some(ref nl) = new_login {
        if passwd_entries.iter().any(|e| e.name == *nl) {
            eprintln!("usermod: user '{}' already exists", nl);
            std::process::exit(E_NAME_IN_USE);
        }
        nl.clone()
    } else {
        username.clone()
    };

    let user = &mut passwd_entries[p_idx];
    if let Some(s) = new_shell {
        user.shell = s;
    }
    if let Some(h) = new_home {
        user.dir = h;
    }
    if let Some(u) = new_uid {
        user.uid = u;
    }
    if let Some(g) = new_gid {
        user.gid = g;
    }
    if let Some(c) = new_comment {
        user.gecos = c;
    }
    if new_login.is_some() {
        user.name = updated_name.clone();
    }

    if let Some(s_entry) = shadow_entries.iter_mut().find(|e| e.name == username) {
        s_entry.name = updated_name.clone();
        if lock_password && !s_entry.hash.starts_with('!') {
            s_entry.hash = format!("!{}", s_entry.hash);
        } else if unlock_password && s_entry.hash.starts_with('!') {
            s_entry.hash = s_entry.hash[1..].to_string();
        }
    }

    if let Err(e) = PasswdFile::save(&passwd_p, &passwd_entries) {
        eprintln!("usermod: failed to update passwd: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("usermod: failed to update shadow: {}", e);
        std::process::exit(1);
    }

    audit::audit_user_op("usermod", "mod", &updated_name, None, true);
    println!("usermod: updated user '{}'", updated_name);
    audit::closelog();
}
