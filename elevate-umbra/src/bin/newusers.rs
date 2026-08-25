//! newusers CLI — batch user creation from stdin for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/newusers.c`.
//!
//! Input format (one per line): username:password:uid:gid:gecos:home:shell

use elevate_crypto::hash_password;
use elevate_umbra::*;
use std::io::{self, BufRead};

fn main() {
    audit::openlog("newusers");

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();
    let group_p = group_path();

    let _lock_p = FileLock::acquire(&passwd_p).unwrap_or_else(|e| {
        eprintln!("newusers: {}", e);
        std::process::exit(1);
    });
    let _lock_s = FileLock::acquire(&shadow_p).unwrap_or_else(|e| {
        eprintln!("newusers: {}", e);
        std::process::exit(1);
    });

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let login_defs = LoginDefs::load_default();

    let stdin = io::stdin();
    let mut count = 0;

    for line in stdin.lock().lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            eprintln!(
                "newusers: invalid line (need 7 colon-separated fields): {}",
                line
            );
            continue;
        }

        let username = parts[0].trim();
        let password = parts[1].trim();
        let uid_str = parts[2].trim();
        let gid_str = parts[3].trim();
        let gecos = parts[4].trim();
        let home = parts[5].trim();
        let shell = parts[6].trim();

        // Validate name
        if let Err(e) = chkname::is_valid_user_name(username) {
            eprintln!("newusers: invalid username '{}': {}", username, e);
            continue;
        }

        // Determine UID
        let uid: u32 = if uid_str.is_empty() {
            // Auto-assign
            let max_uid = passwd_entries
                .iter()
                .map(|e| e.uid)
                .max()
                .unwrap_or(login_defs.uid_min() - 1);
            max_uid + 1
        } else {
            uid_str.parse().unwrap_or_else(|_| {
                eprintln!(
                    "newusers: invalid UID '{}' for user '{}'",
                    uid_str, username
                );
                std::process::exit(1);
            })
        };

        // Determine GID
        let gid: u32 = if gid_str.is_empty() {
            uid
        } else if let Ok(g) = gid_str.parse::<u32>() {
            g
        } else {
            // Try looking up group by name
            group_entries
                .iter()
                .find(|g| g.name == gid_str)
                .map(|g| g.gid)
                .unwrap_or(uid)
        };

        let home_dir = if home.is_empty() {
            format!("/home/{}", username)
        } else {
            home.to_string()
        };
        let user_shell = if shell.is_empty() {
            format!("{}/bin/sh", elevate_paths::get().prefix)
        } else {
            shell.to_string()
        };

        // Hash password
        let hashed = if password.is_empty() {
            "!".to_string()
        } else {
            hash_password(password).unwrap_or_else(|e| {
                eprintln!(
                    "newusers: failed to hash password for '{}': {}",
                    username, e
                );
                "!".to_string()
            })
        };

        // Check if user already exists (update vs create)
        if let Some(existing) = passwd_entries.iter_mut().find(|e| e.name == username) {
            existing.uid = uid;
            existing.gid = gid;
            existing.gecos = gecos.to_string();
            existing.dir = home_dir;
            existing.shell = user_shell;
            if let Some(se) = shadow_entries.iter_mut().find(|e| e.name == username) {
                se.hash = hashed;
                se.lstchg = Some(ShadowEntry::current_days());
            }
        } else {
            passwd_entries.push(PasswdEntry {
                name: username.to_string(),
                passwd: "x".to_string(),
                uid,
                gid,
                gecos: gecos.to_string(),
                dir: home_dir,
                shell: user_shell,
            });
            shadow_entries.push(ShadowEntry {
                name: username.to_string(),
                hash: hashed,
                lstchg: Some(ShadowEntry::current_days()),
                min: Some(0),
                max: Some(99999),
                warn: Some(7),
                inact: None,
                expire: None,
                flag: None,
            });
        }

        audit::audit_user_op("newusers", "add", username, Some(uid), true);
        count += 1;
    }

    PasswdFile::save(&passwd_p, &passwd_entries).unwrap_or_else(|e| {
        eprintln!("newusers: {}", e);
        std::process::exit(1);
    });
    ShadowFile::save(&shadow_p, &shadow_entries).unwrap_or_else(|e| {
        eprintln!("newusers: {}", e);
        std::process::exit(1);
    });

    println!("newusers: processed {} user(s)", count);
    audit::closelog();
}
