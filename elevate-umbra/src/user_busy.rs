//! Check if a user has running processes (port of shadow `lib/user_busy.c`).

use std::fs;
use std::path::Path;

/// Check if a user with the given UID has any running processes.
/// Scans `/proc` for processes owned by this UID.
pub fn user_busy(_name: &str, uid: u32) -> bool {
    let proc_dir = Path::new("/proc");
    if !proc_dir.is_dir() {
        return false;
    }

    let entries = match fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        // Only look at numeric directories (PIDs)
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let status_path = entry.path().join("status");
        if let Ok(content) = fs::read_to_string(&status_path) {
            for line in content.lines() {
                if let Some(uid_str) = line.strip_prefix("Uid:") {
                    // Uid line format: "Uid:\treal\teffective\tsaved\tfs"
                    let parts: Vec<&str> = uid_str.split_whitespace().collect();
                    if let Some(real_uid) = parts.first() {
                        if let Ok(proc_uid) = real_uid.parse::<u32>() {
                            if proc_uid == uid {
                                return true;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    false
}
