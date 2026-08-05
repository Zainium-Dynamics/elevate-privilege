//! chpasswd CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use elevate_crypto::hash_password;
use std::io::{self, BufRead};

fn main() {
    let shadow_p = shadow_path();
    let _lock = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chpasswd: {}", e);
            std::process::exit(1);
        }
    };

    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let stdin = io::stdin();

    for line in stdin.lock().lines().flatten() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((user, pass)) = line.split_once(':') {
            if let Some(entry) = shadow_entries.iter_mut().find(|e| e.name == user) {
                if let Ok(new_hash) = hash_password(pass) {
                    entry.hash = new_hash;
                    entry.lstchg = Some(ShadowEntry::current_days());
                }
            } else {
                eprintln!("chpasswd: warning: user '{}' not found", user);
            }
        }
    }

    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("chpasswd: failed to save shadow: {}", e);
        std::process::exit(1);
    }
}
