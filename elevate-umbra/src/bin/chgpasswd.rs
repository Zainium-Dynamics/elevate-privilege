//! chgpasswd CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use elevate_crypto::hash_password;
use std::io::{self, BufRead};

fn main() {
    let gshadow_p = gshadow_path();
    let _lock = match FileLock::acquire(&gshadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chgpasswd: {}", e);
            std::process::exit(1);
        }
    };

    let mut gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();
    let stdin = io::stdin();

    for line in stdin.lock().lines().flatten() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((group, pass)) = line.split_once(':') {
            if let Some(entry) = gshadow_entries.iter_mut().find(|e| e.name == group) {
                if let Ok(new_hash) = hash_password(pass) {
                    entry.passwd = new_hash;
                }
            } else {
                eprintln!("chgpasswd: warning: group '{}' not found in gshadow", group);
            }
        }
    }

    if let Err(e) = GshadowFile::save(&gshadow_p, &gshadow_entries) {
        eprintln!("chgpasswd: failed to save gshadow: {}", e);
        std::process::exit(1);
    }
}
