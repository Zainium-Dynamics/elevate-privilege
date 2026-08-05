//! pwunconv CLI — convert shadow passwords back to /etc/passwd format for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/pwunconv.c`.

use elevate_umbra::*;
use std::fs;

fn main() {
    audit::openlog("pwunconv");

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    if !shadow_p.exists() {
        println!("pwunconv: shadow file does not exist, nothing to do.");
        return;
    }

    let _lock_p = FileLock::acquire(&passwd_p).unwrap_or_else(|e| {
        eprintln!("pwunconv: {}", e);
        std::process::exit(E_NOPERM);
    });
    let _lock_s = FileLock::acquire(&shadow_p).unwrap_or_else(|e| {
        eprintln!("pwunconv: {}", e);
        std::process::exit(E_NOPERM);
    });

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();

    for pw in &mut passwd_entries {
        if let Some(se) = shadow_entries.iter().find(|s| s.name == pw.name) {
            pw.passwd = se.hash.clone();
        }
    }

    PasswdFile::save(&passwd_p, &passwd_entries).unwrap_or_else(|e| {
        eprintln!("pwunconv: failed to save passwd: {}", e);
        std::process::exit(1);
    });

    // Delete shadow file
    if let Err(e) = fs::remove_file(&shadow_p) {
        eprintln!("pwunconv: warning: failed to remove shadow file {}: {}", shadow_p.display(), e);
    } else {
        println!("pwunconv: removed shadow file {}.", shadow_p.display());
    }

    println!("pwunconv: unshadow conversion complete.");
    audit::audit_info("pwunconv", "converted shadow passwords back to passwd");
    audit::closelog();
}
