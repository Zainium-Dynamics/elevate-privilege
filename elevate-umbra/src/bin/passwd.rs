//! passwd CLI implementation for ZainiumOS syshub using elevate-crypto.

use elevate_crypto::hash_password;
use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("passwd");

    let args: Vec<String> = env::args().collect();
    let current_user = env::var("USER").unwrap_or_else(|_| "root".to_string());
    let target_user = if args.len() > 1 && !args[1].starts_with('-') {
        args[1].clone()
    } else {
        current_user
    };

    println!("Changing password for user {}.", target_user);

    let shadow_p = shadow_path();
    let _lock = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("passwd: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let entry = shadow_entries.iter_mut().find(|e| e.name == target_user);
    if entry.is_none() {
        eprintln!("passwd: user '{}' not found in shadow", target_user);
        audit::audit_user_op("passwd", "chpasswd", &target_user, None, false);
        std::process::exit(E_NOTFOUND);
    }

    let mut pass1 = String::new();
    let mut pass2 = String::new();

    print!("New password: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::stdin().read_line(&mut pass1);
    let pass1 = pass1.trim_end_matches(['\r', '\n']);

    print!("Retype new password: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::stdin().read_line(&mut pass2);
    let pass2 = pass2.trim_end_matches(['\r', '\n']);

    if pass1.len() > PASS_MAX {
        eprintln!(
            "passwd: password exceeds maximum length of {} bytes",
            PASS_MAX
        );
        audit::audit_user_op("passwd", "chpasswd", &target_user, None, false);
        std::process::exit(E_BAD_ARG);
    }

    if pass1 != pass2 {
        eprintln!("passwd: passwords do not match");
        audit::audit_user_op("passwd", "chpasswd", &target_user, None, false);
        std::process::exit(E_BAD_ARG);
    }

    if let Err(reason) = obscure::check_password_quality(pass1, None, &target_user) {
        eprintln!("passwd: BAD PASSWORD: {}", reason);
        audit::audit_user_op("passwd", "chpasswd", &target_user, None, false);
        std::process::exit(E_BAD_ARG);
    }

    let new_hash = hash_password(pass1).unwrap_or_else(|e| {
        eprintln!("passwd: crypto error: {}", e);
        std::process::exit(1);
    });

    let s_entry = entry.unwrap();
    s_entry.hash = new_hash;
    s_entry.lstchg = Some(ShadowEntry::current_days());

    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("passwd: failed to update shadow: {}", e);
        std::process::exit(1);
    }

    audit::audit_user_op("passwd", "chpasswd", &target_user, None, true);
    println!("passwd: password updated successfully for {}", target_user);
    audit::closelog();
}
