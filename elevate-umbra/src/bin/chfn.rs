//! chfn CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let current_user = env::var("USER").unwrap_or_else(|_| "root".to_string());
    let target_user = if args.len() > 1 && !args[1].starts_with('-') {
        args[1].clone()
    } else {
        current_user
    };

    let passwd_p = passwd_path();
    let _lock = match FileLock::acquire(&passwd_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chfn: {}", e);
            std::process::exit(1);
        }
    };

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let entry = passwd_entries.iter_mut().find(|e| e.name == target_user);

    if entry.is_none() {
        eprintln!("chfn: user '{}' not found", target_user);
        std::process::exit(1);
    }

    let p = entry.unwrap();
    println!("Changing finger information for {}.", target_user);
    print!("Full Name [{}]: ", p.gecos);
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let mut new_gecos = String::new();
    let _ = std::io::stdin().read_line(&mut new_gecos);
    let trimmed = new_gecos.trim();
    if !trimmed.is_empty() {
        p.gecos = trimmed.to_string();
    }

    if let Err(e) = PasswdFile::save(&passwd_p, &passwd_entries) {
        eprintln!("chfn: failed to save passwd: {}", e);
        std::process::exit(1);
    }
}
