//! chsh CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let current_user = env::var("USER").unwrap_or_else(|_| "root".to_string());
    let mut target_user = current_user;
    let mut new_shell: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--shell" => {
                i += 1;
                if i < args.len() { new_shell = Some(args[i].clone()); }
            }
            arg if !arg.starts_with('-') => target_user = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    let passwd_p = passwd_path();
    let _lock = match FileLock::acquire(&passwd_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chsh: {}", e);
            std::process::exit(1);
        }
    };

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let entry = passwd_entries.iter_mut().find(|e| e.name == target_user);

    if entry.is_none() {
        eprintln!("chsh: user '{}' not found", target_user);
        std::process::exit(1);
    }

    let p = entry.unwrap();
    let shell = match new_shell {
        Some(s) => s,
        None => {
            println!("Changing shell for {}.", target_user);
            print!("New shell [{}]: ", p.shell);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let trimmed = input.trim();
            if trimmed.is_empty() { p.shell.clone() } else { trimmed.to_string() }
        }
    };

    p.shell = shell;

    if let Err(e) = PasswdFile::save(&passwd_p, &passwd_entries) {
        eprintln!("chsh: failed to save passwd: {}", e);
        std::process::exit(1);
    }

    println!("Shell changed.");
}
