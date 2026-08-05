//! chage CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: chage [options] LOGIN");
        eprintln!("Options:");
        eprintln!("  -l, --list            list password aging information");
        eprintln!("  -m, --mindays MIN     minimum number of days between password changes");
        eprintln!("  -M, --maxdays MAX     maximum number of days password is valid");
        eprintln!("  -W, --warndays WARN   number of days warning before password expires");
        eprintln!("  -I, --inactive INACT  number of days after password expires until account is locked");
        std::process::exit(1);
    }

    let mut username = String::new();
    let mut list_only = false;
    let mut min_days: Option<i64> = None;
    let mut max_days: Option<i64> = None;
    let mut warn_days: Option<i64> = None;
    let mut inact_days: Option<i64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-l" | "--list" => list_only = true,
            "-m" | "--mindays" => {
                i += 1;
                if i < args.len() { min_days = args[i].parse().ok(); }
            }
            "-M" | "--maxdays" => {
                i += 1;
                if i < args.len() { max_days = args[i].parse().ok(); }
            }
            "-W" | "--warndays" => {
                i += 1;
                if i < args.len() { warn_days = args[i].parse().ok(); }
            }
            "-I" | "--inactive" => {
                i += 1;
                if i < args.len() { inact_days = args[i].parse().ok(); }
            }
            arg if !arg.starts_with('-') => username = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    if username.is_empty() {
        eprintln!("chage: username required");
        std::process::exit(1);
    }

    let shadow_p = shadow_path();
    let shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let entry = shadow_entries.iter().find(|e| e.name == username);

    if entry.is_none() {
        eprintln!("chage: user '{}' does not exist in shadow", username);
        std::process::exit(6);
    }

    let s = entry.unwrap();
    if list_only {
        println!("Minimum password age (days): {}", s.min.unwrap_or(0));
        println!("Maximum password age (days): {}", s.max.unwrap_or(99999));
        println!("Password warning days: {}", s.warn.unwrap_or(7));
        println!("Account inactive days: {}", s.inact.map(|i| i.to_string()).unwrap_or_else(|| "never".into()));
        return;
    }

    let _lock = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chage: {}", e);
            std::process::exit(1);
        }
    };

    let mut shadow_entries = shadow_entries;
    let s = shadow_entries.iter_mut().find(|e| e.name == username).unwrap();

    if let Some(m) = min_days { s.min = Some(m); }
    if let Some(m) = max_days { s.max = Some(m); }
    if let Some(w) = warn_days { s.warn = Some(w); }
    if let Some(i) = inact_days { s.inact = Some(i); }

    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("chage: failed to save shadow: {}", e);
        std::process::exit(1);
    }
}
