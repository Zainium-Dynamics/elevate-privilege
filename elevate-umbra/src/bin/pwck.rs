//! pwck CLI implementation for ZainiumOS syshub with Blake3 & Ed25519 integrity support.

use elevate_crypto::{hash_blake3, verify_ed25519};
use elevate_umbra::*;
use std::fs;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("pwck: checking /etc/passwd and /etc/shadow integrity...");

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    let passwd_entries = match PasswdFile::load(&passwd_p) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("pwck: error loading passwd: {}", e);
            std::process::exit(1);
        }
    };

    let shadow_entries = match ShadowFile::load(&shadow_p) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("pwck: error loading shadow: {}", e);
            std::process::exit(1);
        }
    };

    let mut errors = 0;

    // 1. Calculate Blake3 Hashes of passwd and shadow
    if let Ok(passwd_bytes) = fs::read(&passwd_p) {
        let b3 = hash_blake3(&passwd_bytes);
        println!("pwck: Blake3(passwd) = {}", hex_encode(&b3));
    }

    if let Ok(shadow_bytes) = fs::read(&shadow_p) {
        let b3 = hash_blake3(&shadow_bytes);
        println!("pwck: Blake3(shadow) = {}", hex_encode(&b3));
    }

    // 2. Check Ed25519 Signature files if present (.sig & .pub)
    let passwd_sig = passwd_p.with_extension("passwd.sig");
    let pubkey_path = syshub_etc().join("syshub_ed25519.pub");

    if passwd_sig.exists() && pubkey_path.exists() {
        if let (Ok(passwd_bytes), Ok(sig_bytes), Ok(pub_bytes)) = (
            fs::read(&passwd_p),
            fs::read(&passwd_sig),
            fs::read(&pubkey_path),
        ) {
            if sig_bytes.len() == 64 && pub_bytes.len() == 32 {
                let mut sig_arr = [0u8; 64];
                let mut pub_arr = [0u8; 32];
                sig_arr.copy_from_slice(&sig_bytes);
                pub_arr.copy_from_slice(&pub_bytes);

                if verify_ed25519(&pub_arr, &passwd_bytes, &sig_arr).is_ok() {
                    println!("pwck: Ed25519 signature for passwd VERIFIED OK");
                } else {
                    eprintln!("pwck: Ed25519 signature verification FAILED for passwd");
                    errors += 1;
                }
            }
        }
    }

    // 3. Check duplicate UIDs
    let mut seen_uids = std::collections::HashSet::new();
    for entry in &passwd_entries {
        if !seen_uids.insert(entry.uid) {
            eprintln!("pwck: duplicate UID found: {}", entry.uid);
            errors += 1;
        }
    }

    // 4. Check passwd entries without shadow
    for entry in &passwd_entries {
        if entry.passwd == "x" && !shadow_entries.iter().any(|s| s.name == entry.name) {
            eprintln!(
                "pwck: user '{}' expects shadow entry but none exists",
                entry.name
            );
            errors += 1;
        }
    }

    if errors == 0 {
        println!("pwck: no errors found.");
    } else {
        println!("pwck: found {} error(s).", errors);
        std::process::exit(1);
    }
}
