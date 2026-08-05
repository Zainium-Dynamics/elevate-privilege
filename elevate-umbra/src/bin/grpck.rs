//! grpck CLI implementation for ZainiumOS syshub with Blake3 & Ed25519 integrity support.

use elevate_umbra::*;
use elevate_crypto::{hash_blake3, verify_ed25519};
use std::fs;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("grpck: checking /etc/group and /etc/gshadow integrity...");

    let group_p = group_path();
    let gshadow_p = gshadow_path();

    let group_entries = match GroupFile::load(&group_p) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("grpck: error loading group: {}", e);
            std::process::exit(1);
        }
    };

    let mut errors = 0;

    // 1. Calculate Blake3 Hashes of group and gshadow
    if let Ok(group_bytes) = fs::read(&group_p) {
        let b3 = hash_blake3(&group_bytes);
        println!("grpck: Blake3(group) = {}", hex_encode(&b3));
    }

    if let Ok(gshadow_bytes) = fs::read(&gshadow_p) {
        let b3 = hash_blake3(&gshadow_bytes);
        println!("grpck: Blake3(gshadow) = {}", hex_encode(&b3));
    }

    // 2. Check Ed25519 Signature files if present (.sig & .pub)
    let group_sig = group_p.with_extension("group.sig");
    let pubkey_path = syshub_etc().join("syshub_ed25519.pub");

    if group_sig.exists() && pubkey_path.exists() {
        if let (Ok(group_bytes), Ok(sig_bytes), Ok(pub_bytes)) = (
            fs::read(&group_p),
            fs::read(&group_sig),
            fs::read(&pubkey_path),
        ) {
            if sig_bytes.len() == 64 && pub_bytes.len() == 32 {
                let mut sig_arr = [0u8; 64];
                let mut pub_arr = [0u8; 32];
                sig_arr.copy_from_slice(&sig_bytes);
                pub_arr.copy_from_slice(&pub_bytes);

                if verify_ed25519(&pub_arr, &group_bytes, &sig_arr).is_ok() {
                    println!("grpck: Ed25519 signature for group VERIFIED OK");
                } else {
                    eprintln!("grpck: Ed25519 signature verification FAILED for group");
                    errors += 1;
                }
            }
        }
    }

    // 3. Check duplicate GIDs
    let mut seen_gids = std::collections::HashSet::new();
    for entry in &group_entries {
        if !seen_gids.insert(entry.gid) {
            eprintln!("grpck: duplicate GID found: {}", entry.gid);
            errors += 1;
        }
    }

    if errors == 0 {
        println!("grpck: no errors found.");
    } else {
        println!("grpck: found {} error(s).", errors);
        std::process::exit(1);
    }
}
