//! umbra-sign CLI — Ed25519 & Blake3 signing/verification utility for ZainiumOS syshub.

use elevate_umbra::*;
use elevate_crypto::{generate_ed25519_keypair, hash_blake3, sign_ed25519, verify_ed25519};
use std::env;
use std::fs;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  umbra-sign keygen             Generate Ed25519 system keypair");
        eprintln!("  umbra-sign sign FILE          Sign FILE with Ed25519 and produce FILE.sig");
        eprintln!("  umbra-sign verify FILE        Verify FILE against FILE.sig with Ed25519");
        eprintln!("  umbra-sign hash FILE          Compute Blake3 digest of FILE");
        std::process::exit(1);
    }

    let cmd = &args[1];
    let key_path = syshub_etc().join("syshub_ed25519.key");
    let pub_path = syshub_etc().join("syshub_ed25519.pub");

    match cmd.as_str() {
        "keygen" => {
            let (pub_bytes, sec_bytes) = generate_ed25519_keypair();
            if let Err(e) = fs::write(&key_path, sec_bytes) {
                eprintln!("umbra-sign: failed to write private key {}: {}", key_path.display(), e);
                std::process::exit(1);
            }
            if let Err(e) = fs::write(&pub_path, pub_bytes) {
                eprintln!("umbra-sign: failed to write public key {}: {}", pub_path.display(), e);
                std::process::exit(1);
            }
            println!("umbra-sign: generated Ed25519 keypair:");
            println!("  Private key: {}", key_path.display());
            println!("  Public key:  {}", pub_path.display());
        }

        "hash" => {
            if args.len() < 3 {
                eprintln!("umbra-sign hash: FILE required");
                std::process::exit(1);
            }
            let file_path = &args[2];
            let bytes = fs::read(file_path).unwrap_or_else(|e| {
                eprintln!("umbra-sign: failed to read {}: {}", file_path, e);
                std::process::exit(1);
            });
            let digest = hash_blake3(&bytes);
            println!("Blake3({}): {}", file_path, hex_encode(&digest));
        }

        "sign" => {
            if args.len() < 3 {
                eprintln!("umbra-sign sign: FILE required");
                std::process::exit(1);
            }
            let file_path = &args[2];
            let bytes = fs::read(file_path).unwrap_or_else(|e| {
                eprintln!("umbra-sign: failed to read {}: {}", file_path, e);
                std::process::exit(1);
            });

            let sec_bytes = fs::read(&key_path).unwrap_or_else(|_| {
                eprintln!("umbra-sign: private key {} missing. Run 'umbra-sign keygen' first.", key_path.display());
                std::process::exit(1);
            });

            if sec_bytes.len() != 32 {
                eprintln!("umbra-sign: invalid private key length");
                std::process::exit(1);
            }

            let mut sec_arr = [0u8; 32];
            sec_arr.copy_from_slice(&sec_bytes);

            let sig = sign_ed25519(&sec_arr, &bytes).unwrap_or_else(|e| {
                eprintln!("umbra-sign: signing error: {}", e);
                std::process::exit(1);
            });

            let sig_path = format!("{}.sig", file_path);
            if let Err(e) = fs::write(&sig_path, sig) {
                eprintln!("umbra-sign: failed to write signature {}: {}", sig_path, e);
                std::process::exit(1);
            }

            println!("umbra-sign: signed {} -> {}", file_path, sig_path);
        }

        "verify" => {
            if args.len() < 3 {
                eprintln!("umbra-sign verify: FILE required");
                std::process::exit(1);
            }
            let file_path = &args[2];
            let sig_path = format!("{}.sig", file_path);

            let bytes = fs::read(file_path).unwrap_or_else(|e| {
                eprintln!("umbra-sign: failed to read {}: {}", file_path, e);
                std::process::exit(1);
            });

            let sig_bytes = fs::read(&sig_path).unwrap_or_else(|e| {
                eprintln!("umbra-sign: failed to read signature {}: {}", sig_path, e);
                std::process::exit(1);
            });

            let pub_bytes = fs::read(&pub_path).unwrap_or_else(|e| {
                eprintln!("umbra-sign: failed to read public key {}: {}", pub_path.display(), e);
                std::process::exit(1);
            });

            if sig_bytes.len() != 64 || pub_bytes.len() != 32 {
                eprintln!("umbra-sign: signature or key length mismatch");
                std::process::exit(1);
            }

            let mut sig_arr = [0u8; 64];
            let mut pub_arr = [0u8; 32];
            sig_arr.copy_from_slice(&sig_bytes);
            pub_arr.copy_from_slice(&pub_bytes);

            if verify_ed25519(&pub_arr, &bytes, &sig_arr).is_ok() {
                println!("umbra-sign: VERIFIED OK for {}", file_path);
            } else {
                eprintln!("umbra-sign: VERIFICATION FAILED for {}", file_path);
                std::process::exit(1);
            }
        }

        other => {
            eprintln!("umbra-sign: unknown subcommand '{}'", other);
            std::process::exit(1);
        }
    }
}
