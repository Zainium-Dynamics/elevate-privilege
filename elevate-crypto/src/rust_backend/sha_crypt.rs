//! Legacy Unix shadow password hashes `$5$` (SHA-256-crypt) and `$6$` (SHA-512-crypt).
//!
//! **Password verification only** for existing `/etc/shadow` entries.
//! Do **not** use for message signatures — use Ed25519 instead.
//! Do **not** use for general hashing — use Blake3 instead.

use alloc::string::String;

use sha_crypt::{sha256_crypt_b64, sha512_crypt_b64, Sha256Params, Sha512Params};

use crate::common::ct_eq;
use crate::error::{CryptoError, CryptoResult};

/// Verify a password against a `$5$` or `$6$` modular crypt hash.
pub fn verify(password: &str, hash: &str) -> CryptoResult<bool> {
    if hash.starts_with("$6$") {
        verify_sha512(password, hash)
    } else if hash.starts_with("$5$") {
        verify_sha256(password, hash)
    } else {
        Err(CryptoError::Unsupported("not a $5$/$6$ sha-crypt hash"))
    }
}

fn verify_sha512(password: &str, hash: &str) -> CryptoResult<bool> {
    // hash form: $6$rounds=N$salt$checksum  or $6$salt$checksum
    let parts: alloc::vec::Vec<&str> = hash.split('$').collect();
    // ["", "6", salt_or_rounds, ...]
    if parts.len() < 4 {
        return Err(CryptoError::InvalidInput("malformed $6$ hash"));
    }
    let (rounds, salt, checksum) = parse_sha_parts(&parts[2..])?;
    let params = Sha512Params::new(rounds).map_err(|_| CryptoError::InvalidInput("rounds"))?;
    let out = sha512_crypt_b64(password.as_bytes(), salt.as_bytes(), &params)
        .map_err(|_| CryptoError::Internal("sha512_crypt failed"))?;
    // sha_crypt returns b64 checksum only in some versions; compare full rebuild
    let rebuilt = format!("$6${}${out}", if rounds != 5000 {
        // sha-crypt crate API varies — compare checksum field
        format!("rounds={rounds}${salt}")
    } else {
        salt.clone()
    });
    // Prefer comparing the computed modular crypt against stored
    let _ = rebuilt;
    Ok(ct_eq(out.as_bytes(), checksum.as_bytes())
        || ct_eq(out.as_bytes(), hash.as_bytes())
        || full_sha512_match(password, hash, &salt, rounds, &checksum))
}

fn full_sha512_match(
    password: &str,
    hash: &str,
    salt: &str,
    rounds: usize,
    checksum: &str,
) -> bool {
    let params = match Sha512Params::new(rounds) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let out = match sha512_crypt_b64(password.as_bytes(), salt.as_bytes(), &params) {
        Ok(o) => o,
        Err(_) => return false,
    };
    if ct_eq(out.as_bytes(), checksum.as_bytes()) {
        return true;
    }
    // Some implementations store full string; constant-time path via re-crypt
    // using system crypt if available is elsewhere.
    let _ = hash;
    false
}

fn verify_sha256(password: &str, hash: &str) -> CryptoResult<bool> {
    let parts: alloc::vec::Vec<&str> = hash.split('$').collect();
    if parts.len() < 4 {
        return Err(CryptoError::InvalidInput("malformed $5$ hash"));
    }
    let (rounds, salt, checksum) = parse_sha_parts(&parts[2..])?;
    let params = Sha256Params::new(rounds).map_err(|_| CryptoError::InvalidInput("rounds"))?;
    let out = sha256_crypt_b64(password.as_bytes(), salt.as_bytes(), &params)
        .map_err(|_| CryptoError::Internal("sha256_crypt failed"))?;
    Ok(ct_eq(out.as_bytes(), checksum.as_bytes()))
}

fn parse_sha_parts(parts: &[&str]) -> CryptoResult<(usize, String, String)> {
    // parts after version: either [rounds=N, salt, checksum] or [salt, checksum]
    if parts.is_empty() {
        return Err(CryptoError::InvalidInput("empty sha-crypt body"));
    }
    if parts[0].starts_with("rounds=") {
        if parts.len() < 3 {
            return Err(CryptoError::InvalidInput("sha-crypt rounds form"));
        }
        let r: usize = parts[0]["rounds=".len()..]
            .parse()
            .map_err(|_| CryptoError::InvalidInput("rounds parse"))?;
        Ok((r, String::from(parts[1]), String::from(parts[2])))
    } else {
        if parts.len() < 2 {
            return Err(CryptoError::InvalidInput("sha-crypt salt form"));
        }
        Ok((5000, String::from(parts[0]), String::from(parts[1])))
    }
}

/// Hash with SHA-512-crypt (only for interop with old systems). Prefer Argon2id for new hashes.
pub fn hash_sha512(password: &str, salt: &str, rounds: usize) -> CryptoResult<String> {
    let params = Sha512Params::new(rounds).map_err(|_| CryptoError::InvalidInput("rounds"))?;
    let out = sha512_crypt_b64(password.as_bytes(), salt.as_bytes(), &params)
        .map_err(|_| CryptoError::Internal("sha512_crypt failed"))?;
    if rounds == 5000 {
        Ok(format!("$6${salt}${out}"))
    } else {
        Ok(format!("$6$rounds={rounds}${salt}${out}"))
    }
}
