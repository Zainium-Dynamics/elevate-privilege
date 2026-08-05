//! Legacy / alternative password formats (bcrypt, DES-marker, locked accounts).

use alloc::string::String;

use crate::common::ct_eq;
use crate::error::{CryptoError, CryptoResult};

/// bcrypt `$2a$` / `$2b$` / `$2y$`
pub fn verify_bcrypt(password: &str, hash: &str) -> CryptoResult<bool> {
    if !(hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")) {
        return Err(CryptoError::Unsupported("not bcrypt"));
    }
    bcrypt::verify(password, hash).map_err(|_| CryptoError::InvalidInput("bcrypt verify"))
}

/// Hash with bcrypt (cost 12 default).
pub fn hash_bcrypt(password: &str, cost: u32) -> CryptoResult<String> {
    let cost = cost.clamp(4, 31);
    bcrypt::hash(password, cost).map_err(|_| CryptoError::Internal("bcrypt hash failed"))
}

/// Locked / disabled hash markers in shadow (`!`, `*`, `!!`).
pub fn is_locked_hash(hash: &str) -> bool {
    hash.is_empty()
        || hash.starts_with('!')
        || hash.starts_with('*')
        || hash == "!!"
        || hash == "*"
}

/// Constant-time compare two password hash strings when algorithms recompute full string.
pub fn hashes_equal(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}
