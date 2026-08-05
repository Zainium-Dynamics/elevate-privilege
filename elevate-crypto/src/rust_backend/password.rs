//! Unified password verify / hash (libxcrypt-class front door).

use alloc::string::String;

use crate::error::CryptoResult;

// CryptoError is used conditionally
#[cfg(not(feature = "system_crypt"))]
use crate::error::CryptoError;
use crate::rust_backend::{argon, legacy};

#[cfg(feature = "legacy_shadow")]
use crate::rust_backend::sha_crypt;

/// Detected password hash family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// Argon2 PHC.
    Argon2,
    /// bcrypt `$2?$`.
    Bcrypt,
    /// SHA-256-crypt `$5$` (legacy shadow only).
    Sha256Crypt,
    /// SHA-512-crypt `$6$` (legacy shadow only).
    Sha512Crypt,
    /// yescrypt `$y$` (system crypt if enabled).
    Yescrypt,
    /// Locked / invalid.
    Locked,
    /// Unknown prefix.
    Unknown,
}

/// Classify a stored hash string.
pub fn classify(hash: &str) -> HashKind {
    if legacy::is_locked_hash(hash) {
        return HashKind::Locked;
    }
    if hash.starts_with("$argon2") {
        return HashKind::Argon2;
    }
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
        return HashKind::Bcrypt;
    }
    if hash.starts_with("$6$") {
        return HashKind::Sha512Crypt;
    }
    if hash.starts_with("$5$") {
        return HashKind::Sha256Crypt;
    }
    if hash.starts_with("$y$") {
        return HashKind::Yescrypt;
    }
    HashKind::Unknown
}

/// Verify `password` against modular-crypt / PHC `hash`.
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    match classify(hash) {
        HashKind::Locked => Ok(false),
        HashKind::Argon2 => argon::verify_password(password, hash),
        HashKind::Bcrypt => legacy::verify_bcrypt(password, hash),
        #[cfg(feature = "legacy_shadow")]
        HashKind::Sha512Crypt | HashKind::Sha256Crypt => sha_crypt::verify(password, hash),
        #[cfg(not(feature = "legacy_shadow"))]
        HashKind::Sha512Crypt | HashKind::Sha256Crypt => {
            // Fall through to system crypt if enabled
            system_crypt_verify(password, hash)
        }
        HashKind::Yescrypt => system_crypt_verify(password, hash),
        HashKind::Unknown => system_crypt_verify(password, hash),
    }
}

/// Create a new password hash (Argon2id by default — preferred for elevate).
pub fn hash_password(password: &str) -> CryptoResult<String> {
    argon::hash_password(password)
}

/// Hash with bcrypt (interop).
pub fn hash_password_bcrypt(password: &str, cost: u32) -> CryptoResult<String> {
    legacy::hash_bcrypt(password, cost)
}

fn system_crypt_verify(password: &str, hash: &str) -> CryptoResult<bool> {
    #[cfg(feature = "system_crypt")]
    {
        return crate::system_crypt::verify(password, hash);
    }
    #[cfg(not(feature = "system_crypt"))]
    {
        let _ = (password, hash);
        Err(CryptoError::Unsupported(
            "password hash format not available in pure-Rust build (enable system_crypt or legacy_shadow)",
        ))
    }
}
