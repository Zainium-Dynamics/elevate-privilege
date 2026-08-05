//! Argon2id password hashing (preferred new password algorithm).

use alloc::string::String;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::{CryptoError, CryptoResult};

/// Hash password with Argon2id; returns PHC string (`$argon2id$...`).
pub fn hash_password(password: &str) -> CryptoResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| CryptoError::Internal("argon2 hash failed"))
}

/// Verify password against Argon2 PHC hash.
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    let parsed = PasswordHash::new(hash).map_err(|_| CryptoError::InvalidInput("argon2 hash"))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
