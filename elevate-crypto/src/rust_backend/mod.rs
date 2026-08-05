//! Pure-Rust crypto backend (default).
//!
//! - **Blake3** for hashing
//! - **Ed25519** for signatures
//! - Password: Argon2id, bcrypt, optional legacy SHA-crypt for shadow only

#[cfg(feature = "hash")]
pub mod blake3_hash;

#[cfg(feature = "sign")]
pub mod ed25519;

#[cfg(feature = "password")]
pub mod password;

// Keep file name for monorepo layout; SHA-crypt is password-only legacy.
#[cfg(feature = "legacy_shadow")]
pub mod sha_crypt;

#[cfg(feature = "password")]
pub mod argon;

#[cfg(feature = "password")]
pub mod legacy;
