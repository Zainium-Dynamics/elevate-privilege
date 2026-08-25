//! # elevate-crypto
//!
//! **Pure Rust** cryptography for the elevate monorepo.
//! **No C OpenSSL / libcrypto** — everything is implemented in Rust.
//!
//! | Purpose | Algorithm |
//! |---------|-----------|
//! | Hash | **Blake3** |
//! | Sign | **Ed25519** |
//! | Password | Argon2id / bcrypt / legacy shadow (`$5$`/`$6$`) |
//! | RNG | OS CSPRNG via `getrandom` |
//!
//! SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod common;
pub mod error;

#[cfg(any(feature = "hash", feature = "sign", feature = "password"))]
pub mod rust_backend;

/// Pure-Rust secure RNG (replaces OpenSSL `RAND_bytes`).
#[cfg(feature = "std")]
pub mod random;

#[cfg(feature = "system_crypt")]
pub mod system_crypt;

pub use error::{CryptoError, CryptoResult};

// ---- Blake3 ----

/// Hash data with Blake3 (32-byte digest).
#[cfg(feature = "hash")]
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    rust_backend::blake3_hash::hash(data)
}

/// Blake3 over multiple parts.
#[cfg(feature = "hash")]
pub fn hash_blake3_parts(parts: &[&[u8]]) -> [u8; 32] {
    rust_backend::blake3_hash::hash_parts(parts)
}

/// Blake3 keyed MAC.
#[cfg(feature = "hash")]
pub fn mac_blake3(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    rust_backend::blake3_hash::keyed_mac(key, data)
}

/// Blake3 key derivation.
#[cfg(feature = "hash")]
pub fn derive_key_blake3(context: &str, ikm: &[u8]) -> [u8; 32] {
    rust_backend::blake3_hash::derive_key(context, ikm)
}

// ---- Ed25519 ----

/// Generate Ed25519 keypair → (public, secret seed).
#[cfg(feature = "sign")]
pub fn generate_ed25519_keypair() -> ([u8; 32], [u8; 32]) {
    rust_backend::ed25519::generate_keypair()
}

/// Sign message with Ed25519 secret seed.
#[cfg(feature = "sign")]
pub fn sign_ed25519(secret: &[u8; 32], message: &[u8]) -> CryptoResult<[u8; 64]> {
    rust_backend::ed25519::sign(secret, message)
}

/// Verify Ed25519 signature.
#[cfg(feature = "sign")]
pub fn verify_ed25519(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> CryptoResult<()> {
    rust_backend::ed25519::verify(public, message, signature)
}

// ---- Password ----

/// Verify password against modular crypt / PHC hash string.
#[cfg(feature = "password")]
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    rust_backend::password::verify_password(password, hash)
}

/// Hash password with Argon2id (preferred for new accounts).
#[cfg(feature = "password")]
pub fn hash_password(password: &str) -> CryptoResult<alloc::string::String> {
    rust_backend::password::hash_password(password)
}

/// Hash password with bcrypt.
#[cfg(feature = "password")]
pub fn hash_password_bcrypt(password: &str, cost: u32) -> CryptoResult<alloc::string::String> {
    rust_backend::password::hash_password_bcrypt(password, cost)
}

/// Classify a password hash string.
#[cfg(feature = "password")]
pub use rust_backend::password::{classify as classify_password_hash, HashKind};

/// Fill buffer with CSPRNG bytes (pure Rust / OS getrandom).
#[cfg(feature = "std")]
pub fn secure_random(buf: &mut [u8]) -> CryptoResult<()> {
    random::fill(buf)
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Constant-time byte compare.
pub use common::ct_eq;
