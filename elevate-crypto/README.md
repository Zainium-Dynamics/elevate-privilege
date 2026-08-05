# `elevate-crypto` — Cryptographic Library 🛡️

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

**`elevate-crypto`** is the cryptographic engine powering password hashing and file integrity verification across the `elevate-privilege` workspace.

---

## 🔑 Key Features

### 1. Argon2id Password Hashing
Uses standard Argon2id algorithm for password hashing:
- Memory-hard function designed to resist GPU and ASIC brute-force cracking.
- Salt generation via cryptographically secure random number generators (`getrandom`).

### 2. Blake3 Fast File Hashing
High-speed hashing for system databases (`/etc/passwd`, `/etc/shadow`, `/etc/group`):
- Provides cryptographic digests to detect offline tampering.

### 3. Ed25519 Digital Signatures
Cryptographic signature verification for user management data files:
- Enables hardware-backed key verification for authentication state integrity.

---

## 🛠️ Usage Example

```rust
use elevate_crypto::{hash_password, verify_password};

fn main() {
    let password = "SecretPassword123!";
    
    // Hash password using Argon2id
    let hash = hash_password(password).unwrap();
    
    // Verify password against hash
    let is_valid = verify_password(password, &hash).unwrap_or(false);
    assert!(is_valid);
}
```

---

## 📄 License

Distributed under your choice of the **MIT license** or the **Apache License 2.0**. See [`../LICENSE-MIT`](../LICENSE-MIT) and [`../LICENSE-APACHE`](../LICENSE-APACHE) for details.
