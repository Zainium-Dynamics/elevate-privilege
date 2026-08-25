# `elevate-crypto`

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

Pure-Rust crypto backing password hashing and file-integrity checks
across the workspace. No C OpenSSL/libcrypt dependency (the one
exception is the optional `system_crypt` feature, for legacy
`/etc/shadow` hash formats pure Rust doesn't cover).

## What's in it

- **Argon2id** password hashing — memory-hard, resists GPU/ASIC
  brute-forcing. Salts via `getrandom`.
- **Blake3** file hashing — used to detect offline tampering of
  `/etc/passwd` / `/etc/shadow` / `/etc/group`.
- **Ed25519** signatures — verification for user-management data
  integrity.

## Usage

```rust
use elevate_crypto::{hash_password, verify_password};

let hash = hash_password("SecretPassword123!").unwrap();
assert!(verify_password("SecretPassword123!", &hash).unwrap_or(false));
```

## License

MIT OR Apache-2.0 — see [`../LICENSE-MIT`](../LICENSE-MIT) and
[`../LICENSE-APACHE`](../LICENSE-APACHE).
