# `elevate-pam` — Pluggable Authentication Engine 🔑

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

**`elevate-pam`** provides a modern, modular Pluggable Authentication Module (PAM) architecture for Unix-like operating systems. Written in Rust, it ensures memory safety while performing critical authentication, account validation, session management, and password updates.

---

## 🏗️ Architecture

`elevate-pam` supports standard PAM facilities:
- **`auth`**: Authenticates users against shadow hashes or crypto tokens.
- **`account`**: Validates account expiration, password aging, and access controls.
- **`session`**: Handles session setup, environment initialization, and teardown.
- **`password`**: Manages interactive password updates with quality checks.

---

## 🔒 Security Features

- **Environment Isolation**: Cleans and validates environment variables (`TERM`, `PATH`, `SHELL`, `LANG`) during session initialization.
- **Account Locking**: Built-in support for account lockouts after consecutive failed logins.
- **Syslog Audit**: Integrated auditing via syslog (`LOG_AUTHPRIV`).

---

## 📦 Native PAM Modules (100% Parity)

`elevate-pam` includes built-in and modular implementations of all standard Linux PAM facilities:
- **Built-in Handlers**: `pam_permit`, `pam_deny`, `pam_rootok`, `pam_unix`, `pam_env`, `pam_limits`, `pam_wheel`, `pam_nologin`, `pam_securetty`, `pam_shells`, `pam_motd`, `pam_umask`, `pam_exec`, `pam_succeed_if`, `pam_mail`, `pam_faildelay`, `pam_warn`, `pam_issue`, `pam_localuser`, `pam_usertype`, `pam_echo`, `pam_debug`.
- **Modular Crates**: `pam-access`, `pam-faillock`, `pam-mkhomedir`, `pam-namespace`, `pam-tally2`, `pam-pwhistory`, `pam-loginuid`.

---

## 🧩 Standalone builds (any distro, outside the elevate-privilege monorepo)

`elevate-pam/pam` builds on its own — it doesn't require the rest of the
`elevate-privilege` workspace. Its `Cargo.toml` pins explicit dependency
versions rather than `.workspace = true` inheritance specifically so it
stays buildable when extracted by itself (that inheritance syntax requires
a parent `[workspace]`, which a standalone checkout won't have).

To build it outside this repo, vendor two small sibling directories
alongside `pam/` (they're path dependencies, not published crates):

```
your-tree/
├── elevate-paths/   # tiny: single source of truth for install paths
├── elevate-crypto/  # optional: pure-Rust Blake3/Ed25519/password crypto
└── elevate-pam/pam/ # this crate
```

```sh
cd elevate-pam/pam
cargo build --release
```

If you don't want the `elevate-crypto` dependency at all, build without the
default features that pull it in:

```sh
cargo build --release --no-default-features \
  --features std,dynload,syslog,secure_mem,fail_delay,builtin_modules
```

By default `elevate-pam` looks for its config/module/policy paths under
`/overlayer/syshub/...` (Zainium OS's layout). On any other distro, point
it at your own layout instead — no code changes needed:

- `ELEVATE_PRIVILEGE_TOML=/path/to/your/elevate_privilege.toml` — full
  config file with your own `[paths]` table, or
- `SYSHUB_PREFIX=/usr` / `SYSHUB_ETC=/etc` — quick overrides for a single
  value.

See `elevate-paths/src/lib.rs` for the full resolution order and every
derived path.

---

## 📄 License

Distributed under your choice of the **MIT license** or the **Apache License 2.0**. See [`../LICENSE-MIT`](../LICENSE-MIT) and [`../LICENSE-APACHE`](../LICENSE-APACHE) for details.
