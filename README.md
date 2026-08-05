# Elevate Privilege Suite ⚡

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Security: Memory Safe](https://img.shields.io/badge/Security-Memory%20Safe-green.svg)](#security-architecture)
[![Dependencies: Standalone](https://img.shields.io/badge/Dependencies-Zero%20systemd-brightgreen.svg)](#standalone--systemd-free-architecture)
[![AI Policy: Strict](https://img.shields.io/badge/AI%20Policy-Strict-red.svg)](AI_POLICY.md)

**`elevate-privilege`** is a production-grade, high-security privilege escalation, user management, and authentication suite written in **100% pure Rust**. Built as a modern, memory-safe replacement for legacy utility suites (`sudo`, `shadow-utils`, `doas`, `PAM`), it provides complete 1:1 functional parity while adding modern cryptographic safeguards.

---

> [!NOTE]
> **Project Origin & Lineage**: The core `elevate` CLI was originally forked and derived from [`sudo-rs`](https://github.com/memorysafety/sudo-rs). It has since been heavily customized, enhanced, and hardened with custom security engines, anti-brute-force rate limiters, and strict password policies. 
> 
> All other ecosystem components — including **`elevate-umbra`** (the 29-binary shadow utility suite), **`elevate-crypto`**, and **`elevate-pam`** — are **100% native implementations** built entirely from scratch. All sub-crates are consolidated into this unified workspace so that developers and systems engineers can build the entire authentication stack in a single compile pass without needing external library dependencies.

---

## 🚀 Standalone & Systemd-Free Architecture

- **Zero `systemd` Requirement**: `elevate-privilege` is completely decoupled from `systemd`, `logind`, or DBus. It runs natively on any Linux init system (`sysvinit`, `runit`, `s6`, `quantra-system`, or standalone init).
- **Self-Contained Ecosystem**: Requires **NO external library dependencies** outside the internal workspace crates (`elevate-pam`, `elevate-crypto`, `elevate-umbra`).
- **Portable & Musl-Friendly**: Fully compatible with both `glibc` and `musl` toolchains for lightweight, containerized, embedded, or custom distribution builds.

---

## 🏛️ Architecture Overview

The `elevate-privilege` workspace consists of four modular, independent crates:

```
elevate-privilege/
├── elevate/         # Privilege escalation binaries (elevate, elev, vielev)
├── elevate-umbra/   # User management suite (useradd, userdel, passwd, sulogin, etc.)
├── elevate-crypto/  # Cryptographic engine (Argon2id, Blake3, Ed25519)
└── elevate-pam/     # Pluggable Authentication Modules (PAM) engine
```

---

## 📦 Workspace Component Summary

| Component | Description | Primary Targets / Features |
|:---|:---|:---|
| **[`elevate`](elevate/README.md)** | Core privilege escalation CLI | `elevate`, `elev`, `vielev` |
| **[`elevate-umbra`](elevate-umbra/README.md)** | User & group management suite | `useradd`, `userdel`, `usermod`, `passwd`, `gpasswd`, `sulogin`, `pwck`, etc. |
| **[`elevate-crypto`](elevate-crypto/README.md)** | Modern cryptographic library | Argon2id password hashing, Blake3 digests, Ed25519 signatures |
| **[`elevate-pam`](elevate-pam/README.md)** | Authentication & session engine | PAM authentication, environment management, session controls |

---

## 🏗️ Building

Three build paths, depending on target:

| Path | Command | Produces | Notes |
|:---|:---|:---|:---|
| **Host glibc** (default) | `./scripts/build-all.sh` or `cargo build --release` | Everything, incl. all PAM `.so` modules | No `--target` needed; works on any glibc dev machine |
| **Generic musl-static** | `./scripts/build-zainium.sh static` | Static `elevate`/`elev`/`vielev` + `elevate-umbra` binaries | Stable Rust, rustup's own musl target (see [`elevate/MUSL_BUILD_README.md`](elevate/MUSL_BUILD_README.md)) |
| **Zainium OS target** | `./scripts/build-zainium.sh dynamic` | PAM `.so` modules + `libelevate_pam.so` + `libelevate_crypto.so`, natively musl-linked | Needs the Zainium crosstool-NG toolchain + a pinned nightly (`-Z build-std`) — see [`targets/x86_64-zainium-linux-musl.json`](targets/x86_64-zainium-linux-musl.json) and [`scripts/build-zainium.sh`](scripts/build-zainium.sh) |

Rustup's stock `x86_64-unknown-linux-musl` target cannot produce `cdylib`
outputs at all (its target spec's `crt-static-default: true` gates
crate-type support regardless of the resolved `crt-static` flag) — that's
why PAM modules need the real Zainium target above rather than the generic
musl one. The generic musl target is still exactly right for fully static
binaries, since a `crt-static` build embeds its own libc and needs nothing
from any external toolchain.

`elevate-pam` itself also builds completely standalone, outside this
workspace — see [`elevate-pam/README.md`](elevate-pam/README.md#-standalone-builds-any-distro-outside-the-elevate-privilege-monorepo).

---

## 🔐 Security Architecture

- **Memory Safety Guaranteed**: Pure Rust implementation with strict safety checks (`#![deny(unsafe_code)]`).
- **Argon2id Hashing**: Replaces legacy MD5/SHA-crypt password hashing with industry-standard Argon2id.
- **Cryptographic File Verification**: Integrates Blake3 hashing and Ed25519 hardware-verifiable signatures for system user database files (`/etc/passwd`, `/etc/shadow`).
- **Anti-Brute-Force Rate Limiting**: Progressive penalty delays (30 seconds penalty on 3 failures, 5-minute lockout on high-frequency brute-force attacks).
- **Password Complexity Rules**: Enforces minimum length (6+ chars), uppercase characters, numeric digits, special characters, and username/password mismatch.
- **Legacy Sudo Interceptor**: Prevents legacy `sudo` invocation by directing users to native `elevate`.

---

## 🛠️ Usage Quickstart

### Privilege Escalation

```bash
# Execute command with root privileges (preserves user environment)
elevate apt update

# Execute minimal privilege escalation
elev htop

# Safely edit configuration with lock protection
vielev /etc/elevate.toml
```

### User & Group Management (`elevate-umbra`)

```bash
# Add a new user with home directory and subids
useradd -m -s /bin/bash john

# Change password (enforces Argon2id & complexity checks)
passwd john

# Lock or unlock user account
usermod -L john
usermod -U john

# Emergency maintenance mode
sulogin
```

---

## 📄 License

Distributed under your choice of the **MIT license** or the **Apache License 2.0**.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE) for details.
