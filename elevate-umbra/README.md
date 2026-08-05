# `elevate-umbra` — User & Group Management Suite 👥

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)
[![Dependencies: Standalone](https://img.shields.io/badge/Dependencies-Zero%20systemd-brightgreen.svg)](#standalone-architecture)

**`elevate-umbra`** is a complete, 1:1 drop-in Rust replacement for legacy `shadow-utils` (`shadow-4.17.2`). It provides 29 production-grade user/group administration tools and authentication binaries.

---

## ⚡ Standalone Architecture

- **Zero `systemd` Requirement**: Operates independently of systemd, logind, or DBus.
- **Zero External Dependencies**: Relies solely on workspace ecosystem crates (`elevate-crypto`, `elevate-pam`).
- **Musl & Glibc Compatible**: Designed for lightweight, embedded, containerized, and custom distribution environments.

---

## 🛠️ Complete Binary List (29 Binaries)

| Category | Binaries |
|:---|:---|
| **User Administration** | `useradd`, `userdel`, `usermod`, `newusers` |
| **Group Administration** | `groupadd`, `groupdel`, `groupmod`, `gpasswd`, `groupmems`, `newgrp` |
| **Password & Expiry** | `passwd`, `chpasswd`, `chgpasswd`, `chage`, `expiry`, `obscure` |
| **User Information** | `chfn`, `chsh`, `nologin` |
| **Integrity & Verification** | `pwck`, `grpck`, `vipw`, `umbra-sign` |
| **Shadow Conversion** | `pwconv`, `pwunconv`, `grpconv`, `grpunconv` |
| **Security & Rescue** | `sulogin` (Rescue Shell), `faillog`, `sudo` (Blocker Interceptor) |

---

## 🛡️ Key Security Improvements Over Legacy Shadow

1. **Memory Safety**: 100% Rust implementation eliminating C buffer overflows, use-after-free, and format string vulnerabilities.
2. **Brute-Force Rate Limiting Engine (`ratelimit.rs`)**:
   - 30-second penalty delay on 3 failed attempts.
   - 5-minute lockout on high-frequency brute-force attacks.
3. **Password Quality Enforcement (`obscure.rs`)**:
   - Enforces min length (6+ chars), capital letters, numbers, special chars, and username mismatch.
4. **Subordinate ID Engine (`subordinateio.rs`)**:
   - Native support for `/etc/subuid` and `/etc/subgid` ranges.
5. **Legacy `sudo` Interceptor (`sudo.rs`)**:
   - Intercepts and blocks legacy `sudo` calls, directing users to native `elevate`.

---

## 📄 License

Distributed under your choice of the **MIT license** or the **Apache License 2.0**. See [`../LICENSE-MIT`](../LICENSE-MIT) and [`../LICENSE-APACHE`](../LICENSE-APACHE) for details.
