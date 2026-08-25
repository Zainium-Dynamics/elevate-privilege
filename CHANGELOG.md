# Changelog

All notable changes to the `elevate-privilege` workspace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-25

### Added
- GitHub Actions CI (check/clippy/fmt/test) and a tag-triggered release
  workflow, replacing the previous GitLab CI + zex-package pipeline.
- `elevate-pam` and `elevate-crypto` now also publish as separate
  standalone GitHub Releases alongside the main `elevate-privilege`
  release.

### Changed
- Moved `packaging/etc/` to top-level `etc/`.
- `elevate-umbra`'s shell/editor fallbacks (`newgrp`, `sulogin`,
  `newusers`, `vipw`) now resolve under the configured Zainium prefix
  instead of hardcoded bare `/bin/sh` / `/bin/vi`.
- Fixed `packaging/etc/elevate-pam/elevate-pam.toml`'s `[paths]` table,
  which still pointed at a stale bare `/bin`, `/lib`, `/etc` convention
  instead of the real `/overlayer/syshub/...` prefix.
- Cleaned up READMEs and dropped empty/stale docs across the workspace.
- All crate versions unified at `1.0.1`.

## [1.0.0] - 2026-07-26

### Added
- **`elevate-privilege` Core Suite**: Next-generation memory-safe privilege management suite written in 100% pure Rust.
- **`elevate` & `elev` binaries**: Modern replacement for `sudo` / `doas` with environment preservation (`elevate`) and minimal footprint (`elev`).
- **`vielev` binary**: Memory-safe interactive configuration editor with lockfile protection.
- **`elevate-umbra` Suite**: Full 1:1 drop-in Rust replacement for legacy `shadow-utils` (29 binaries total including `useradd`, `userdel`, `usermod`, `passwd`, `chpasswd`, `groupadd`, `gpasswd`, `sulogin`, `pwck`, `grpck`, `subuid`/`subgid` support).
- **`elevate-crypto`**: High-performance cryptographic hashing (Argon2id for passwords, Blake3 digests, Ed25519 digital signatures).
- **`elevate-pam`**: Modular Pluggable Authentication Modules engine supporting system authentication, session handling, and environment rules.
- **Brute-Force Rate Limiter Engine**: Progressive security penalty delays (30 seconds penalty on 3 failed attempts, 5-minute lockout on high-frequency attacks).
- **Password Complexity Engine (`obscure.rs`)**: Enforces min length 6, uppercase letter, special character, digit, and username mismatch rules.
- **Sudo Interceptor Shim (`sudo.rs`)**: Intercepts legacy `sudo` invocations and directs users to native `elevate`.

### Changed
- Standardized file paths using configurable prefix environment variables (`SYSHUB_PREFIX`, `SYSHUB_ETC`).
- Enforced `#![deny(unsafe_code)]` across core authentication logic.
