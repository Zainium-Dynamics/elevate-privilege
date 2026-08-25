# `elevate-umbra`

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

A drop-in Rust replacement for `shadow-utils` (targeting `shadow-4.17.2`
parity). 29 binaries, no `systemd`/`logind`/D-Bus dependency, no external
crates outside this workspace (`elevate-crypto`, `elevate-pam`). Builds
for both musl and glibc.

## Binaries

| Category | Binaries |
|---|---|
| User administration | `useradd`, `userdel`, `usermod`, `newusers` |
| Group administration | `groupadd`, `groupdel`, `groupmod`, `gpasswd`, `groupmems`, `newgrp` |
| Password & expiry | `passwd`, `chpasswd`, `chgpasswd`, `chage`, `expiry`, `obscure` |
| User information | `chfn`, `chsh`, `nologin` |
| Integrity & verification | `pwck`, `grpck`, `vipw`, `umbra-sign` |
| Shadow conversion | `pwconv`, `pwunconv`, `grpconv`, `grpunconv` |
| Security & rescue | `sulogin`, `faillog`, `sudo` (blocks legacy `sudo`, redirects to `elevate`) |

## Differences from legacy shadow-utils

- Memory-safe: no buffer overflows, use-after-free, or format-string
  bugs from the C implementation.
- Failed-login rate limiting (`ratelimit.rs`): penalty delay after
  repeated failures, lockout under sustained brute-force attempts.
- Password quality checks (`obscure.rs`): minimum length, case mix,
  digits, special characters, rejects passwords matching the username.
- Native `/etc/subuid` / `/etc/subgid` handling (`subordinateio.rs`).
- `sudo` here is a blocker/interceptor, not a real implementation — it
  exists so scripts calling `sudo` fail loudly toward `elevate` instead
  of silently doing the wrong thing.

## License

MIT OR Apache-2.0 — see [`../LICENSE-MIT`](../LICENSE-MIT) and
[`../LICENSE-APACHE`](../LICENSE-APACHE).
