# elevate-privilege

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)

A Rust replacement for `sudo`, `shadow-utils`, and PAM. No `systemd`,
`logind`, or D-Bus dependency — it runs on any init system, including
`quantra-system`.

`elevate` (the privilege-escalation CLI) started as a fork of
[`sudo-rs`](https://github.com/memorysafety/sudo-rs) and has since been
reworked with its own rate limiting and policy engine. `elevate-umbra`,
`elevate-crypto`, and `elevate-pam` are original implementations, not
forks.

## Layout

```
elevate-privilege/
├── elevate/         privilege escalation: elevate, elev, vielev
├── elevate-umbra/   user/group management: useradd, passwd, sulogin, etc.
├── elevate-crypto/  Argon2id / Blake3 / Ed25519, no C OpenSSL
└── elevate-pam/     PAM engine + builtin modules
```

| Component | Description |
|---|---|
| [`elevate`](elevate/README.md) | `elevate`, `elev`, `vielev` |
| [`elevate-umbra`](elevate-umbra/README.md) | `useradd`, `usermod`, `passwd`, `gpasswd`, `sulogin`, `pwck`, etc. |
| [`elevate-crypto`](elevate-crypto/README.md) | Password hashing, file-integrity hashing, signatures |
| [`elevate-pam`](elevate-pam/README.md) | PAM authentication/session engine |

## Building

Three build paths, depending on target:

| Path | Command | Produces | Notes |
|---|---|---|---|
| Host glibc (default) | `./scripts/build-all.sh` or `cargo build --release` | Everything, incl. all PAM `.so` modules | No `--target` needed |
| Generic musl-static | `./scripts/build-zainium.sh static` | Static `elevate`/`elev`/`vielev` + `elevate-umbra` | Stable Rust, rustup's own musl target — see [`elevate/MUSL_BUILD_README.md`](elevate/MUSL_BUILD_README.md) |
| Zainium OS target | `./scripts/build-zainium.sh dynamic` | PAM `.so` modules + `libelevate_pam.so` + `libelevate_crypto.so`, natively musl-linked | Needs the Zainium crosstool-NG toolchain + a pinned nightly (`-Z build-std`) — see [`targets/x86_64-zainium-linux-musl.json`](targets/x86_64-zainium-linux-musl.json) |

Rustup's stock `x86_64-unknown-linux-musl` target can't produce `cdylib`
outputs at all — its target spec's `crt-static-default: true` gates
crate-type support regardless of the resolved `crt-static` flag. That's
why the PAM modules need the real Zainium target instead of the generic
musl one. The generic musl target is still correct for fully static
binaries, since a `crt-static` build embeds its own libc and needs
nothing from any external toolchain.

`elevate-pam` also builds standalone, outside this workspace — see
[`elevate-pam/README.md`](elevate-pam/README.md#standalone-builds-any-distro-outside-the-elevate-privilege-monorepo).

## Security-relevant behavior

- No `unsafe_code` outside what FFI/syscalls require.
- Argon2id for password hashing (not MD5/SHA-crypt).
- Blake3 + Ed25519 for integrity/signature verification of the user
  database files.
- Failed-login rate limiting: penalty delay after repeated failures,
  lockout under sustained brute-force.
- Legacy `sudo` invocations are intercepted and redirected to `elevate`.

## Usage

```bash
# privilege escalation
elevate apt update
elev htop
vielev /etc/elevate.toml    # edit config under a lock

# user/group management (elevate-umbra)
useradd -m -s /bin/bash john
passwd john
usermod -L john              # lock
usermod -U john               # unlock
sulogin                       # emergency maintenance shell
```

## License

MIT OR Apache-2.0 — see [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).
