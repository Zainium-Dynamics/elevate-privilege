# `elevate-pam`

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)

A modular PAM implementation in Rust: `auth`, `account`, `session`,
`password` facilities, TOML-configured (no `/etc/pam.d` text format).

## Facilities

- **`auth`** — authenticates against shadow hashes or crypto tokens.
- **`account`** — expiration, password aging, access control checks.
- **`session`** — session setup/teardown, environment initialization.
- **`password`** — interactive password updates with quality checks.

## Behavior notes

- Environment is cleaned/validated on session init (`TERM`, `PATH`,
  `SHELL`, `LANG`).
- Account lockout after consecutive failed logins is built in, not a
  separate module you have to remember to stack.
- Audit goes to syslog (`LOG_AUTHPRIV`).

## Built-in / modular coverage

Built in: `pam_permit`, `pam_deny`, `pam_rootok`, `pam_unix`,
`pam_env`, `pam_limits`, `pam_wheel`, `pam_nologin`, `pam_securetty`,
`pam_shells`, `pam_motd`, `pam_umask`, `pam_exec`, `pam_succeed_if`,
`pam_mail`, `pam_faildelay`, `pam_warn`, `pam_issue`, `pam_localuser`,
`pam_usertype`, `pam_echo`, `pam_debug`.

Separate crates: `pam-access`, `pam-faillock`, `pam-mkhomedir`,
`pam-namespace`, `pam-tally2`, `pam-pwhistory`, `pam-loginuid`.

## Build

```sh
make            # cargo build --workspace --release
make test       # cargo test --workspace
make check-nostd
```

The only external sibling is [`elevate-crypto`](https://github.com/Zainium-Dynamics/elevate-crypto)
(pure-Rust Blake3 / Ed25519 / password hashing), pulled in as a git
dependency behind the default `elevate_crypto` feature. To build without it:

```sh
cargo build --release -p elevate-pam --no-default-features \
  --features std,dynload,syslog,secure_mem,fail_delay,builtin_modules
```

## Configuration and paths

elevate-pam reads everything from `elevate-pam.toml`, found at the first of:

1. `$ELEVATE_PAM_CONFIG`
2. `/etc/elevate-pam/elevate-pam.toml`
3. `/etc/elevate-pam.toml`
4. `./elevate-pam.toml`

Install locations are set in its `[paths]` table. All keys are optional and
derive from `prefix` (default empty, meaning `/`), so changing only `prefix`
moves everything:

```toml
[paths]
prefix = "/opt/pam"              # etc_dir, conf_dir, module_dir, ... follow
# etc_dir    = "<prefix>/etc"                    # passwd, shadow, security/*
# conf_dir   = "<etc_dir>/elevate-pam"           # services/, services.d/
# module_dir = "<prefix>/lib/security"           # pam_*.so
# vendor_dir = "<prefix>/lib/elevate-pam/services"
# var_dir    = "<prefix>/var/run/elevate"        # faillock, tallylog, timestamps
```

With no config file the conventional Linux layout is used. A reference
config is in [`etc/elevate-pam/elevate-pam.toml`](etc/elevate-pam/elevate-pam.toml);
service stacks are in [`etc/elevate-pam/services/`](etc/elevate-pam/services).

## Install

```sh
sudo make install                       # real /lib, /etc, /bin
make install DESTDIR=$PWD/pkg           # staged, for packaging
make install PREFIX=/opt/pam            # relocated; bakes prefix into the config
```

For a relocated install, run consumers with
`ELEVATE_PAM_CONFIG=/opt/pam/etc/elevate-pam/elevate-pam.toml`.

## Layout

```
pam/             core engine (libelevate_pam: rlib, cdylib, staticlib)
libpam-abi/      libpam.so.0-compatible C ABI shim
libpam-misc/     pam_misc helpers
elevate-pam-cli/ elevate-pam CLI
pam-*/           loadable modules (pam_unix.so, pam_faillock.so, ...)
helpers/         unix_chkpwd
etc/             reference config and service stacks
include/         C headers (security/pam_*.h)
```

Related projects: [`elevate`](https://github.com/Zainium-Dynamics/elevate)
(sudo/su replacement), [`elevate-umbra`](https://github.com/Zainium-Dynamics/elevate-umbra)
(shadow-utils replacement), [`elevate-crypto`](https://github.com/Zainium-Dynamics/elevate-crypto).

## License

MIT OR Apache-2.0 — see [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).
