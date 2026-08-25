# `elevate-pam`

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

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

## Standalone builds (any distro, outside the elevate-privilege monorepo)

`elevate-pam/pam` builds on its own — it doesn't require the rest of
the `elevate-privilege` workspace. Its `Cargo.toml` pins explicit
dependency versions rather than `.workspace = true` inheritance
specifically so it stays buildable when extracted by itself (that
inheritance syntax requires a parent `[workspace]`, which a standalone
checkout won't have).

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

If you don't want the `elevate-crypto` dependency, build without the
default features that pull it in:

```sh
cargo build --release --no-default-features \
  --features std,dynload,syslog,secure_mem,fail_delay,builtin_modules
```

By default `elevate-pam` looks for its config/module/policy paths under
`/overlayer/syshub/...` (Zainium OS's layout). On any other distro,
point it at your own layout instead — no code changes needed:

- `ELEVATE_PRIVILEGE_TOML=/path/to/your/elevate_privilege.toml` — full
  config file with your own `[paths]` table, or
- `SYSHUB_PREFIX=/usr` / `SYSHUB_ETC=/etc` — quick overrides for a
  single value.

See `elevate-paths/src/lib.rs` for the full resolution order and every
derived path.

## License

MIT OR Apache-2.0 — see [`../LICENSE-MIT`](../LICENSE-MIT) and
[`../LICENSE-APACHE`](../LICENSE-APACHE).
