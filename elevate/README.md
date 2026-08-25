# `elevate`

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

Privilege escalation binaries: `elevate`, `elev`, `vielev`. Originally
forked from [`sudo-rs`](https://github.com/memorysafety/sudo-rs), since
reworked with its own rate limiter, policy engine, and `elevate-pam` /
`elevate-crypto` integration.

## Binaries

**`elevate`** — main privilege escalation executable, replaces `sudo`.
Forwards the caller's environment (filtered), authenticates via
`elevate-pam`, logs to `LOG_AUTHPRIV`.

**`elev`** — lightweight escalation, replaces `doas`. Skips the heavier
environment handling `elevate` does, for a faster simple-command path.

**`vielev`** — edits privilege config files under a lock, replaces
`visudo`. Verifies syntax before saving; rejects the write on error
instead of leaving a broken config in place.

## Usage

```bash
elevate systemctl restart nginx
elevate -u postgres psql
vielev
```

## License

MIT OR Apache-2.0 — see [`../LICENSE-MIT`](../LICENSE-MIT) and
[`../LICENSE-APACHE`](../LICENSE-APACHE).
