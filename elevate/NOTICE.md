# NOTICE — elevate

## License

**This package is licensed under MIT OR Apache-2.0** (same as the elevate monorepo).

See:
- monorepo [`../LICENSE-MIT`](../LICENSE-MIT)
- monorepo [`../LICENSE-APACHE`](../LICENSE-APACHE)
- package [`COPYRIGHT`](COPYRIGHT)

## Upstream heritage

`elevate` (package `elevate-zainium`) is a fork of
[sudo-rs](https://github.com/trifectatechfoundation/sudo-rs), originally
created by the Trifecta Tech Foundation and contributors, itself inspired
by the original `sudo` by Todd C. Miller.

Upstream sudo-rs was dual-licensed Apache-2.0 OR MIT. This fork keeps the
same dual license, `MIT OR Apache-2.0`.

### Copyright (upstream)

```
Copyright (c) 2022-2026 Trifecta Tech Foundation and contributors
Copyright (c) 1994-1996, 1998-2024 Todd C. Miller <Todd.Miller@sudo.ws>
```

### Copyright (this fork)

```
Copyright (c) 2026 Zainium Dynamics
Author: alizain <alizain@zainiumdynamics.tech>
Website: https://zainiumdynamics.tech
```

## Zainium / elevate changes (summary)

- Binaries: `sudo` → `elevate`, `su` → `elev`, `visudo` → `viselev`
- Paths: no `/usr` — `/bin`, `/sbin`, `/lib`, `/etc`
- Policy file: `/etc/elevators/elevate.toml`
- PAM: runtime `dlopen(libelevate_pam.so)` (elevate-pam)
- Zero-Trust Core Protector for `/overlayer` paths
- License: **MIT OR Apache-2.0** (monorepo unified)

Details: [`elevate_linux_dev_guide.md`](elevate_linux_dev_guide.md)

## Known scope limitations (intentional, not silent)

- **No I/O logging / session recording** (`log_input`/`log_output`/
  `iolog_*` and their `Defaults` equivalents). Real sudo can record a
  full typescript of a privileged session for audit; `elevate` doesn't
  implement this subsystem at all yet. If your compliance/audit
  requirements need it, don't assume it's happening silently — it isn't.
- Only a curated subset of upstream sudo's ~163 `Defaults` settings is
  implemented (see the scope comment in `src/defaults/mod.rs`) — the
  ones affecting auth, environment filtering, timestamps, umask, and
  exec. Settings tied to I/O logging or command interception aren't
  recognized, for the same reason as above.
