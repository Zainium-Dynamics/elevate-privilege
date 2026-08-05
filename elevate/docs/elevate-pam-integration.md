# elevate ↔ elevate-pam integration (Zainium)

elevate does **not** link `-lpam`. At runtime it loads **elevate-pam**:

```
dlopen("libelevate_pam.so.0")   # preferred
dlopen("libelevate_pam.so")
dlopen("/lib/libelevate_pam.so.0")
…
```

Code: `src/pam/dynload.rs`.

## Zainium paths (no /usr)

| Component | Path |
|-----------|------|
| elevate binary | `/bin/elevate` |
| elev | `/bin/elev` |
| viselev | `/sbin/viselev` |
| elevate-pam library | `/lib/libelevate_pam.so.0` |
| modules | `/lib/security/` |
| auth stacks (TOML) | `/etc/elevate-pam/services/` |
| elevate policy | `/etc/elevators/elevate.toml` |

## Install order

1. Build & install **elevate-pam** (repo `elevate-pam`):
   ```bash
   DESTROOT=/path/to/overlayer/syshub ./scripts/install-dev.sh
   # or bare metal:
   ./scripts/install-dev.sh
   ```
2. Build & install **elevate** (this repo):
   ```bash
   cargo build --release
   install -m 4755 target/.../elevate /bin/elevate
   install -m 4755 target/.../elev    /bin/elev
   install -m 0755 target/.../viselev /sbin/viselev
   ```

## Service names

| Call site | Service |
|-----------|---------|
| `pam_start("elevate", …)` | `elevate.toml` |
| `pam_start("elev", …)` | `elev.toml` |
| `pam_start("elev-l", …)` | `elev-l.toml` |

Legacy `/etc/pam.d/*` files in `pam.d/` are optional docs only; production stacks are TOML under elevate-pam.

## Fallback

`ELEVATE_ALLOW_LIBPAM=1` allows classic `libpam.so` if elevate-pam is missing (dev/foreign hosts only).
