# elevate_linux_dev_guide.md

A developer's guide to the Zainium Dynamics `elevate` project: what it is and
how it's put together. For upstream heritage/attribution, see
[`NOTICE.md`](NOTICE.md) — this guide doesn't repeat that here.

---

## 1. What this project is

`elevate` provides privilege escalation for **Zainium OS** — a custom Linux
distribution with:

- **No merged `/usr`** — binaries live directly under `/bin`, `/sbin`,
  `/lib`, not `/usr/bin` etc.
- **musl libc**, not glibc, as the system C library.
- A unique immutable-base + writable-overlay architecture
  (`/overlayer/syshub` = read-only base OS, `/overlayer/zexlib` = writable
  package layer).
- A custom init system (`quantra`) and package manager (`zex`).

Three binaries are produced:

| Binary | Purpose |
|---|---|
| `elevate` | Run a command as another user (usually root) |
| `elev` | Switch user / start a shell as another user |
| `viselev` | Safely edit the elevators permissions config file |

---

## 2. Project identity

| Item | Value |
|---|---|
| Cargo package name | `elevate` |
| Folder name | `elevate/` |
| Source modules | `src/elevate/`, `src/elev/`, `src/vielev/`, `src/elevators/` |
| Crate entry points (used in `src/bin/*.rs`) | `elevate::elevate_main()`, `elevate::su_main()`, `elevate::viselev_main()` |

The compiled binary names (`elevate`, `elev`, `viselev`) are controlled via
`[[bin]]` sections in `Cargo.toml`.

---

## 3. Path layout: no `/usr`

Zainium has no `/usr` hierarchy at all — everything lives directly under
`/bin`, `/sbin`, `/lib`, `/etc`. Relevant defaults:

- `PATH_DEFAULT` (`src/elevate/env/environment.rs`): `/overlayer/syshub/bin:/bin:/sbin`
- `zoneinfo_path()` (`src/system/audit.rs`): checks `/etc/zoneinfo` then `/lib/zoneinfo` (no `/usr/share/zoneinfo`)
- `SYSTEM_EDITOR` (`src/defaults/mod.rs`): `/bin/nano:/bin/vi`

---

## 4. Config file: `/etc/elevators/elevate.toml`

The permissions file lives at `/etc/elevators/elevate.toml`. Despite the
`.toml` extension, this is **not** parsed as TOML — it's classic sudoers-style
grammar (`User_Alias`, `Cmnd_Alias`, `user ALL=(ALL) ALL`, etc.) handled by
`src/elevators/`. The extension is a naming convention only; rewriting the
grammar itself to real TOML has been considered and rejected as too high-risk
for a single pass.

`viselev` edits the same path and includes a self-lockout safety check (warns
you if you've edited yourself out of permission to run `viselev` again).

---

## 5. PAM: `elevate-pam`, not classic Linux-PAM

`elevate` never links `-lpam` at build time (`#[link(name = "pam")]` was
removed from `src/pam/mod.rs`). At runtime, `src/pam/dynload.rs` resolves the
12 required PAM functions via `dlsym()`, loading the library in this order:

1. `libelevate_pam.so.0` / `libelevate_pam.so` / `libelevate_pam.so.1` (and
   the absolute `/lib/libelevate_pam.so*` paths — Zainium has no `/usr`) —
   this project's own PAM engine, built from the `elevate-pam` workspace
   member.
2. Only if `ELEVATE_ALLOW_LIBPAM=1` is explicitly set: classic `libpam.so.0` /
   `libpam.so` / `libpam.so.1` — a migration escape hatch for foreign/dev
   hosts that don't have `elevate-pam` installed yet.

If neither is found, `elevate` exits with a fatal error rather than silently
falling back. See [`docs/elevate-pam-integration.md`](docs/elevate-pam-integration.md)
for install paths and service-stack locations.

### musl static build

Building targets `x86_64-unknown-linux-musl` with `crt-static` on (see
`.cargo/config.toml`). Since PAM is loaded via `dlopen()` rather than linked,
`crt-static` doesn't conflict with it — the result is a single
dependency-free binary that runs on both glibc and musl systems.

### PAM service names

| Zainium service name | Used by |
|---|---|
| `elevate` (`elevate-i` if `pam-login` feature enabled) | `elevate` |
| `elev` | `elev` (non-login) |
| `elev-l` | `elev -` / `elev --login` |
| *(none — `viselev` doesn't authenticate)* | `viselev` |

`elevate-i` is not created by default — the `pam-login` Cargo feature that
would require it is off unless you specifically need split
`elevate`/`elevate-i` services.

Matching `/etc/pam.d/` stacks (optional; production stacks are TOML under
`elevate-pam`, see section 4 above and `elevate-pam-integration.md`):

- `pam.d/elevate` — mirrors the standard privilege-escalation PAM stack
  (`pam_env.so`, `pam_unix.so`, `pam_limits.so`).
- `pam.d/elev` — mirrors the standard user-switch PAM stack
  (`pam_rootok.so`, `pam_unix.so`, `pam_xauth.so`).
- `pam.d/elev-l` — login-mode variant, adding `pam_env.so`.

---

## 6. Zainium Zero-Trust Core Protector

`src/core_protector.rs` blocks destructive filesystem operations from
targeting Zainium's immutable OS core layers — **even when run as root**.

### 6.1 What it does

- **Triggers on these commands:** `rm`, `rmdir`, `mv`, `shred`, `unlink`
  (matched by base filename, so `/bin/rm` and `rm` are treated identically).
- **Blocks any argument** that is exactly, or is a path *underneath* (prefix
  match), any of:
  - `/overlayer`
  - `/overlayer/syshub`
  - `/overlayer/zaisys`
- **One narrow exception:** the exact command line `zex syshub -u` (the
  legitimate system-upgrade command) is allowed through unconditionally. The
  match is intentionally strict — any extra or different flags will *not*
  match the override, by design.
- Trailing slashes are normalized (`/overlayer/` matches the same as
  `/overlayer`), and similar-but-distinct paths are correctly **not** matched
  (`/overlayer-backup` does NOT trigger the block).

### 6.2 Where it's wired in

The check runs in both privilege-escalation paths, immediately after the
target command and arguments are fully resolved but **before** the actual
`execve()`-equivalent call:

- `src/elevate/pipeline.rs`, in `run()`.
- `src/elev/mod.rs`, in the run path.

A blocked command exits with status `77` and prints:

```
Zainium Security Violation: Modification of Core OS layers is strictly prohibited
Blocked path: /overlayer/syshub/bin/ls
This action was blocked by the Zero-Trust Core Protector, even though you are root.
```

### 6.3 Important limitation — read this before relying on it

This is a **userspace, application-level** check. It only protects commands
launched *through* `elevate`/`elev`. It does **not** stop:

- A destructive command run from an already-open root shell (e.g. `elevate
  bash`, then typing `rm -rf /overlayer` directly inside that shell).
- Direct filesystem access via `chmod`/`chown` that bypasses `elevate`
  entirely.
- Any other process/language deleting files directly as root (e.g. a Python
  script calling `os.remove()`).

This is intentional "defense in depth," **not** a complete guarantee. For an
actual unbypassable guarantee, the core layers need to be enforced at the
kernel/VFS level — e.g. mounting `/overlayer/syshub` and `/overlayer/zaisys`
as read-only during boot, with `elevate` additionally blocking `mount -o
remount,rw` against those paths. That work lives in Zainium's init/boot
process (`quantra`) and/or fstab-equivalent configuration — out of scope for
this Rust binary.

### 6.4 Test coverage

`src/core_protector.rs` includes unit tests covering: exact-path match,
nested-path match, the second protected prefix (`zaisys`), an unrelated path
(must be allowed), a non-destructive command on a protected path (must be
allowed — e.g. `cat` is not blocked), a deliberately similar but distinct
path (`/overlayer-backup`, must NOT false-positive), and a trailing-slash
variant.

---

## 7. Build & deploy quick reference

```bash
cd elevate
cargo build --release
```

Produces:
```
target/x86_64-unknown-linux-musl/release/elevate
target/x86_64-unknown-linux-musl/release/elev
target/x86_64-unknown-linux-musl/release/viselev
```

Install (no `/usr` prefix):
```bash
install -m 4755 target/x86_64-unknown-linux-musl/release/elevate /bin/elevate
install -m 4755 target/x86_64-unknown-linux-musl/release/elev    /bin/elev
install -m 0755 target/x86_64-unknown-linux-musl/release/viselev /sbin/viselev

cp pam.d/elevate /etc/pam.d/elevate
cp pam.d/elev    /etc/pam.d/elev
cp pam.d/elev-l  /etc/pam.d/elev-l

mkdir -p /etc/elevators
touch /etc/elevators/elevate.toml
chmod 0440 /etc/elevators/elevate.toml
viselev   # edit it safely
```

See `ZAINIUM_DEPLOY_README.md` for the full walkthrough, including a
verification checklist and Core Protector test commands.
