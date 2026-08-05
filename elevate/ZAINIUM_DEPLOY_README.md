# Zainium "elevate" / "elev" / "viselev" -- Final Build & Deploy Guide

This is a customized build of the original sudo-rs for Zainium OS, which
includes the following changes:

1. Binary rename: `sudo` -> `elevate`, `su` -> `elev`, `visudo` -> `viselev`
2. Path layout fix: removed `/usr/bin`, `/usr/sbin` references in favor
   of `/bin`, `/sbin` (no merged-/usr system)
3. Config file rename: `/etc/sudoers` -> `/etc/elevators/elevate.toml`
   (only the file's NAME/extension changed -- the syntax INSIDE it is
   still classic sudoers grammar; this is not actually parsed as TOML)
4. PAM service rename: `sudo`/`sudo-i` -> `elevate`/`elevate-i`,
   `su`/`su-l` -> `elev`/`elev-l`
5. musl static build with PAM loaded via `dlopen()` at runtime (zero
   link-time PAM dependency, works on glibc AND musl systems)
6. Zainium Zero-Trust Core Protector: blocks `rm`/`rmdir`/`mv`/`shred`/
   `unlink` from targeting `/overlayer`, `/overlayer/syshub`,
   `/overlayer/zaisys` (or anything underneath them), even for root,
   with a single exact-match exception for `zex syshub -u`

## 1. Build

```bash
cd elevate
cargo build --release
```

`.cargo/config.toml` already targets `x86_64-unknown-linux-musl` with
`crt-static` ON. Binaries produced:

```
target/x86_64-unknown-linux-musl/release/elevate
target/x86_64-unknown-linux-musl/release/elev
target/x86_64-unknown-linux-musl/release/viselev
```

(These come from `[[bin]]` sections in `Cargo.toml` that rename the
build output -- the source files are still named `sudo.rs`/`su.rs`/
`visudo.rs` internally, only the produced binary name changed.)

## 2. Install binaries (no /usr prefix, per your layout)

```bash
install -m 4755 target/x86_64-unknown-linux-musl/release/elevate /bin/elevate
install -m 4755 target/x86_64-unknown-linux-musl/release/elev    /bin/elev
install -m 0755 target/x86_64-unknown-linux-musl/release/viselev /sbin/viselev
```

`4755` = setuid root, required for `elevate`/`elev` to function.
`viselev` does not need setuid (it never authenticates -- same as
upstream `visudo`).

Optional: if you later want `elevate file...` to behave like
`sudoedit` (auto `-e` mode), create a symlink named `elevatedit`:
```bash
ln -s /bin/elevate /bin/elevatedit
```

## 3. Install elevate-pam (required)

elevate loads **`libelevate_pam.so`** at runtime (not link-time `-lpam`).
Build/install the elevate-pam project first:

```bash
# from elevate-pam tree
DESTROOT=/overlayer/syshub ./scripts/install-dev.sh
# installs:
#   /lib/libelevate_pam.so.0
#   /lib/security/pam_*.so
#   /etc/elevate-pam/services/{elevate,elev,elev-l,other}.toml
```

See `docs/elevate-pam-integration.md`.

Legacy classic pam.d samples remain under `pam.d/` for reference only.
Production auth stacks are **TOML** under `/etc/elevate-pam/services/`.

**Note:** `elevate-i` (the `pam-login` feature's login-mode service)
is NOT included, because that Cargo feature is OFF by default and
should stay off unless you specifically know your setup needs Debian's
`sudo-i` split-service behavior. If you ever enable the `pam-login`
cargo feature, you'll need to add an `/etc/pam.d/elevate-i` file too
(a copy of `elevate` is a safe starting point).

`viselev` does not call PAM at all (same as upstream `visudo`) -- no
config needed for it.

## 4. Create the config directory and file

```bash
mkdir -p /etc/elevators
touch /etc/elevators/elevate.toml
chmod 0440 /etc/elevators/elevate.toml
```

Edit it with `viselev` (never edit it directly with a plain text
editor in production, since `viselev` validates syntax before saving):

```bash
viselev
```

The file's content uses the same syntax as classic `/etc/sudoers`
(e.g.):
```
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL:ALL) ALL
alizain ALL=(ALL:ALL) NOPASSWD: ALL
```

If `/etc/elevators/elevate.toml` does not exist yet at first run,
`elevate` will automatically fall back to checking `/etc/sudoers-rs`
and then `/etc/sudoers`, in that order -- so migration from an
existing sudo/elevate setup is non-destructive.

## 5. Zero-Trust Core Protector -- how it works

Implemented in `src/core_protector.rs`, wired into both `elevate`'s
and `elev`'s execution path (right before the resolved command is
actually exec'd).

- Triggers on: `rm`, `rmdir`, `mv`, `shred`, `unlink`
- Blocks any argument that is exactly, or starts with (path-prefix),
  any of: `/overlayer`, `/overlayer/syshub`, `/overlayer/zaisys`
- Blocks even when the invoking user is root
- The ONLY exception: an exact-match command line `zex syshub -u`
  (no extra/different flags) is allowed through, for legitimate
  system upgrades

Example of a blocked command:
```bash
elevate rm -rf /overlayer/syshub/bin/ls
# -> Zainium Security Violation: Modification of Core OS layers is strictly prohibited
# -> Blocked path: /overlayer/syshub/bin/ls
# -> exits with status 77
```

### Important limitation (please read)

This is a **userspace, application-level** check. It only protects
commands launched **through** `elevate`/`elev`. It does **not** stop:

- A command run from an already-open root shell (e.g. `elevate bash`,
  then `rm -rf /overlayer` typed directly inside that shell)
- Direct filesystem access via `chmod`/`chown` bypassing `elevate`
  entirely
- Any other programming language/runtime deleting files directly
  (e.g. a Python script run as root calling `os.remove()`)

This is intentional "defense in depth," not a complete guarantee. For
an unbypassable guarantee, the core layers should also be mounted
**read-only at the kernel/VFS level** during boot (e.g. mounting
`/overlayer/syshub` and `/overlayer/zaisys` as `ro`), with `elevate`
additionally blocking `mount -o remount,rw` against those same paths.
That kernel-level work is outside the scope of this Rust binary and
would need to be done in your init/boot process (`quantra`) and/or
fstab-equivalent configuration.

## 6. Quick verification checklist

```bash
# Binary names and setuid bits
ls -l /bin/elevate /bin/elev /sbin/viselev

# PAM services resolve correctly
cat /etc/pam.d/elevate /etc/pam.d/elev /etc/pam.d/elev-l

# Config file present
cat /etc/elevators/elevate.toml

# Test elevate works at all
elevate whoami

# Test elev works at all
elev - root -c whoami

# Test Core Protector blocks a core-layer delete
elevate rm -rf /overlayer/syshub/test    # should be blocked

# Test Core Protector allows unrelated deletes
elevate rm -rf /tmp/some-test-file       # should work normally

# Test the upgrade override path
elevate zex syshub -u                     # should be allowed through
```
