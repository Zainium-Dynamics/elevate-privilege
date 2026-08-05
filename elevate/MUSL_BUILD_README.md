# elevate: musl + dynamic-PAM-via-dlopen build guide

## First error: `libgcc_s.so.1` was requested at runtime (SOLVED)

This happened because the default build target was glibc. Fix:
`.cargo/config.toml` forces the musl target. The musl target compiles
its libgcc-equivalent code (`compiler_builtins`) directly into the
binary, which eliminates the runtime dependency on `libgcc_s.so.1`
entirely.

## Second error: `cannot find -lpam` (in a musl static build) (SOLVED)

```
/usr/bin/ld.bfd: cannot find -lpam: No such file or directory
/usr/bin/ld.bfd: have you installed the static version of the pam library ?
```

### Cause

The musl target defaults to `crt-static` (fully static linking) being
ON. When `elevate` tried to link PAM via `#[link(name = "pam")]`, the
linker also tried to find a **static** version of PAM (`-lpam` as a
static `.a` file). On Fedora (and most distros), PAM only ships as a
dynamic `.so` — there is no static `.a` — so linking failed.

Statically linking PAM is also not the right approach in general,
because Linux-PAM itself loads its own modules (`pam_unix.so`,
`pam_deny.so`, etc.) via `dlopen()` at runtime — this is PAM's core
design and cannot be changed.

### Fix: moved PAM from link-time linking to a runtime `dlopen()` loader

The following changes were made to elevate's PAM-related code:

1. **`src/pam/mod.rs`**: the `#[link(name = "pam")]` attribute was
   removed. PAM is no longer linked at link time at all.

2. **`src/pam/dynload.rs`**: this module calls
   `dlopen("libelevate_pam.so*")` first (elevate-pam product library;
   also `/lib/libelevate_pam.so*`). Classic `libpam.so*` is only tried
   when `ELEVATE_ALLOW_LIBPAM=1`. It resolves `pam_start`,
   `pam_authenticate`, `pam_end`, etc. via `dlsym()`, cached in
   `OnceLock`.

3. Every call site that used to call `pam_start(...)`,
   `pam_authenticate(...)`, etc. directly now calls through the
   function pointer instead, e.g. `(dynload::pam_lib().pam_start)(...)`.

### Benefits

- **Zero PAM dependency at link time** — the linker never looks for
  `-lpam` at all, whether a static `.a` exists or not.
- **Only a `.so` is required at runtime** — which already exists on
  every Linux distribution (glibc or musl).
- This gives cross-OS portability: a single static binary can run on
  both glibc and musl systems.

## Final `.cargo/config.toml` setup

```toml
[build]
target = "x86_64-unknown-linux-musl"

[target.x86_64-unknown-linux-musl]
rustflags = [
    "-C", "target-feature=+crt-static",
]
```

`crt-static` stays ON because PAM is now completely independent of it
(it's loaded via `dlopen()`), so the rest of the binary (libc,
unwinding, everything else) can be statically compiled without any
conflict.

## Build steps

```bash
rustup target add x86_64-unknown-linux-musl   # if not already installed
cargo build --release
```

Because of `.cargo/config.toml`, you don't need to pass `--target`
manually, but you can if you want to be explicit:
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Verify

```bash
file target/x86_64-unknown-linux-musl/release/elevate
ldd target/x86_64-unknown-linux-musl/release/elevate
```

Expected output: `ldd` should say "not a dynamic executable" or show
only very few dependencies. **You should never see a `libgcc_s.so.1`
requirement or a `-lpam` link-time error.**

PAM is loaded at runtime, so it will NOT show up in `ldd` output — this
is expected, since it happens via `dlopen()`, which `ldd` does not
track. The real test is to **run** the binary and confirm
authentication actually works:

```bash
./target/x86_64-unknown-linux-musl/release/elevate whoami
```

If you see this error:
```
elevate: fatal: failed to load elevate-pam (libelevate_pam.so). ...
```
install elevate-pam to `/lib` (no `/usr` on Zainium):
`/lib/libelevate_pam.so.0` and TOML stacks under
`/etc/elevate-pam/services/`. See `docs/elevate-pam-integration.md`.
For temporary classic libpam fallback: `ELEVATE_ALLOW_LIBPAM=1`.

## Install

```bash
install -m 4755 target/x86_64-unknown-linux-musl/release/elevate /bin/elevate
install -m 4755 target/x86_64-unknown-linux-musl/release/elev    /bin/elev
install -m 0755 target/x86_64-unknown-linux-musl/release/viselev /sbin/viselev
```

The `4755` permission is required (setuid root) — without it,
`elevate`/`elev` will not function.

## Troubleshooting

### If you still get a link error

```bash
cargo clean
cargo build --release
```
(A stale cached glibc/musl artifact can cause confusion.)

### If `dlopen` fails to resolve a symbol

If some system uses an unusually old/new PAM version where a function
name differs, `dynload.rs` will print a clear error stating exactly
which symbol was not found — debug from there.

### If you're unsure about `dlopen()` reliability with `crt-static`

On some older musl versions, `dlopen()` inside static-pie binaries can
be slightly fragile. If you hit an issue in production, comment out
the `crt-static` line in `.cargo/config.toml` — this produces a
"normal dynamic" musl executable (which requires musl's own `libc.so`
to be present on the target system), which works more reliably with
`dlopen()`, at the cost of being slightly less portable (the target
system needs a musl runtime).
