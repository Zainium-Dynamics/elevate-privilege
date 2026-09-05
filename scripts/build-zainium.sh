#!/usr/bin/env bash
# Cross-build elevate-privilege for Zainium OS's real musl target.
# Two variants, both musl, no glibc:
#
#   dynamic (default target) -- the real x86_64-zainium-linux-musl target,
#     wired to the crosstool-NG toolchain (x86_64-zainium-linux-musl-gcc) and
#     built with a pinned nightly + `-Z build-std` (no rustup-provided std
#     exists for a custom target). Rustup's stock x86_64-unknown-linux-musl
#     target cannot produce cdylib at all -- its target spec's
#     crt-static-default=true gates crate-type support regardless of the
#     resolved rustflags (verified empirically) -- so PAM .so modules and
#     libelevate_pam.so/libelevate_crypto.so require this custom target.
#     Produces: PAM module .so's, libelevate_pam.so, libelevate_crypto.so.
#
#   static -- the generic rustup x86_64-unknown-linux-musl target with
#     crt-static (stable, already wired via elevate/.cargo/config.toml and
#     the workspace-root .cargo/config.toml). This does NOT use the Zainium
#     toolchain: this toolchain's musl was built shared-only (no libc.a
#     anywhere in its sysroot -- confirmed with a bare `gcc -static` test),
#     which matches elevate_privilege.toml's own `[build] shared = true,
#     static = false` default. Rustup's musl target instead statically
#     links its own self-contained musl build, so it needs no libc from any
#     external toolchain at all -- a fully static binary only needs a
#     compatible Linux kernel, not a specific libc.
#     Produces: elevate, elev, vielev, elevate-umbra's user/group/passwd
#     binaries.
#
# Usage:
#   ./scripts/build-zainium.sh [dynamic|static|all]   # default: all
#
# Env overrides:
#   ZAINIUM_TOOLCHAIN_BIN  bin/ dir of the x86_64-zainium-linux-musl
#                          toolchain (default: this dev machine's mounted
#                          drive path -- override for CI / other machines)
#   ZAINIUM_NIGHTLY        pinned nightly toolchain (default: nightly-2026-05-24)
#   PROFILE                cargo profile (default: release)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ZAINIUM_TOOLCHAIN_BIN="${ZAINIUM_TOOLCHAIN_BIN:-/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub/x86_64-zainium-linux-musl/bin}"
ZAINIUM_NIGHTLY="${ZAINIUM_NIGHTLY:-nightly-2026-05-24}"
ZAINIUM_TARGET_JSON="${ROOT}/targets/x86_64-zainium-linux-musl.json"
ZAINIUM_LINKER="x86_64-zainium-linux-musl-gcc"
DIST="${ROOT}/dist/zainium"
PROFILE="${PROFILE:-release}"

DO_DYNAMIC=1
DO_STATIC=1
case "${1:-all}" in
  dynamic) DO_STATIC=0 ;;
  static) DO_DYNAMIC=0 ;;
  all) ;;
  *) echo "usage: $0 [dynamic|static|all]" >&2; exit 2 ;;
esac

log() { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }

# Same discovery convention as scripts/build-all.sh / scripts/install.sh --
# read straight from Cargo.toml's [workspace] members instead of a
# hand-maintained duplicate list.
mapfile -t PAM_MODULE_CRATES < <(
  grep -oE '"elevate-pam/pam-[a-zA-Z0-9_-]+"' "${ROOT}/Cargo.toml" \
    | tr -d '"' | sed 's#.*/##' | sort -u
)

# dynamic
# Body is `( ... )` (subshell), not `{ ... }` -- the PATH export below must
# NOT leak into build_static(), which needs the host's own cc/ld. Bash
# functions otherwise share the caller's shell environment (no subshell),
# so a plain `export PATH=...` here would silently make the static build
# pick up the Zainium cross-toolchain's `ld` too -- which then fails
# loading the host gcc's LTO plugin (built against a different libc/glibc
# than that ld expects): "error loading plugin: ... symbol not found".
build_dynamic() (
  if [[ ! -d "$ZAINIUM_TOOLCHAIN_BIN" ]]; then
    warn "Zainium toolchain not found at $ZAINIUM_TOOLCHAIN_BIN"
    warn "set ZAINIUM_TOOLCHAIN_BIN to the toolchain's bin/ dir"
    exit 1
  fi
  export PATH="${ZAINIUM_TOOLCHAIN_BIN}:${PATH}"

  log "dynamic: x86_64-zainium-linux-musl (+${ZAINIUM_NIGHTLY}, -Z build-std)"

  local pkg_args=(-p elevate-crypto -p elevate-pam -p libpam-abi -p elevate-pam-cli)
  for c in "${PAM_MODULE_CRATES[@]}"; do
    pkg_args+=(-p "$c")
  done

  cargo "+${ZAINIUM_NIGHTLY}" build --"$PROFILE" \
    -Z json-target-spec \
    --target "$ZAINIUM_TARGET_JSON" \
    -Z build-std=core,alloc,std,panic_abort \
    --config "target.x86_64-zainium-linux-musl.linker=\"${ZAINIUM_LINKER}\"" \
    "${pkg_args[@]}"

  local outdir="target/x86_64-zainium-linux-musl/${PROFILE}"
  install -d "$DIST/overlayer/syshub/lib/security"

  if [[ -f "$outdir/libelevate_pam.so" ]]; then
    install -m 755 "$outdir/libelevate_pam.so" "$DIST/overlayer/syshub/lib/libelevate_pam.so.0"
  else
    warn "missing $outdir/libelevate_pam.so"
  fi

  # libpam-abi is a separate crate (elevate-pam/libpam-abi) that just
  # statically links elevate-pam's own #[no_mangle] C ABI in again under
  # the canonical libpam.so.0 SONAME (baked in via its own build.rs) --
  # so pam-sys/dlopen("libpam.so.0") consumers (greetd, anything not
  # written against elevate directly) link against a real drop-in. Two
  # independent .so's built from two independent crates, not a rename of
  # one file, so this can't collide with libelevate_pam.so.0 at runtime.
  if [[ -f "$outdir/libpam.so" ]]; then
    install -m 755 "$outdir/libpam.so" "$DIST/overlayer/syshub/lib/libpam.so.0"
    ln -sf libpam.so.0 "$DIST/overlayer/syshub/lib/libpam.so"
  else
    warn "missing $outdir/libpam.so (libpam-abi crate)"
  fi
  if [[ -f "$outdir/libelevate_crypto.so" ]]; then
    install -m 755 "$outdir/libelevate_crypto.so" "$DIST/overlayer/syshub/lib/libelevate_crypto.so"
  else
    warn "missing $outdir/libelevate_crypto.so"
  fi
  if [[ -f "$outdir/elevate-pam" ]]; then
    install -d "$DIST/overlayer/syshub/bin"
    install -m 755 "$outdir/elevate-pam" "$DIST/overlayer/syshub/bin/elevate-pam"
  fi

  local missing=()
  for c in "${PAM_MODULE_CRATES[@]}"; do
    m="${c//-/_}"
    f="$outdir/lib${m}.so"
    if [[ -f "$f" ]]; then
      install -m 755 "$f" "$DIST/overlayer/syshub/lib/security/${m}.so"
    else
      missing+=("$m")
    fi
  done
  [[ ${#missing[@]} -gt 0 ]] && warn "PAM modules not built (${#missing[@]}): ${missing[*]}"

  log "dynamic artifacts staged under $DIST/overlayer/syshub/lib{,/security}"
)

# static
build_static() {
  log "static: x86_64-unknown-linux-musl (crt-static, stable)"
  rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true

  ( cd "$ROOT/elevate" && cargo build --"$PROFILE" )
  cargo build --"$PROFILE" --target x86_64-unknown-linux-musl -p elevate-umbra

  # elevate/ is a workspace member, not a standalone workspace -- despite
  # cd'ing into it, cargo still places output under the shared workspace
  # root target/ dir (elevate/.cargo/config.toml only forces the target,
  # it doesn't relocate the output dir).
  local bindir="$ROOT/target/x86_64-unknown-linux-musl/${PROFILE}"
  local umbradir="$ROOT/target/x86_64-unknown-linux-musl/${PROFILE}"
  install -d "$DIST/overlayer/syshub/bin" "$DIST/overlayer/syshub/sbin"

  for b in elevate elev; do
    if [[ -f "$bindir/$b" ]]; then
      install -m 4755 "$bindir/$b" "$DIST/overlayer/syshub/bin/$b"
    else
      warn "missing $bindir/$b"
    fi
  done
  if [[ -f "$bindir/vielev" ]]; then
    install -m 0755 "$bindir/vielev" "$DIST/overlayer/syshub/sbin/vielev"
  fi

  for ubin in useradd userdel usermod groupadd groupdel groupmod passwd \
    chpasswd chgpasswd chage chfn chsh pwck grpck vipw umbra-sign gpasswd \
    newusers groupmems nologin expiry pwconv pwunconv grpconv grpunconv \
    newgrp faillog sulogin sudo; do
    if [[ -f "$umbradir/$ubin" ]]; then
      install -m 0755 "$umbradir/$ubin" "$DIST/overlayer/syshub/bin/$ubin"
    fi
  done

  log "static artifacts staged under $DIST/overlayer/syshub/{bin,sbin}"
}

[[ "$DO_DYNAMIC" -eq 1 ]] && build_dynamic
[[ "$DO_STATIC" -eq 1 ]] && build_static

log "done"
echo "  rsync -a $DIST/overlayer/ <target-zairoot>/overlayer/  # to deploy"
