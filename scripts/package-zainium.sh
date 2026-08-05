#!/usr/bin/env bash
# =============================================================================
# Package elevate-privilege into Zainium syshub packages (manifest.toml +
# payload/), matching the convention used across
# /run/media/alizain/ZAINIUM_DRIVE/syshub-Packages and
# .../packages/syshub-packages (e.g. GCC-16's manifest -- a core syshub
# component, _syshub = true, installed straight into /overlayer/syshub/
# rather than /overlayer/zexlib/union/ like userland apps).
#
# Three packages, all _syshub = true:
#
#   musl-shared    -- PAM .so modules + libelevate_pam.so + libelevate_crypto.so,
#                      built for the real Zainium target (see build-zainium.sh dynamic)
#   musl-static    -- elevate/elev/vielev + elevate-umbra binaries, fully static
#                      (see build-zainium.sh static)
#   pam-standalone -- elevate-pam built with its `standalone` feature (all
#                      builtin_modules compiled directly in, no dlopen) for the
#                      host's default target -- a single portable
#                      libelevate_pam any Linux distro (glibc or musl) can drop
#                      in as a Linux-PAM replacement, independent of Zainium.
#
# Cryptographic identity (blake3/ed25519_sig/ed25519_pubkey) is left blank,
# same as every other manifest here -- these get filled in for real by
# Zainium's own signing tooling at publish time, not by this script.
#
# Output: .tar.gz for now (dirname_version.tar.gz, mirroring the real
# dirname_version.zex convention). Swapping to a real signed .zex is a
# mechanical follow-up once that tool is available in this environment/CI.
#
# Usage:
#   ./scripts/package-zainium.sh [musl-shared|musl-static|pam-standalone|all]
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
PKG_ROOT="${ROOT}/dist/syshub-packages"
DEPENDS_MUSL='["musl"]'

log() { printf '==> %s\n' "$*"; }

write_manifest() {
  # write_manifest <dir> <name> <description> <build_type> <depends-toml-array> <provides-toml-array> <install-toml-block>
  local dir="$1" name="$2" desc="$3" build_type="$4" depends="$5" provides="$6" install_block="$7"
  cat > "${dir}/manifest.toml" <<EOF
# manifest.toml — ${name}-${VERSION}.zex
#
# elevate-privilege: memory-safe sudo/PAM/shadow-utils replacement suite
# for Zainium OS. This is a syshub (core OS) package, not userland --
# _syshub = true routes it into /overlayer/syshub/ instead of
# /overlayer/zexlib/union/, matching every other core-OS package here
# (see e.g. GCC-16's manifest.toml).

[package]
name             = "${name}"
version          = "${VERSION}"
description      = "${desc}"
license          = "MIT OR Apache-2.0"
maintainer       = "Ali Zain <alizain@zainiumdynamics.tech>"
homepage         = "https://zainiumdynamics.tech"
build_type       = "${build_type}"
libc_target      = "musl"

# Cryptographic identity — left blank, filled in for real by Zainium's
# signing tooling at publish time (fresh ephemeral key per build, never
# persisted here).
blake3           = ""
ed25519_sig      = ""
ed25519_pubkey   = ""

# Runtime requirements
requires_syshub  = "2026v1.0"
depends          = ${depends}
provides         = ${provides}
tags             = ["security", "authentication", "sudo", "pam", "shadow-utils"]

# ── Install map — payload subdir → absolute on-disk destination
${install_block}
_syshub = true

[remove]
files    = []
dirs     = []
symlinks = []

[hooks]
EOF
}

tar_package() {
  local dir="$1" name="$2"
  local out="${PKG_ROOT}/${name}-${VERSION}_${VERSION}.tar.gz"
  ( cd "$(dirname "$dir")" && tar -czf "$out" "$(basename "$dir")" )
  ( cd "$PKG_ROOT" && sha256sum "$(basename "$out")" > "$(basename "$out").sha256" )
  log "packaged ${out}"
}

# =============================================================================
# musl-shared
# =============================================================================
package_musl_shared() {
  log "musl-shared: building (dynamic Zainium target)"
  "${ROOT}/scripts/build-zainium.sh" dynamic

  local name="elevate-privilege-musl-shared"
  local dir="${PKG_ROOT}/${name}"
  rm -rf "$dir"
  mkdir -p "${dir}/payload"
  cp -a "${ROOT}/dist/zainium/overlayer/syshub/lib" "${dir}/payload/lib"

  write_manifest "$dir" "$name" \
    "elevate-privilege PAM modules + libelevate_pam.so + libelevate_crypto.so (Zainium musl target, dynamic)" \
    "dynamic" \
    "$DEPENDS_MUSL" \
    '["elevate-pam", "pam-unix", "pam-env", "pam-limits", "pam-deny", "pam-permit", "pam-rootok", "pam-wheel", "pam-nologin", "pam-securetty", "pam-access", "pam-faillock", "pam-mkhomedir", "pam-pwhistory", "pam-loginuid", "pam-cap", "pam-listfile", "pam-timestamp", "pam-keyinit", "pam-group", "pam-time", "pam-xauth", "pam-canonicalize-user", "pam-filter", "pam-ftp", "pam-stress", "elevate-crypto"]' \
    '[install]
lib = "/overlayer/syshub/lib"
module_dir = "/overlayer/syshub/lib/security"'

  tar_package "$dir" "$name"
}

# =============================================================================
# musl-static
# =============================================================================
package_musl_static() {
  log "musl-static: building (crt-static, generic musl target)"
  "${ROOT}/scripts/build-zainium.sh" static

  local name="elevate-privilege-musl-static"
  local dir="${PKG_ROOT}/${name}"
  rm -rf "$dir"
  mkdir -p "${dir}/payload"
  cp -a "${ROOT}/dist/zainium/overlayer/syshub/bin" "${dir}/payload/bin"
  cp -a "${ROOT}/dist/zainium/overlayer/syshub/sbin" "${dir}/payload/sbin"

  write_manifest "$dir" "$name" \
    "elevate/elev/vielev (sudo replacement) + elevate-umbra (shadow-utils replacement), fully static musl binaries" \
    "static" \
    "[]" \
    '["elevate", "elev", "vielev", "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "passwd", "sudo"]' \
    '[install]
bin = "/overlayer/syshub/bin"
sbin = "/overlayer/syshub/sbin"'

  tar_package "$dir" "$name"
}

# =============================================================================
# pam-standalone
# =============================================================================
package_pam_standalone() {
  log "pam-standalone: building (host default target, standalone feature)"
  cargo build --release --manifest-path "${ROOT}/elevate-pam/pam/Cargo.toml" \
    --no-default-features --features standalone,elevate_crypto

  local name="elevate-pam-standalone"
  local dir="${PKG_ROOT}/${name}"
  rm -rf "$dir"
  mkdir -p "${dir}/payload/lib" "${dir}/payload/include/security"

  # elevate-pam/pam is a workspace member, not a standalone workspace --
  # --manifest-path still resolves to the shared workspace-root target/ dir.
  local outdir="${ROOT}/target/release"
  [[ -f "$outdir/libelevate_pam.so" ]] && cp -a "$outdir/libelevate_pam.so" "${dir}/payload/lib/libelevate_pam.so.0"
  [[ -f "$outdir/libelevate_pam.a" ]] && cp -a "$outdir/libelevate_pam.a" "${dir}/payload/lib/"
  [[ -d "${ROOT}/elevate-pam/include" ]] && cp -a "${ROOT}/elevate-pam/include/security/." "${dir}/payload/include/security/"

  write_manifest "$dir" "$name" \
    "elevate-pam standalone: self-contained PAM implementation (all builtin modules compiled in, no dlopen) -- a Linux-PAM replacement any distro can use, not Zainium-specific" \
    "standalone" \
    "[]" \
    '["libpam.so.0", "elevate-pam"]' \
    '[install]
lib = "/overlayer/syshub/lib"
include = "/overlayer/syshub/include"'

  tar_package "$dir" "$name"
}

case "${1:-all}" in
  musl-shared) package_musl_shared ;;
  musl-static) package_musl_static ;;
  pam-standalone) package_pam_standalone ;;
  all)
    package_musl_shared
    package_musl_static
    package_pam_standalone
    ;;
  *) echo "usage: $0 [musl-shared|musl-static|pam-standalone|all]" >&2; exit 2 ;;
esac

log "done — packages under ${PKG_ROOT}/"
ls -la "$PKG_ROOT"/*.tar.gz 2>/dev/null || true
