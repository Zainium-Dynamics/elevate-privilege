#!/usr/bin/env bash
# elevate monorepo installer (Zainium — no /usr)
# Installs binaries, libraries, ALL PAM modules, AND the full /etc tree.
#
# Usage:
#   ./scripts/install.sh                          # live system: /bin /lib /etc
#   ./scripts/install.sh --prefix /path/to/root   # install under a prefix
#   DESTROOT=/path/to/overlayer/syshub ./scripts/install.sh
#   ./scripts/install.sh --etc-only               # only packaging/etc → $DESTROOT/etc
#   ./scripts/install.sh --force-policy           # overwrite existing elevate.toml
#   ./scripts/install.sh --skip-build             # use already-built target/release
#   ./scripts/install.sh --no-verify              # skip the post-install check
#
# Prefix resolution order (first match wins):
#   1. --prefix <path> / DESTROOT env var
#   2. `prefix` from elevate_privilege.toml's [paths] table
#   3. `/` (live system paths — no separate root)
#
# Notes:
#   - /etc/elevators/elevate.toml is NOT created per-user. It is system-wide
#     policy installed once. New OS users do not get their own elevate.toml.
#   - Existing elevate.toml is preserved unless --force-policy is set.
#   - elevate.toml uses classic sudoers grammar (not real TOML tables).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_TOML="${ROOT}/elevate_privilege.toml"
ETC_ONLY=0
FORCE_POLICY=0
SKIP_BUILD=0
NO_VERIFY=0
INSTALL_BINS=1
INSTALL_LIBS=1
INSTALL_ETC=1
PREFIX_ARG=""

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage ;;
    --prefix=*) PREFIX_ARG="${arg#--prefix=}" ;;
    --prefix) shift_next_is_prefix=1 ;;
    --etc-only) ETC_ONLY=1; INSTALL_BINS=0; INSTALL_LIBS=0 ;;
    --force-policy) FORCE_POLICY=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --no-verify) NO_VERIFY=1 ;;
    --bins-only) INSTALL_ETC=0; INSTALL_LIBS=0 ;;
    --libs-only) INSTALL_BINS=0; INSTALL_ETC=0 ;;
    *)
      if [[ "${shift_next_is_prefix:-0}" -eq 1 ]]; then
        PREFIX_ARG="$arg"
        shift_next_is_prefix=0
      else
        echo "unknown option: $arg" >&2
        exit 2
      fi
      ;;
  esac
done

log() { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
fail() { printf 'xx  %s\n' "$*" >&2; }

# --- resolve DESTROOT --------------------------------------------------------
# 1. --prefix / DESTROOT env var, 2. [paths].prefix from elevate_privilege.toml, 3. "/" (live)
config_prefix() {
  [[ -f "$CONFIG_TOML" ]] || return 1
  awk -F'"' '/^\s*prefix\s*=/{print $2; found=1; exit} END{exit !found}' "$CONFIG_TOML"
}

if [[ -n "$PREFIX_ARG" ]]; then
  DESTROOT="$PREFIX_ARG"
elif [[ -n "${DESTROOT:-}" ]]; then
  : # already set by caller's environment
elif cfg_prefix="$(config_prefix)"; then
  DESTROOT="$cfg_prefix"
  log "using prefix from elevate_privilege.toml: $DESTROOT"
else
  DESTROOT=""
fi

BINDIR="${BINDIR:-${DESTROOT}/bin}"
SBINDIR="${SBINDIR:-${DESTROOT}/sbin}"
LIBDIR="${LIBDIR:-${DESTROOT}/lib}"
MODDIR="${MODDIR:-${LIBDIR}/security}"
ETCDIR="${ETCDIR:-${DESTROOT}/etc}"
PKG_ETC="${ROOT}/packaging/etc"

rel="${ROOT}/target/release"

need_root_hint() {
  if [[ -z "${DESTROOT}" && "$(id -u)" -ne 0 ]]; then
    warn "installing to live system paths without root (uid=$(id -u))"
    warn "if this fails, re-run as root or set --prefix=... / DESTROOT=..."
  fi
}

install_file() {
  # install_file MODE SRC DEST
  local mode="$1" src="$2" dest="$3"
  install -D -m "$mode" "$src" "$dest"
}

# --- discover all pam-* module workspace members -----------------------------
# Read straight from Cargo.toml's [workspace] members list instead of a
# hand-maintained duplicate, so newly added pam-* crates are picked up
# automatically instead of silently being skipped by both build and install.
mapfile -t PAM_MODULE_CRATES < <(
  grep -oE '"elevate-pam/pam-[a-zA-Z0-9_-]+"' "${ROOT}/Cargo.toml" \
    | tr -d '"' | sed 's#.*/##' | sort -u
)
# Cargo module names use underscores; crate dirs use hyphens.
PAM_MODULE_NAMES=()
for c in "${PAM_MODULE_CRATES[@]}"; do
  PAM_MODULE_NAMES+=("${c//-/_}")
done

# --- build -------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 && "$ETC_ONLY" -eq 0 ]]; then
  log "building monorepo (release)"
  (
    cd "$ROOT"
    cargo build --release \
      -p elevate-crypto \
      -p elevate-pam \
      -p elevate-pam-cli \
      -p elevate \
      -p elevate-umbra \
      -p unix_chkpwd
    # All PAM modules (best-effort; some may not build on every host).
    pkg_args=()
    for c in "${PAM_MODULE_CRATES[@]}"; do
      pkg_args+=(-p "$c")
    done
    cargo build --release "${pkg_args[@]}" 2>/dev/null || true
  )
fi

need_root_hint

# --- directories -------------------------------------------------------------
log "creating directories under DESTROOT='${DESTROOT:-/}'"
install -d \
  "$BINDIR" "$SBINDIR" "$LIBDIR" "$MODDIR" \
  "$LIBDIR/elevate-pam/services" \
  "$ETCDIR/elevators/elevate.toml.d" \
  "$ETCDIR/elevate-pam/services" \
  "$ETCDIR/elevate-pam/services.d" \
  "$ETCDIR/security"

# --- libraries / modules -----------------------------------------------------
if [[ "$INSTALL_LIBS" -eq 1 ]]; then
  log "installing libraries → $LIBDIR"
  if [[ -f "$rel/libelevate_pam.so" ]]; then
    install_file 755 "$rel/libelevate_pam.so" "$LIBDIR/libelevate_pam.so.0"
    ln -sfn libelevate_pam.so.0 "$LIBDIR/libelevate_pam.so"
  else
    warn "missing $rel/libelevate_pam.so (build with elevate-pam shared features)"
  fi
  if [[ -f "$rel/libelevate_crypto.so" ]]; then
    install_file 755 "$rel/libelevate_crypto.so" "$LIBDIR/libelevate_crypto.so"
  fi
  if [[ -f "$rel/libelevate_pam.a" ]]; then
    install_file 644 "$rel/libelevate_pam.a" "$LIBDIR/libelevate_pam.a"
  fi
  if [[ -f "$rel/libelevate_crypto.a" ]]; then
    install_file 644 "$rel/libelevate_crypto.a" "$LIBDIR/libelevate_crypto.a"
  fi

  log "installing PAM modules (${#PAM_MODULE_NAMES[@]} total) → $MODDIR"
  missing_modules=()
  for m in "${PAM_MODULE_NAMES[@]}"; do
    f="$rel/lib${m}.so"
    if [[ -f "$f" ]]; then
      install_file 755 "$f" "$MODDIR/${m}.so"
    else
      missing_modules+=("$m")
    fi
  done
  if [[ ${#missing_modules[@]} -gt 0 ]]; then
    warn "not built/installed (${#missing_modules[@]}): ${missing_modules[*]}"
  fi

  if [[ -f "$rel/unix_chkpwd" ]]; then
    install_file 4755 "$rel/unix_chkpwd" "${LIBDIR}/elevate-pam/unix_chkpwd"
  fi
fi

# --- binaries ----------------------------------------------------------------
if [[ "$INSTALL_BINS" -eq 1 ]]; then
  log "installing binaries → $BINDIR $SBINDIR"
  if [[ -f "$rel/elevate" ]]; then
    install_file 4755 "$rel/elevate" "$BINDIR/elevate"
  else
    warn "missing $rel/elevate"
  fi
  if [[ -f "$rel/elev" ]]; then
    install_file 4755 "$rel/elev" "$BINDIR/elev"
  fi
  if [[ -f "$rel/vielev" ]]; then
    install_file 0755 "$rel/vielev" "$SBINDIR/vielev"
  fi
  if [[ -f "$rel/elevate-pam" ]]; then
    install_file 0755 "$rel/elevate-pam" "$BINDIR/elevate-pam"
  fi

  log "installing elevate-umbra shadow binaries → $BINDIR $SBINDIR"
  for ubin in useradd userdel usermod groupadd groupdel groupmod passwd chpasswd chgpasswd chage chfn chsh pwck grpck vipw umbra-sign gpasswd newusers groupmems nologin expiry pwconv pwunconv grpconv grpunconv newgrp faillog sulogin sudo; do
    if [[ -f "$rel/$ubin" ]]; then
      install_file 0755 "$rel/$ubin" "$BINDIR/$ubin"
    fi
  done
fi

# --- /etc tree ---------------------------------------------------------------
if [[ "$INSTALL_ETC" -eq 1 ]]; then
  if [[ ! -d "$PKG_ETC" ]]; then
    echo "error: packaging tree missing: $PKG_ETC" >&2
    exit 1
  fi

  log "installing /etc layout from packaging/etc → $ETCDIR"

  # elevate-pam main config + services (always refresh; safe to replace)
  install_file 644 "$PKG_ETC/elevate-pam/elevate-pam.toml" \
    "$ETCDIR/elevate-pam/elevate-pam.toml"
  for s in elevate elev elev-l other; do
    install_file 644 "$PKG_ETC/elevate-pam/services/${s}.toml" \
      "$ETCDIR/elevate-pam/services/${s}.toml"
    # vendor copy for fallback
    install_file 644 "$PKG_ETC/elevate-pam/services/${s}.toml" \
      "$LIBDIR/elevate-pam/services/${s}.toml"
  done
  if [[ -f "$PKG_ETC/elevate-pam/services.d/README.md" ]]; then
    install_file 644 "$PKG_ETC/elevate-pam/services.d/README.md" \
      "$ETCDIR/elevate-pam/services.d/README.md"
  fi

  # security helpers (only create if missing — sites often customize)
  for f in limits.conf pam_env.conf; do
    dest="$ETCDIR/security/$f"
    if [[ ! -e "$dest" ]]; then
      install_file 644 "$PKG_ETC/security/$f" "$dest"
    else
      log "keep existing $dest"
    fi
  done
  if [[ ! -e "$ETCDIR/environment" ]]; then
    install_file 644 "$PKG_ETC/environment" "$ETCDIR/environment"
  fi

  # elevate_privilege.toml itself, so the installed system's own binaries
  # (once elevate-paths is wired in) can find their own configuration.
  if [[ -f "$CONFIG_TOML" ]]; then
    install_file 644 "$CONFIG_TOML" "$ETCDIR/elevate_privilege.toml"
  fi

  # elevators policy — 0440, never clobber unless --force-policy
  policy_src="$PKG_ETC/elevators/elevate.toml"
  policy_dst="$ETCDIR/elevators/elevate.toml"
  if [[ -e "$policy_dst" && "$FORCE_POLICY" -eq 0 ]]; then
    warn "keeping existing policy: $policy_dst  (use --force-policy to replace)"
  else
    install_file 440 "$policy_src" "$policy_dst"
    log "installed policy $policy_dst (mode 0440)"
  fi

  # drop-ins
  if [[ -f "$PKG_ETC/elevators/elevate.toml.d/00-keep" ]]; then
    install_file 440 "$PKG_ETC/elevators/elevate.toml.d/00-keep" \
      "$ETCDIR/elevators/elevate.toml.d/00-keep"
  fi
  if [[ -f "$PKG_ETC/elevators/elevate.toml.d/README.md" ]]; then
    install_file 644 "$PKG_ETC/elevators/elevate.toml.d/README.md" \
      "$ETCDIR/elevators/elevate.toml.d/README.md"
  fi

  # modes: dirs 0755, elevators dir stricter 0750 is common; keep 0755 for Zainium
  chmod 755 "$ETCDIR/elevators" "$ETCDIR/elevators/elevate.toml.d" 2>/dev/null || true
  chmod 440 "$policy_dst" 2>/dev/null || true
fi

# --- verify --------------------------------------------------------------
verify_ok=1
if [[ "$NO_VERIFY" -eq 0 ]]; then
  log "verifying install"

  check_exec() {
    local path="$1"
    if [[ ! -e "$path" ]]; then
      warn "missing: $path"; verify_ok=0; return
    fi
    if [[ ! -x "$path" ]]; then
      warn "not executable: $path"; verify_ok=0
    fi
  }

  check_setuid() {
    local path="$1"
    [[ -e "$path" ]] || return
    if [[ ! -u "$path" ]]; then
      warn "setuid bit not set: $path"; verify_ok=0
    fi
  }

  if [[ "$INSTALL_BINS" -eq 1 ]]; then
    check_exec "$BINDIR/elevate"
    check_setuid "$BINDIR/elevate"
    check_exec "$BINDIR/elev"
    check_setuid "$BINDIR/elev"
    check_exec "$SBINDIR/vielev"
  fi

  if [[ "$INSTALL_LIBS" -eq 1 ]]; then
    [[ -e "$LIBDIR/libelevate_pam.so.0" ]] || { warn "missing $LIBDIR/libelevate_pam.so.0"; verify_ok=0; }
    [[ -e "$LIBDIR/libelevate_crypto.so" ]] || { warn "missing $LIBDIR/libelevate_crypto.so"; verify_ok=0; }
    if command -v ldd >/dev/null 2>&1 && [[ -x "$BINDIR/elevate" ]]; then
      if ldd "$BINDIR/elevate" 2>/dev/null | grep -qi "not found"; then
        warn "elevate has unresolved shared library dependencies (ldd reported \"not found\")"
        verify_ok=0
      fi
    fi
  fi

  if [[ "$verify_ok" -eq 1 ]]; then
    log "verify: PASS"
  else
    fail "verify: FAIL (see warnings above)"
  fi
fi

# --- summary -----------------------------------------------------------------
log "done"
echo "  DESTROOT:  ${DESTROOT:-/ (live)}"
echo "  bins:      $BINDIR  $SBINDIR"
echo "  libs:      $LIBDIR"
echo "  modules:   $MODDIR  (${#PAM_MODULE_NAMES[@]} known)"
echo "  elevators: $ETCDIR/elevators/elevate.toml"
echo "  pam:       $ETCDIR/elevate-pam/services/"
echo ""
echo "Verify:"
echo "  ls -la ${DESTROOT}/etc/elevators ${DESTROOT}/etc/elevate-pam/services"
if [[ -x "${SBINDIR}/vielev" ]]; then
  echo "  ${SBINDIR}/vielev -c -f ${ETCDIR}/elevators/elevate.toml"
fi
echo "  ${BINDIR}/elevate -V   # if installed"

if [[ "$NO_VERIFY" -eq 0 && "$verify_ok" -eq 0 ]]; then
  exit 1
fi
