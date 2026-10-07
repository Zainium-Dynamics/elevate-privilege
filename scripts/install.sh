#!/usr/bin/env bash
# Install elevate-pam.
#
#   PREFIX   install root baked into the installed config's [paths] (default: empty = /)
#   DESTDIR  staging root for packaging (not baked into any config)
#   LIBDIR / ETCDIR / MODDIR / BINDIR / INCLUDEDIR   per-directory overrides
#
# Examples:
#   sudo ./scripts/install.sh                          # real /lib, /etc, /bin
#   DESTDIR=$PWD/pkg ./scripts/install.sh              # staged for a package
#   PREFIX=/opt/pam ./scripts/install.sh               # relocated tree; run with
#                                                      # ELEVATE_PAM_CONFIG=/opt/pam/etc/elevate-pam/elevate-pam.toml
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-}"
DESTDIR="${DESTDIR:-}"
D="${DESTDIR}${PREFIX}"
LIBDIR="${LIBDIR:-${D}/lib}"
ETCDIR="${ETCDIR:-${D}/etc/elevate-pam}"
MODDIR="${MODDIR:-${LIBDIR}/security}"
BINDIR="${BINDIR:-${D}/bin}"
INCLUDEDIR="${INCLUDEDIR:-${D}/include}"
MODULES=(pam_unix pam_env pam_limits pam_access pam_deny pam_permit pam_rootok
         pam_wheel pam_nologin pam_securetty pam_faillock pam_mkhomedir)

cd "$ROOT"
echo "==> Building (release)"
./scripts/build-modules.sh release

echo "==> Installing: lib=$LIBDIR modules=$MODDIR etc=$ETCDIR bin=$BINDIR"
install -d "$LIBDIR" "$MODDIR" "$ETCDIR/services" "$ETCDIR/services.d" \
  "$LIBDIR/elevate-pam/services" "$BINDIR" "$INCLUDEDIR/security"

if [[ -f target/release/libelevate_pam.so ]]; then
  install -m 755 target/release/libelevate_pam.so "$LIBDIR/libelevate_pam.so.0"
  ln -sfn libelevate_pam.so.0 "$LIBDIR/libelevate_pam.so"
  if [[ "${INSTALL_LIBPAM_SONAME:-0}" == "1" ]]; then
    ln -sfn libelevate_pam.so.0 "$LIBDIR/libpam.so.0"
    ln -sfn libelevate_pam.so.0 "$LIBDIR/libpam.so"
  fi
fi
[[ -f target/release/libelevate_pam.a ]] && install -m 644 target/release/libelevate_pam.a "$LIBDIR/"

for m in "${MODULES[@]}"; do
  f="target/release/lib${m}.so"
  [[ -f "$f" ]] && install -m 755 "$f" "$MODDIR/${m}.so"
done

# Main config: bake PREFIX into [paths] when a relocated tree is requested.
install -m 644 etc/elevate-pam/elevate-pam.toml "$ETCDIR/elevate-pam.toml"
if [[ -n "$PREFIX" ]]; then
  sed -i "s|^# prefix = \"\"  .*|prefix = \"${PREFIX}\"|" "$ETCDIR/elevate-pam.toml"
fi
install -m 644 etc/elevate-pam/services/*.toml "$ETCDIR/services/"
install -m 644 etc/elevate-pam/services/*.toml "$LIBDIR/elevate-pam/services/"
install -m 644 include/security/*.h "$INCLUDEDIR/security/" 2>/dev/null || true
[[ -f target/release/elevate-pam ]] && install -m 755 target/release/elevate-pam "$BINDIR/elevate-pam"

echo "Done."
