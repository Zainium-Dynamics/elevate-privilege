#!/usr/bin/env bash
# Install elevate-pam on Zainium (no /usr).
#
# Default DESTROOT is live system roots (/lib, /etc, /bin).
# For the zairoot overlayer tree:
#   DESTROOT=/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub ./scripts/install-dev.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Empty DESTROOT => install to real /lib /etc /bin (Zainium layout, no /usr)
DESTROOT="${DESTROOT:-}"
LIBDIR="${LIBDIR:-${DESTROOT}/lib}"
ETCDIR="${ETCDIR:-${DESTROOT}/etc/elevate-pam}"
MODDIR="${MODDIR:-${LIBDIR}/security}"
BINDIR="${BINDIR:-${DESTROOT}/bin}"
INCLUDEDIR="${INCLUDEDIR:-${DESTROOT}/include}"

cd "$ROOT"

echo "==> Building elevate-pam (release, shared)"
cargo build -p elevate-pam -p elevate-pam-cli --release --features shared
cargo build -p pam-unix -p pam-env -p pam-limits -p pam-deny -p pam-permit \
  -p pam-rootok -p pam-wheel -p pam-nologin -p pam-securetty --release 2>/dev/null || true

echo "==> Installing to LIBDIR=$LIBDIR ETCDIR=$ETCDIR"
install -d "$LIBDIR" "$MODDIR" "$ETCDIR/services" "$LIBDIR/elevate-pam/services" "$BINDIR"
if [[ -d "$ROOT/include/security" ]]; then
  install -d "$INCLUDEDIR/security"
fi

# Shared library
if [[ -f target/release/libelevate_pam.so ]]; then
  install -m 755 target/release/libelevate_pam.so "$LIBDIR/libelevate_pam.so.0"
  ln -sfn libelevate_pam.so.0 "$LIBDIR/libelevate_pam.so"
  # Optional drop-in classic soname (off by default — elevate loads libelevate_pam)
  if [[ "${INSTALL_LIBPAM_SONAME:-0}" == "1" ]]; then
    ln -sfn libelevate_pam.so.0 "$LIBDIR/libpam.so.0"
    ln -sfn libelevate_pam.so.0 "$LIBDIR/libpam.so"
    echo "    also provided libpam.so.0 -> libelevate_pam.so.0"
  fi
fi

if [[ -f target/release/libelevate_pam.a ]]; then
  install -m 644 target/release/libelevate_pam.a "$LIBDIR/"
fi

# Modules as pam_*.so in /lib/security
for m in pam_unix pam_env pam_limits pam_deny pam_permit pam_rootok pam_wheel pam_nologin pam_securetty; do
  f="target/release/lib${m}.so"
  if [[ -f "$f" ]]; then
    install -m 755 "$f" "$MODDIR/${m}.so"
  fi
done

install -m 644 elevate-pam.toml "$ETCDIR/elevate-pam.toml"
install -m 644 config/services/*.toml "$ETCDIR/services/"
install -m 644 config/services/*.toml "$LIBDIR/elevate-pam/services/" 2>/dev/null || true

if [[ -d include/security ]]; then
  install -m 644 include/security/*.h "$INCLUDEDIR/security/" 2>/dev/null || true
fi

if [[ -f target/release/elevate-pam ]]; then
  install -m 755 target/release/elevate-pam "$BINDIR/elevate-pam"
fi

echo "Done (elevate-pam / libelevate_pam)."
echo "  lib:      $LIBDIR/libelevate_pam.so.0"
echo "  modules:  $MODDIR"
echo "  services: $ETCDIR/services"
echo "  CLI:      $BINDIR/elevate-pam"
echo ""
echo "elevate loads this via dlopen(libelevate_pam.so*) — see elevate src/pam/dynload.rs"
