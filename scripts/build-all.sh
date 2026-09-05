#!/usr/bin/env bash
# Build entire elevate monorepo (pure-Rust crypto + pam + sudo)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> elevate monorepo (pure Rust crypto — no C OpenSSL)"
echo "    config: elevate_privilege.toml"

mapfile -t PAM_MODULE_CRATES < <(
  grep -oE '"elevate-pam/pam-[a-zA-Z0-9_-]+"' "${ROOT}/Cargo.toml" \
    | tr -d '"' | sed 's#.*/##' | sort -u
)
pkg_args=()
for c in "${PAM_MODULE_CRATES[@]}"; do
  pkg_args+=(-p "$c")
done

cargo build --release \
  -p elevate-crypto \
  -p elevate-pam \
  -p libpam-abi \
  -p elevate-pam-cli \
  -p elevate \
  -p elevate-umbra \
  -p unix_chkpwd \
  "${pkg_args[@]}"

echo "==> artifacts"
ls -la target/release/libelevate_crypto* target/release/libelevate_pam* \
  target/release/libpam.so target/release/elevate target/release/elev \
  target/release/vielev target/release/elevate-pam 2>/dev/null || true

echo "Done."
