#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="${1:-release}"

cargo build --workspace --"$PROFILE" \
  -p elevate-pam \
  -p pam-unix -p pam-env -p pam-limits -p pam-access \
  -p pam-deny -p pam-permit -p pam-rootok -p pam-wheel \
  -p pam-nologin -p pam-securetty -p pam-faillock -p pam-mkhomedir \
  -p elevate-pam-cli

echo "Artifacts under target/$PROFILE/"
ls -1 "target/$PROFILE"/libpam_*.so "target/$PROFILE"/libelevate_pam* 2>/dev/null || true
