#!/bin/sh
# Build zainium-logind-session against Zainium's own musl sysroot.
#
# Not a workspace crate: this is C on purpose. It calls sd_bus_call_method(),
# which is variadic -- trivial from C, and painful to bind correctly from Rust
# without pulling a whole D-Bus crate stack into elevate-pam.
#
# Usage: ./build.sh [SYSHUB_DIR] [OUT]
set -e

SYSHUB="${1:-/home/alizain/os/zairoot/overlayer/syshub}"
OUT="${2:-zainium-logind-session}"

musl-gcc -O2 -o "$OUT" zainium-logind-session.c \
    -I"$SYSHUB/include" \
    -L"$SYSHUB/lib" \
    -L"$SYSHUB/x86_64-zainium-linux-musl/lib" \
    -Wl,-rpath-link="$SYSHUB/lib:$SYSHUB/x86_64-zainium-linux-musl/lib" \
    -Wl,-dynamic-linker=/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1 \
    -Wl,-rpath=/overlayer/syshub/lib \
    -Wl,-l:libsystemd.so.0 -Wl,-l:libucontext.so.1

# musl-gcc records the host's generic "libc.so" SONAME; Zainium's runtime
# linker only knows it as libc.musl-x86_64.so.1.
patchelf --replace-needed libc.so libc.musl-x86_64.so.1 "$OUT"

echo "built $OUT"
readelf -d "$OUT" | grep NEEDED
