#!/usr/bin/env bash
# Build all four libhv dns_name_decode PoCs.
set -euo pipefail
cd "$(dirname "$0")"

CLANG="${CLANG:-clang}"
LIBHV_DIR="./libhv"

# 1. Vendor libhv (only needed to compile protocol/dns.c + headers).
if [ ! -d "$LIBHV_DIR" ]; then
  echo "[*] cloning libhv..."
  git clone --depth 1 https://github.com/ithewei/libhv.git "$LIBHV_DIR"
fi

# 2. Generate hconfig.h (dns.h needs BYTE_ORDER etc.).
if [ ! -f "$LIBHV_DIR/hconfig.h" ]; then
  echo "[*] generating hconfig.h (./configure)..."
  (cd "$LIBHV_DIR" && ./configure >/dev/null 2>&1 || true)
  # Fallback: minimal hconfig.h if configure didn't produce one
  if [ ! -f "$LIBHV_DIR/hconfig.h" ]; then
    touch "$LIBHV_DIR/hconfig.h"
  fi
fi

INC="-I$LIBHV_DIR -I$LIBHV_DIR/base -I$LIBHV_DIR/protocol"
DNS_C="$LIBHV_DIR/protocol/dns.c"

mkdir -p bin

echo "[*] building ASAN PoCs (crash / OOB read)..."
"$CLANG" -fsanitize=address -g -O0 $INC pocs/dns_overflow_poc.c "$DNS_C" -o bin/dns_overflow_poc
"$CLANG" -fsanitize=address -g -O0 $INC pocs/dns_read_poc.c    "$DNS_C" -o bin/dns_read_poc

echo "[*] building non-ASAN PoCs (adjacency-dependent RIP / code-exec)..."
"$CLANG" -g -O0 $INC pocs/dns_hijack_poc.c "$DNS_C" -o bin/dns_hijack_poc
"$CLANG" -g -O0 -no-pie $INC pocs/dns_exec_poc.c "$DNS_C" -o bin/dns_exec_poc

echo "[*] done:"
ls -la bin/
