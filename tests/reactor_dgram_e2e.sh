#!/usr/bin/env bash
# E2E for RFC 9221 QUIC datagrams from nimony: build the datagram echo program
# (server + client over one epoll loop) and assert the unreliable datagram
# round-trips.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8492}"
CERT="$NC/cert.pem"; KEY="$NC/key.pem"

echo "== build QUIC glue shim =="
bash "$ROOT/quic/build.sh" >/dev/null

echo "== self-signed cert =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$CERT" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null

echo "== build dgram_echo =="
BIN="$(build_example "$ROOT" "$NC" dgram_echo)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

export LD_LIBRARY_PATH="$ROOT/quic"
OUT="$("$BIN" "$PORT" "$CERT" "$KEY" 2>&1)"
echo "$OUT"
rm -rf "$NC"
echo "$OUT" | grep -q "DGRAM_ECHO=ping-datagram" || { echo FAIL; exit 1; }
echo PASS
