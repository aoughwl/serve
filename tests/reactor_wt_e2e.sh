#!/usr/bin/env bash
# E2E for WebTransport over HTTP/3 from nimony: build the WT-enabled shim
# (vendored nghttp3 >= 1.x) and the wt_echo program (server + client on one
# epoll loop), then assert the WebTransport session + datagram round-trip.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8496}"
CERT="$NC/cert.pem"; KEY="$NC/key.pem"

# WebTransport needs vendored nghttp3 >= 1.x.
if [[ ! -f "$ROOT/quic/vendor/lib/pkgconfig/libnghttp3.pc" ]]; then
  echo "SKIP: vendored nghttp3 not built — run quic/build-nghttp3.sh first"; exit 0
fi

echo "== build WT-enabled QUIC shim =="
BUILDOUT="$(bash "$ROOT/quic/build.sh" 2>&1)"
echo "$BUILDOUT"
echo "$BUILDOUT" | grep -q "WebTransport enabled" || { echo "shim not WT-enabled"; exit 1; }

echo "== self-signed cert =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$CERT" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null

echo "== build wt_echo =="
BIN="$(build_example "$ROOT" "$NC" wt_echo)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

export LD_LIBRARY_PATH="$ROOT/quic:$ROOT/quic/vendor/lib"
OUT="$("$BIN" "$PORT" "$CERT" "$KEY" 2>&1)"
echo "$OUT"
rm -rf "$NC"
echo "$OUT" | grep -q "WT_SESSION=established" || { echo "FAIL: no WT session"; exit 1; }
echo "$OUT" | grep -q "WT_DGRAM_ECHO=wt-hello" || { echo "FAIL: no WT datagram echo"; exit 1; }
echo PASS
