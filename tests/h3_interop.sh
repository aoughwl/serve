#!/usr/bin/env bash
# HTTP/3 INTEROP against a third-party implementation (aioquic).
#
# Every other HTTP/3 test here drives our shim against our shim. That shows the
# two halves agree with each other and nothing about whether either agrees with
# RFC 9000 / RFC 9114 — a shared misreading passes a self-interop test happily.
# This gate puts a client we did not write on the other end.
#
#   pip3 install --user aioquic
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8455}"
NC="$(mktemp -d)"
CERT="$NC/cert.pem"; KEY="$NC/key.pem"

if ! python3 -c "import aioquic" >/dev/null 2>&1; then
  echo "SKIP: aioquic not installed (pip3 install --user aioquic)"; exit 0
fi

BIN="$(find "$ROOT/examples/nimcache" -type f -name reactor_h3 -executable 2>/dev/null | head -1)"
if [[ -z "$BIN" ]]; then
  echo "SKIP: build examples/reactor_h3.nim first"; exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$CERT" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null

export LD_LIBRARY_PATH="$ROOT/quic:$ROOT/quic/vendor/lib"
"$BIN" "$PORT" "$CERT" "$KEY" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$NC"' EXIT
sleep 2

fail=0

echo "== GET =="
OUT="$(timeout 30 python3 "$ROOT/tests/h3_interop_client.py" 127.0.0.1 "$PORT" /hello 2>/dev/null)"
echo "$OUT"
echo "$OUT" | grep -q "^STATUS=200$" || { echo "FAIL: GET status"; fail=1; }
echo "$OUT" | grep -q "GET /hello" || { echo "FAIL: GET body"; fail=1; }

echo "== POST =="
OUT="$(timeout 30 python3 "$ROOT/tests/h3_interop_client.py" 127.0.0.1 "$PORT" /echo "interop-body" 2>/dev/null)"
echo "$OUT"
echo "$OUT" | grep -q "^STATUS=200$" || { echo "FAIL: POST status"; fail=1; }

if (( fail )); then
  echo "FAIL: third-party HTTP/3 interop"
  exit 1
fi
echo PASS
