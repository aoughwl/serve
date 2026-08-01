#!/usr/bin/env bash
# E2E for WebTransport STREAMS (bidi + uni) over HTTP/3 from nimony: build the
# WT-enabled shim (vendored nghttp3 >= 1.x) and the wt_stream_echo program
# (server + client on one epoll loop), then assert both stream round-trips.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8497}"
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

echo "== build wt_stream_echo =="
"$NIMONY" c --nimcache:"$NC" --path:"$ROOT" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-http" --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" \
  "$ROOT/examples/wt_stream_echo.nim" 2>&1 | grep -iE 'Error:|FAILURE' && exit 1 || true
BIN="$(find "$NC" -type f -name wt_stream_echo -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

export LD_LIBRARY_PATH="$ROOT/quic:$ROOT/quic/vendor/lib"
OUT="$("$BIN" "$PORT" "$CERT" "$KEY" 2>&1)"
echo "$OUT"
rm -rf "$NC"
echo "$OUT" | grep -q "WT_SESSION=established" || { echo "FAIL: no WT session"; exit 1; }
echo "$OUT" | grep -q "WT_BIDI_ECHO=wt-bidi-hello" || { echo "FAIL: no bidi echo"; exit 1; }
echo "$OUT" | grep -q "WT_UNI_ANSWER=srv:wt-uni-hello" || { echo "FAIL: no uni answer"; exit 1; }
echo PASS
