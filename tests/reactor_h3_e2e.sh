#!/usr/bin/env bash
# E2E for the async HTTP/3 (QUIC) server on the reactor: build the ngtcp2/nghttp3
# glue shim, build the nimony H3 server + client, then fetch concurrently from
# many independent QUIC clients against the server's single thread.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8470}"; N="${N:-20}"
CERT="$NC/cert.pem"; KEY="$NC/key.pem"

echo "== build QUIC glue shim =="
bash "$ROOT/quic/build.sh" >/dev/null

echo "== self-signed cert =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$CERT" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null

echo "== build server + client =="
for t in reactor_h3 h3_client; do
  "$NIMONY" c --nimcache:"$NC" --path:"$ROOT" --path:"$H/aoughwl-tcp" \
    --path:"$H/aoughwl-http" --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" \
    "$ROOT/examples/$t.nim" 2>&1 | grep -iE 'Error:|FAILURE' && exit 1 || true
done
SBIN="$(find "$NC" -type f -name reactor_h3 -executable | head -1)"
CBIN="$(find "$NC" -type f -name h3_client -executable | head -1)"
[[ -n "$SBIN" && -n "$CBIN" ]] || { echo "build failed"; exit 1; }

export LD_LIBRARY_PATH="$ROOT/quic"
"$SBIN" "$PORT" "$CERT" "$KEY" &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.6

echo "== $N concurrent HTTP/3 clients =="
OUT="$NC/out"; mkdir -p "$OUT"
pids=()
for i in $(seq 1 "$N"); do
  ( "$CBIN" "$PORT" "/req$i" > "$OUT/$i.txt" 2>&1 ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

ok=0
for i in $(seq 1 "$N"); do
  if grep -q "STATUS=200" "$OUT/$i.txt" && grep -q "GET /req$i" "$OUT/$i.txt"; then
    ok=$((ok+1))
  else
    echo "  client $i FAILED:"; sed 's/^/    /' "$OUT/$i.txt"
  fi
done

THREADS="$(ls /proc/$SRV/task | wc -l)"
echo "HTTP/3: $ok/$N requests succeeded across $N independent QUIC clients"
echo "server OS threads: $THREADS (expected 1)"
[[ "$ok" -eq "$N" && "$THREADS" -eq 1 ]] || { echo FAIL; exit 1; }
echo PASS
