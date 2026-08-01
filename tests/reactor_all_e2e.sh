#!/usr/bin/env bash
# E2E for the combined server: HTTP/1.1 + HTTP/2 (TLS/TCP) and HTTP/3 (QUIC/UDP)
# on the same port number, from one handler, on one OS thread.
#
# HTTP/3 used to run a private epoll loop, so a process could serve QUIC or TCP
# but not both without threads. This asserts all three answer, that the TCP
# responses advertise the HTTP/3 endpoint via Alt-Svc (without which no browser
# ever tries QUIC), and that the whole thing is still one thread.
#
# The HTTP/3 client is aioquic — a third-party implementation, not our own shim
# talking to itself.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8149}"

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl absent"; exit 0; }
[[ -f "$ROOT/quic/libaowlquic.so" ]] || { echo "SKIP: build quic/build.sh first"; exit 0; }
python3 -c "import aioquic" 2>/dev/null || { echo "SKIP: aioquic not installed"; exit 0; }

echo "== build reactor_all =="
BIN="$(build_example "$ROOT" "$NC" reactor_all)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1

export LD_LIBRARY_PATH="$ROOT/quic:${LD_LIBRARY_PATH:-}"
"$BIN" "$PORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 1

fail() { echo "FAIL: $*"; exit 1; }

# --- HTTP/1.1 over TLS, and the Alt-Svc advertisement ------------------------
OUT="$(curl -sk --http1.1 "https://127.0.0.1:$PORT/one" -D- 2>/dev/null)"
echo "$OUT" | grep -q '^HTTP/1.1 200' || fail "no HTTP/1.1 200"
echo "$OUT" | grep -qi "alt-svc: h3=\":$PORT\"" || fail "no Alt-Svc advertising h3 on :$PORT"
echo "$OUT" | grep -q 'ok /one' || fail "HTTP/1.1 body wrong"
echo "http/1.1: 200, Alt-Svc advertises h3"

# --- HTTP/2 over TLS on the same port ----------------------------------------
VER="$(curl -sk --http2 "https://127.0.0.1:$PORT/two" -o "$NC/two.txt" -w '%{http_version}')"
[[ "$VER" == "2" ]] || fail "expected HTTP/2, got $VER"
grep -q 'ok /two' "$NC/two.txt" || fail "HTTP/2 body wrong"
echo "http/2:   200 over the same port"

# --- HTTP/3 over QUIC, same port number, third-party client ------------------
H3="$(python3 "$ROOT/tests/h3_interop_client.py" 127.0.0.1 "$PORT" /three 2>/dev/null | tail -2)"
echo "$H3" | grep -q 'STATUS=200' || fail "HTTP/3 status not 200: $H3"
echo "$H3" | grep -q 'BODY=ok /three' || fail "HTTP/3 body wrong: $H3"
echo "http/3:   200 from aioquic on the same port number"

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || fail "server is not single-threaded"
echo "PASS"
