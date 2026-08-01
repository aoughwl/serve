#!/usr/bin/env bash
# The router over the async stack, on all three protocols.
#
# Two things this pins down that nothing else did. First, that `toHandler`'s
# `{.nimcall.}` entry point really does compose with the reactor servers — the
# router was written for the blocking loop, and nothing demonstrated it working
# with the async one. Second, that request-scoped routing state (path params)
# survives the HTTP/3 path, where the request is reconstructed from
# `(method, path, body)` rather than parsed off the wire.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
NC="$(mktemp -d)"; PORT="${PORT:-8151}"

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl absent"; exit 0; }
[[ -f "$ROOT/quic/libaowlquic.so" ]] || { echo "SKIP: build quic/build.sh first"; exit 0; }

echo "== build reactor_router =="
BIN="$(build_example "$ROOT" "$NC" reactor_router)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1

export LD_LIBRARY_PATH="$ROOT/quic:${LD_LIBRARY_PATH:-}"
"$BIN" "$PORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 1

fail() { echo "FAIL: $*"; exit 1; }
expect() {  # expect <label> <curl-args...> -- <wanted-body>
  local label="$1"; shift
  local want="${*: -1}"; set -- "${@:1:$#-1}"
  local got
  got="$(curl -sk --max-time 10 "$@" 2>/dev/null)"
  [[ "$got" == "$want" ]] || fail "$label: got $(printf %q "$got"), wanted $(printf %q "$want")"
  echo "$label: ok"
}

expect "h2 param route"  --http2 "https://127.0.0.1:$PORT/users/42"  "user 42"
expect "h2 static route" --http2 "https://127.0.0.1:$PORT/users"     "all users"
expect "h1 POST route"   --http1.1 -X POST --data-binary "bob" "https://127.0.0.1:$PORT/users" "created: bob"
expect "custom 404"      --http2 "https://127.0.0.1:$PORT/nope"      "no route for /nope"

H3="$(python3 "$ROOT/tests/h3_interop_client.py" 127.0.0.1 "$PORT" /users/7 2>/dev/null | tail -2)"
echo "$H3" | grep -q 'STATUS=200' || fail "h3 status not 200: $H3"
echo "$H3" | grep -q 'BODY=user 7' || fail "h3 lost the path parameter: $H3"
echo "h3 param route: ok"

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || fail "server is not single-threaded"
echo "PASS"
