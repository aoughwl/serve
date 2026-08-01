#!/usr/bin/env bash
# Streamed responses: server-sent events, and a download the server never holds.
#
# The claim is "the body is produced, not materialised", so the test measures
# exactly that: it serves a file far larger than any buffer and reads the
# server's PEAK RSS (VmHWM) afterwards. Materialising the body would put the
# whole file in that number; streaming keeps it flat. A checksum comparison on
# its own would pass either way, which is why the memory figure is the
# assertion and the checksum is the sanity check.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
NC="$(mktemp -d)"; PORT="${PORT:-8190}"
SIZE_MB="${SIZE_MB:-128}"
RSS_LIMIT_KB="${RSS_LIMIT_KB:-65536}"      # 64 MiB, i.e. half the payload

echo "== build reactor_stream =="
BIN="$(build_example "$ROOT" "$NC" reactor_stream)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

dd if=/dev/urandom of="$NC/big.bin" bs=1M count="$SIZE_MB" status=none
WANT="$(md5sum "$NC/big.bin" | cut -d' ' -f1)"

"$BIN" "$PORT" "$NC/big.bin" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.7

fail() { echo "FAIL: $*"; exit 1; }

# --- server-sent events ------------------------------------------------------
SSE="$(curl -sN --max-time 10 "http://127.0.0.1:$PORT/events")"
echo "$SSE" | grep -q '^event: tick$' || fail "no SSE event line: $SSE"
echo "$SSE" | grep -q '^data: tick 5$' || fail "SSE stream did not reach the last event"
COUNT="$(echo "$SSE" | grep -c '^data: tick ')"
[[ "$COUNT" == "5" ]] || fail "expected 5 events, got $COUNT"

HEAD="$(curl -sI --max-time 10 "http://127.0.0.1:$PORT/events")"
echo "$HEAD" | grep -qi 'transfer-encoding: chunked' || fail "SSE was not chunked-framed"
echo "$HEAD" | grep -qi 'content-type: text/event-stream' || fail "wrong SSE content type"
echo "$HEAD" | grep -qi 'x-accel-buffering: no' || fail "missing the no-proxy-buffering header"
echo "sse: 5 events, chunked, correctly framed"

# --- the large download ------------------------------------------------------
GOT="$(curl -s --max-time 120 "http://127.0.0.1:$PORT/file" | md5sum | cut -d' ' -f1)"
[[ "$GOT" == "$WANT" ]] || fail "streamed file differs from the original"
echo "download: ${SIZE_MB}MiB byte-exact over chunked transfer"

# --- and the property that matters -------------------------------------------
HWM="$(grep VmHWM /proc/$SRV/status | awk '{print $2}')"
echo "server peak RSS after streaming ${SIZE_MB}MiB: ${HWM} kB (limit ${RSS_LIMIT_KB} kB)"
(( HWM < RSS_LIMIT_KB )) || fail "peak RSS ${HWM} kB means the body was materialised, not streamed"

# --- ordinary responses still work on the same server ------------------------
BODY="$(curl -s --max-time 10 "http://127.0.0.1:$PORT/hello")"
[[ "$BODY" == "hello, not streamed" ]] || fail "non-streamed route broke: $BODY"

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || fail "server is not single-threaded"
echo "PASS"
