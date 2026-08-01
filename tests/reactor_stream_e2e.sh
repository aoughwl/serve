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

TICK_MS="${TICK_MS:-300}"
"$BIN" "$PORT" "$NC/big.bin" "$TICK_MS" >/dev/null 2>&1 &
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

# --- pacing: the producer must not sleep, and must not spin -------------------
# Five events at TICK_MS apart should take about 4 intervals; a producer that
# ignored the pause would finish instantly and one that slept would block the
# thread. Both are checked: the elapsed time, and a plain request served WHILE a
# paced stream is mid-pause.
T0="$(date +%s%N)"
curl -sN --max-time 30 "http://127.0.0.1:$PORT/events" >/dev/null
PACED_MS=$(( ( $(date +%s%N) - T0 ) / 1000000 ))
MIN_MS=$(( TICK_MS * 3 ))
echo "5 events at ${TICK_MS}ms took ${PACED_MS}ms (expected >= ${MIN_MS}ms)"
(( PACED_MS >= MIN_MS )) || fail "the stream ignored pauseMs — events were not paced"

curl -sN --max-time 30 "http://127.0.0.1:$PORT/events" >/dev/null &
SSE_PID=$!
sleep 0.4
T1="$(date +%s%N)"
BODY_MID="$(curl -s --max-time 5 "http://127.0.0.1:$PORT/hello")"
MID_MS=$(( ( $(date +%s%N) - T1 ) / 1000000 ))
wait $SSE_PID 2>/dev/null || true
[[ "$BODY_MID" == "hello, not streamed" ]] || fail "request during a paced stream failed: $BODY_MID"
echo "a plain request mid-pause was served in ${MID_MS}ms"
(( MID_MS < TICK_MS )) || fail "the pause blocked the reactor thread for ${MID_MS}ms"

# --- and a disconnect during a pause ends the stream at once ------------------
# On a SEPARATE server with a deliberately slow feed (5s between events), so the
# stream cannot simply have run to completion: the socket must go when the
# client does, not at the next tick. Otherwise a feed nobody is listening to
# holds its coroutine and its fd for as long as its interval.
SLOWPORT=$(( PORT + 1 ))
"$BIN" "$SLOWPORT" "$NC/big.bin" 5000 >/dev/null 2>&1 &
SLOW=$!
sleep 0.5
FD_IDLE="$(ls /proc/$SLOW/fd | wc -l)"
curl -sN --max-time 30 "http://127.0.0.1:$SLOWPORT/events" >/dev/null &
CPID=$!
sleep 0.6
FD_OPEN="$(ls /proc/$SLOW/fd | wc -l)"
(( FD_OPEN > FD_IDLE )) || { kill $SLOW $CPID 2>/dev/null; fail "the slow stream never opened a connection (idle $FD_IDLE, open $FD_OPEN)"; }
kill -9 $CPID 2>/dev/null || true
sleep 1.0                                  # a fifth of one tick
FD_GONE="$(ls /proc/$SLOW/fd | wc -l)"
kill $SLOW 2>/dev/null || true
echo "slow-feed fds idle/open/after-disconnect: $FD_IDLE / $FD_OPEN / $FD_GONE"
(( FD_GONE <= FD_IDLE )) || fail "an abandoned slow stream held its socket past the disconnect"

# --- a producer that spins is ended, not tolerated ---------------------------
# /spin always says "nothing right now" and never asks for a pause, which is a
# busy loop on the reactor thread. The transport must end that stream. Exercised
# rather than assumed: an unexercised guard is a guess.
T2="$(date +%s%N)"
timeout 15 curl -sN "http://127.0.0.1:$PORT/spin" >/dev/null 2>&1 || true
SPIN_MS=$(( ( $(date +%s%N) - T2 ) / 1000000 ))
echo "a spinning producer was cut off after ${SPIN_MS}ms"
(( SPIN_MS < 5000 )) || fail "a spinning producer was allowed to run — the guard did not fire"
BODY_AFTER="$(curl -s --max-time 10 "http://127.0.0.1:$PORT/hello")"
[[ "$BODY_AFTER" == "hello, not streamed" ]] || fail "server unhealthy after a spinning producer"

# --- the large download ------------------------------------------------------
GOT="$(curl -s --max-time 120 "http://127.0.0.1:$PORT/file" | md5sum | cut -d' ' -f1)"
[[ "$GOT" == "$WANT" ]] || fail "streamed file differs from the original"
echo "download: ${SIZE_MB}MiB byte-exact over chunked transfer"

# --- and the property that matters -------------------------------------------
HWM="$(grep VmHWM /proc/$SRV/status | awk '{print $2}')"
echo "server peak RSS after streaming ${SIZE_MB}MiB: ${HWM} kB (limit ${RSS_LIMIT_KB} kB)"
(( HWM < RSS_LIMIT_KB )) || fail "peak RSS ${HWM} kB means the body was materialised, not streamed"

# --- the same file through the streaming STATIC path -------------------------
# Ranges, validators and Content-Type come from the request, and the body still
# never lands in memory.
RHEAD="$(curl -s --max-time 60 -r 100-109 -D- -o "$NC/part.bin" "http://127.0.0.1:$PORT/static")"
echo "$RHEAD" | grep -q '^HTTP/1.1 206' || fail "streamed static did not answer 206"
echo "$RHEAD" | grep -qi "content-range: bytes 100-109/" || fail "wrong Content-Range: $RHEAD"
[[ "$(wc -c < "$NC/part.bin")" == "10" ]] || fail "range returned $(wc -c < "$NC/part.bin") bytes, wanted 10"
cmp -s <(dd if="$NC/big.bin" bs=1 skip=100 count=10 status=none) "$NC/part.bin" \
  || fail "the ranged bytes are not the right bytes"

LM="$(curl -sI --max-time 60 "http://127.0.0.1:$PORT/static" | grep -i '^last-modified:' | sed 's/^[^:]*: //' | tr -d '\r')"
REAL="$(date -r "$NC/big.bin" -u '+%a, %d %b %Y %H:%M:%S GMT')"
[[ "$LM" == "$REAL" ]] || fail "Last-Modified '$LM' does not match the file's mtime '$REAL'"
echo "streamed static: 206 with the right bytes, Last-Modified matches the file"

ETAG="$(curl -sI --max-time 60 "http://127.0.0.1:$PORT/static" | grep -i '^etag:' | sed 's/^[^:]*: //' | tr -d '\r')"
CODE="$(curl -s --max-time 60 -o /dev/null -w '%{http_code}' -H "If-None-Match: $ETAG" "http://127.0.0.1:$PORT/static")"
[[ "$CODE" == "304" ]] || fail "conditional request got $CODE, wanted 304"
echo "streamed static: a matching ETag is a 304"

# --- ordinary responses still work on the same server ------------------------
BODY="$(curl -s --max-time 10 "http://127.0.0.1:$PORT/hello")"
[[ "$BODY" == "hello, not streamed" ]] || fail "non-streamed route broke: $BODY"

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || fail "server is not single-threaded"
echo "PASS"
