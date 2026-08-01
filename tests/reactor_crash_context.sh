#!/usr/bin/env bash
# What a failing handler does, and whether the crash says which request did it.
#
# A handler cannot raise: `Handler` has no `.raises`, so nimony rejects `raise`
# inside one at compile time — the "uncaught exception kills the server" class
# does not exist here. What remains is a DEFECT (index error, nil dereference),
# which is not catchable: `panic` in std/system/panics.nim writes its message
# and calls exit(1).
#
# So the deliverable is not "survive it" — it is "say what killed you". Before
# this the log read `seqimpl.nim(167, 41): i < s.len and 0 <= i` and named no
# request, which on a busy server is the difference between a five-minute fix
# and an unreproducible ticket.
#
# Note the hook is atexit, not a signal handler: nothing raises SIGABRT on this
# path, and the first version of the module installed signal handlers that never
# fired. This gate exists to keep that from being re-broken silently.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
NC="$(mktemp -d)"; PORT="${PORT:-8216}"

echo "== build reactor_raise =="
BIN="$(build_example "$ROOT" "$NC" reactor_raise)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

fail() { echo "FAIL: $*"; exit 1; }

"$BIN" "$PORT" > "$NC/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.7

# Healthy first, so a later silence means the crash and not a dead start.
[[ "$(curl -s --max-time 5 "http://127.0.0.1:$PORT/hello")" == "still here" ]] \
  || fail "server was not healthy before the defect"
BOUND_BEFORE="$(ss -ltn 2>/dev/null | grep -c ":$PORT" || true)"
[[ "$BOUND_BEFORE" == "1" ]] || fail "port $PORT not bound before the defect"

# The defect. curl gets no reply (exit 52, empty response).
CODE="$(curl -s --max-time 5 -o /dev/null -w '%{exitcode}' "http://127.0.0.1:$PORT/boom" || true)"
[[ "$CODE" == "52" ]] || echo "note: curl exit $CODE (52 = empty reply, the expected shape)"
sleep 0.7

# The process is gone — checked by the PORT, not by a pid, because pgrep also
# matches the shell wrapper and reports a corpse as alive.
BOUND_AFTER="$(ss -ltn 2>/dev/null | grep -c ":$PORT" || true)"
[[ "$BOUND_AFTER" == "0" ]] || fail "port still bound: the defect did not end the process"
echo "a handler defect ends the process (port released), as fail-fast requires"

# And the log names the request.
grep -q 'AssertionDefect' "$NC/server.log" \
  || fail "no defect message in the log: $(cat "$NC/server.log")"
grep -q 'died while handling: GET /boom' "$NC/server.log" \
  || fail "the crash did not name the request; log was: $(cat "$NC/server.log")"
echo "the crash names the request: $(grep 'died while handling' "$NC/server.log")"

# A clean shutdown must NOT print a crash line — otherwise every graceful stop
# looks like a crash and the line stops meaning anything.
"$BIN" "$(( PORT + 1 ))" > "$NC/clean.log" 2>&1 &
SRV2=$!
sleep 0.7
curl -s --max-time 5 -o /dev/null "http://127.0.0.1:$(( PORT + 1 ))/hello"
kill -TERM $SRV2 2>/dev/null || true
sleep 0.7
if grep -q 'died while handling' "$NC/clean.log"; then
  fail "a graceful shutdown printed a crash line: $(cat "$NC/clean.log")"
fi
echo "a graceful shutdown prints no crash line"
echo "PASS"
