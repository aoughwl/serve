#!/usr/bin/env bash
# HTTP/2 conformance via h2spec (https://github.com/summerwind/h2spec).
#
# Before this, HTTP/2 coverage was two curl smoke tests — "curl got a 200 back",
# which says nothing about frame handling, flow control, HPACK edge cases, or
# protocol-error responses. h2spec drives all 146 cases from RFC 7540/7541.
#
# BASELINE 2026-08-01: 95 passed / 51 failed.
# Every failure is "Error: Timeout": serve/http2.nim does not answer protocol
# violations with GOAWAY / RST_STREAM, it simply ignores them and the connection
# stalls. That is a real gap, recorded here rather than hidden — raise BASELINE
# as it is closed, and never lower it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8091}"
BASELINE="${BASELINE:-95}"

H2SPEC="${H2SPEC:-$HOME/.local/bin/h2spec}"
if [[ ! -x "$H2SPEC" ]]; then
  echo "SKIP: h2spec not installed (expected at $H2SPEC)"; exit 0
fi

BIN="$(find "$ROOT/examples/nimcache" -type f -name h2_server -executable 2>/dev/null | head -1)"
if [[ -z "$BIN" ]]; then
  echo "SKIP: build examples/h2_server.nim first"; exit 0
fi

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2

OUT="$("$H2SPEC" -h 127.0.0.1 -p "$PORT" --timeout 3 2>&1)"
SUMMARY="$(echo "$OUT" | grep -E '^[0-9]+ tests,' | tail -1)"
echo "$SUMMARY"

PASSED="$(echo "$SUMMARY" | sed -E 's/.*, ([0-9]+) passed.*/\1/')"
if [[ -z "$PASSED" ]]; then
  echo "FAIL: could not parse h2spec summary"; exit 1
fi

if (( PASSED < BASELINE )); then
  echo "FAIL: h2spec regression — $PASSED passed, baseline is $BASELINE"
  echo "$OUT" | grep -E '^\s+×' | head -20
  exit 1
fi
if (( PASSED > BASELINE )); then
  echo "IMPROVED: $PASSED passed (baseline $BASELINE) — raise BASELINE in this script"
fi
echo "PASS ($PASSED/146, baseline $BASELINE)"
