#!/usr/bin/env bash
# HTTP/2 conformance via h2spec (https://github.com/summerwind/h2spec).
#
# Before this, HTTP/2 coverage was two curl smoke tests — "curl got a 200 back",
# which says nothing about frame handling, flow control, HPACK edge cases, or
# protocol-error responses. h2spec drives all 146 cases from RFC 7540/7541.
#
# BASELINE 2026-08-01: 146 passed / 0 failed, against the REACTOR server
# (examples/reactor_h2.nim). Never lower it.
#
# The first baseline here was 95/146 against the blocking `serveHttp2`, and the
# note blamed missing GOAWAY/RST_STREAM. That diagnosis was wrong: every one of
# those 51 cases passes when its section is run alone. The blocking server
# serves ONE connection at a time — its accept loop runs a whole session to
# completion — so a peer that leaves a connection open wedges the listener and
# every later case times out. Two real bugs hid behind that:
#   * mem_recv was fed once per read and its return value ignored, so a frame
#     sitting in the tail of a read was silently dropped (5.1.1);
#   * closing with unread bytes still queued made the kernel send RST where the
#     peer expected a clean FIN (3.8, 7.1).
# Hence: run the gate against the async server, which multiplexes connections.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8091}"
BASELINE="${BASELINE:-146}"

H2SPEC="${H2SPEC:-$HOME/.local/bin/h2spec}"
if [[ ! -x "$H2SPEC" ]]; then
  echo "SKIP: h2spec not installed (expected at $H2SPEC)"; exit 0
fi

NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"
trap 'rm -rf "$NC"' EXIT

build() {   # build <example-name>
  "$NIMONY" c --nimcache:"$NC" \
    --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
    --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" --path:"$H/aoughwl-compress" \
    "$ROOT/examples/$1.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' || true
  find "$NC" -type f -name "$1" -executable | head -1
}

# Runs the suite against one already-listening server and enforces the baseline.
gate() {    # gate <label> <port> [extra h2spec args...]
  local label="$1" port="$2"; shift 2
  local out summary passed
  out="$("$H2SPEC" -h 127.0.0.1 -p "$port" --timeout 3 "$@" 2>&1)"
  summary="$(echo "$out" | grep -E '^[0-9]+ tests,' | tail -1)"
  echo "$label: $summary"
  passed="$(echo "$summary" | sed -E 's/.*, ([0-9]+) passed.*/\1/')"
  if [[ -z "$passed" ]]; then
    echo "FAIL: could not parse h2spec summary for $label"; return 1
  fi
  if (( passed < BASELINE )); then
    echo "FAIL: h2spec regression on $label — $passed passed, baseline is $BASELINE"
    echo "$out" | grep -E '^\s+×' | head -20
    return 1
  fi
  if (( passed > BASELINE )); then
    echo "IMPROVED: $label $passed passed (baseline $BASELINE) — raise BASELINE in this script"
  fi
  echo "PASS $label ($passed/146, baseline $BASELINE)"
  return 0
}

echo "== build reactor_h2 =="
BIN="$(build reactor_h2)"
[[ -n "$BIN" ]] || { echo "FAIL: could not build examples/reactor_h2.nim"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$NC"' EXIT
sleep 1
gate "h2c " "$PORT" || exit 1
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null || true

# --- the same suite over TLS (ALPN h2), which is what a browser speaks -------
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP: openssl absent, TLS half of the gate not run"; exit 0
fi
echo "== build reactor_h2tls =="
TBIN="$(build reactor_h2tls)"
[[ -n "$TBIN" ]] || { echo "FAIL: could not build examples/reactor_h2tls.nim"; exit 1; }
openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1
TPORT="$(( PORT + 1 ))"
"$TBIN" "$TPORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$NC"' EXIT
sleep 1
gate "h2tls" "$TPORT" -t -k || exit 1
