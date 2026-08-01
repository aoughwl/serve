#!/usr/bin/env bash
# E2E for the ALPN-dispatching TLS server: ONE port, both protocols.
#
# Asserts what a real HTTPS port must do — an h2 client gets HTTP/2, an
# http/1.1 client gets HTTP/1.1, both from the same handler, both while the
# other kind of client is mid-connection, all on one OS thread. And, if h2spec
# is around, that the HTTP/2 half of that port is still fully conformant rather
# than merely reachable.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8147}"; N="${N:-12}"

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl absent"; exit 0; }

echo "== build reactor_alpn =="
BIN="$(build_example "$ROOT" "$NC" reactor_alpn)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1

"$BIN" "$PORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.7

python3 - "$PORT" "$N" <<'PY'
import subprocess, sys, threading

PORT, N = int(sys.argv[1]), int(sys.argv[2])
# Alternate the two protocols so each kind is in flight while the other is.
want = [("--http2", "2") if i % 2 == 0 else ("--http1.1", "1.1") for i in range(N)]
got = [None] * N

def fetch(i):
    flag, _ = want[i]
    r = subprocess.run(["curl", "-sk", flag, "--max-time", "15",
                        "https://127.0.0.1:%d/c%d" % (PORT, i),
                        "-w", "|%{http_version}"], capture_output=True)
    got[i] = r.stdout.decode(errors="replace").strip()

ts = [threading.Thread(target=fetch, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()

bad = []
for i, g in enumerate(got):
    expect = "ok /c%d\n|%s" % (i, want[i][1])
    if g != expect:
        bad.append((i, want[i][0], g))
if bad:
    print("FAIL: %d/%d clients got the wrong protocol or body" % (len(bad), N))
    for i, flag, g in bad[:6]:
        print("  client %d (%s) -> %r" % (i, flag, g))
    sys.exit(1)
print("ALPN dispatch: %d clients, h2 and http/1.1 interleaved, all correct" % N)
PY

H2SPEC="${H2SPEC:-$HOME/.local/bin/h2spec}"
if [[ -x "$H2SPEC" ]]; then
  SUMMARY="$("$H2SPEC" -h 127.0.0.1 -p "$PORT" -t -k --timeout 3 2>&1 | grep -E '^[0-9]+ tests,' | tail -1)"
  echo "h2spec on the shared port: $SUMMARY"
  PASSED="$(echo "$SUMMARY" | sed -E 's/.*, ([0-9]+) passed.*/\1/')"
  [[ "$PASSED" == "146" ]] || { echo "FAIL: expected 146 passed on the ALPN port"; exit 1; }
else
  echo "note: h2spec absent, conformance half of this gate not run"
fi

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || { echo "FAIL: server is not single-threaded"; exit 1; }
echo "PASS"
