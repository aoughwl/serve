#!/usr/bin/env bash
# E2E for the async HTTP/2 server on the reactor.
#
# The property under test is the one the blocking `serveHttp2` gets wrong: a
# connection that is open but SILENT must not stop any other connection from
# being served. So this parks an idle h2 connection first (preface sent, then
# nothing), and only then fires the concurrent requests. Against the blocking
# server every one of them hangs; against the reactor all of them are answered
# on its single thread.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8143}"; N="${N:-20}"

echo "== build reactor_h2 =="
BIN="$(build_example "$ROOT" "$NC" reactor_h2)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" "$N" <<'PY'
import socket, struct, subprocess, sys, threading

PORT, N = int(sys.argv[1]), int(sys.argv[2])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
def frame(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p

# --- an idle connection: complete the handshake, then say nothing ------------
idle = socket.create_connection(("127.0.0.1", PORT), timeout=5)
idle.sendall(PREFACE + frame(4, 0, 0))
idle.settimeout(2)
assert len(idle.recv(65536)) > 0, "server never sent its SETTINGS on the idle connection"

# --- concurrent requests, all of which must be answered ----------------------
results = [None] * N
def fetch(i):
    r = subprocess.run(
        ["curl", "-s", "--max-time", "10", "--http2-prior-knowledge",
         "http://127.0.0.1:%d/c%d" % (PORT, i)],
        capture_output=True)
    results[i] = r.stdout.decode(errors="replace").strip()

ts = [threading.Thread(target=fetch, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()

bad = [(i, r) for i, r in enumerate(results) if r != "ok /c%d" % i]
if bad:
    print("FAIL: %d/%d requests wrong while an idle connection was open" % (len(bad), N))
    for i, r in bad[:5]:
        print("  request %d -> %r" % (i, r))
    sys.exit(1)

# --- the idle connection is still live and still speaks HTTP/2 ---------------
idle.sendall(frame(6, 0, 0, b"stillher"))
idle.settimeout(3)
buf, acked = b"", False
while not acked:
    try:
        d = idle.recv(65536)
    except socket.timeout:
        break
    if not d:
        break
    buf += d
    i = 0
    while i + 9 <= len(buf):                      # walk whole frames only
        ln = int.from_bytes(buf[i:i+3], "big")
        if i + 9 + ln > len(buf):
            break
        if buf[i+3] == 6 and (buf[i+4] & 0x01):   # PING with ACK
            acked = True
        i += 9 + ln
    buf = buf[i:]
if not acked:
    print("FAIL: idle connection never answered PING with a PING ACK")
    sys.exit(1)
idle.close()
print("reactor_h2_e2e: %d concurrent requests served with an idle connection parked" % N)
PY
echo "PASS"
