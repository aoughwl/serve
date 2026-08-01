#!/usr/bin/env bash
# The reactor's idle timeout, exercised through the HTTP/2 server.
#
# Before this the reactor had no clock at all: a coroutine parked on a socket
# that never became ready stayed parked for the life of the process, so one
# silent peer could hold a connection — and, for HTTP/2, one of the fixed
# session slots — forever. `setIdleTimeout` shuts such a socket down, which the
# coroutine sees as an ordinary EOF.
#
# The property asserted here is exactly that: a connection that completes the
# handshake and then says nothing is dropped, and the server keeps serving.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8144}"; IDLE_MS="${IDLE_MS:-1000}"

echo "== build reactor_h2 =="
"$NIMONY" c --nimcache:"$NC" \
  --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" --path:"$H/aoughwl-compress" \
  "$ROOT/examples/reactor_h2.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' || true
BIN="$(find "$NC" -type f -name reactor_h2 -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" "$IDLE_MS" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" "$IDLE_MS" <<'PY'
import socket, subprocess, sys, time

PORT, IDLE = int(sys.argv[1]), int(sys.argv[2]) / 1000.0
s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes([0,0,0,4,0,0,0,0,0]))

t0 = time.time()
s.settimeout(IDLE * 6 + 2)
eof = False
while not eof:
    try:
        if not s.recv(65536):
            eof = True
    except socket.timeout:
        print("FAIL: idle connection was never dropped")
        sys.exit(1)
waited = time.time() - t0
if waited < IDLE * 0.5:
    print("FAIL: connection dropped after %.2fs, before the %.2fs idle limit" % (waited, IDLE))
    sys.exit(1)
s.close()

r = subprocess.run(["curl", "-s", "--max-time", "10", "--http2-prior-knowledge",
                    "http://127.0.0.1:%d/live" % PORT], capture_output=True)
body = r.stdout.decode(errors="replace").strip()
if body != "ok /live":
    print("FAIL: server stopped serving after reaping an idle connection: %r" % body)
    sys.exit(1)
print("reactor_idle_timeout: idle connection reaped after %.2fs (limit %.2fs), server still serving" % (waited, IDLE))
PY
