#!/usr/bin/env bash
# Graceful shutdown of a reactor server.
#
# Before this the reactor had no stop at all: `run()` looped until the process
# was killed, so the only way to end a server was to cut a response in half.
# SIGINT/SIGTERM now request a graceful stop — listeners close, connections
# already in flight finish, then `run()` returns.
#
# Asserted here, in order: a keep-alive connection open across the signal still
# gets a complete, correct response; a NEW connection after the signal is
# refused (the listener really did close); and the process exits on its own.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8148}"

echo "== build reactor_http =="
BIN="$(build_example "$ROOT" "$NC" reactor_http)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill -9 $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" "$SRV" <<'PY'
import os, signal, socket, sys, time

PORT, SRV = int(sys.argv[1]), int(sys.argv[2])

def request(s, path, body):
    s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
              b"Connection: keep-alive\r\n\r\n%s" % (path.encode(), len(body), body))
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: raise IOError("closed before headers")
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    n = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":")[1])
    while len(rest) < n:
        d = s.recv(65536)
        if not d: raise IOError("closed mid-body")
        rest += d
    return rest[:n]

# A keep-alive connection that is already established and already used.
s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
if request(s, "/echo", b"before") != b"before":
    print("FAIL: server was not healthy before the signal"); sys.exit(1)

os.kill(SRV, signal.SIGTERM)
time.sleep(0.3)

# 1. the in-flight connection still works
try:
    got = request(s, "/echo", b"after-signal")
except Exception as e:      # noqa: BLE001
    print("FAIL: established connection died on the signal: %r" % (e,)); sys.exit(1)
if got != b"after-signal":
    print("FAIL: established connection got %r after the signal" % got); sys.exit(1)

# 2. a new connection is refused — the listener is gone
refused = False
try:
    s2 = socket.create_connection(("127.0.0.1", PORT), timeout=2)
    s2.close()
except (ConnectionRefusedError, socket.timeout):
    refused = True
if not refused:
    print("FAIL: server still accepted a new connection after the signal"); sys.exit(1)

# 3. and once the last connection closes, the process leaves on its own
s.sendall(b"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
s.close()
deadline = time.time() + 5
gone = False
while time.time() < deadline and not gone:
    try:
        os.kill(SRV, 0)
        time.sleep(0.1)
    except OSError:
        gone = True
if not gone:
    print("FAIL: server did not exit within 5s of its last connection closing")
    sys.exit(1)
print("graceful shutdown: in-flight request completed, listener closed, process exited")
PY
echo "PASS"
