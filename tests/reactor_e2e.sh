#!/usr/bin/env bash
# End-to-end test for the single-threaded epoll reactor: build the reactor echo
# server, then hammer it with many SIMULTANEOUS client connections and assert
# every one is served concurrently on the server's single thread.
#
# Requires a working Nimony (override with NIMONY=) and the sibling net-stack
# checkouts under $HOME (tcp/net/tls/http/compress).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"
NC="$(mktemp -d)"
PORT="${PORT:-8094}"

echo "== build reactor_echo =="
"$NIMONY" c --nimcache:"$NC" \
  --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-net" --path:"$H/aoughwl-compress" --path:"$H/aoughwl-tls" \
  "$ROOT/examples/reactor_echo.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' || true
BIN="$(find "$NC" -type f -name reactor_echo -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

echo "== run server + concurrent clients =="
"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" <<'PY'
import socket, sys
PORT = int(sys.argv[1]); N = 100; ROUNDS = 3
conns = [socket.create_connection(("127.0.0.1", PORT), timeout=5) for _ in range(N)]
ok = 0; total = N * ROUNDS
for r in range(ROUNDS):
    for i, s in enumerate(conns): s.sendall(("r%dc%d" % (r, i)).encode())
    for i, s in enumerate(conns):
        try:
            if s.recv(100).decode() == ("r%dc%d" % (r, i)): ok += 1
        except Exception: pass
for s in conns: s.close()
print("reactor e2e: %d/%d echoes across %d simultaneous conns x %d rounds" % (ok, total, N, ROUNDS))
sys.exit(0 if ok == total else 1)
PY
RC=$?

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1 — single-threaded multiplexing)"
[[ "$RC" -eq 0 && "$THREADS" -eq 1 ]] && echo "PASS" || { echo "FAIL"; exit 1; }
