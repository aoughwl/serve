#!/usr/bin/env bash
# E2E for the async HTTP/1.1 server on the reactor: build it, then drive many
# SIMULTANEOUS keep-alive connections and assert every request is served on the
# server's single thread.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8142}"

echo "== build reactor_http =="
BIN="$(build_example "$ROOT" "$NC" reactor_http)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" <<'PY'
import socket, threading, sys
PORT=int(sys.argv[1]); N=60; REQS=5; results=[]
def worker(i):
    s=socket.create_connection(("127.0.0.1",PORT),timeout=5); ok=0
    for r in range(REQS):
        body=("c%d-r%d"%(i,r)).encode()
        req=b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"%(len(body),body)
        s.sendall(req)
        data=b""
        while b"\r\n\r\n" not in data: data+=s.recv(4096)
        head,_,rest=data.partition(b"\r\n\r\n")
        cl=next((int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")),0)
        while len(rest)<cl: rest+=s.recv(4096)
        if rest[:cl]==body: ok+=1
    s.close(); results.append(ok)
ts=[threading.Thread(target=worker,args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()
tot=N*REQS; got=sum(results)
print("async HTTP: %d/%d keep-alive echoes across %d simultaneous conns"%(got,tot,N))
sys.exit(0 if got==tot else 1)
PY
RC=$?
THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$RC" -eq 0 && "$THREADS" -eq 1 ]] && echo "PASS" || { echo "FAIL"; exit 1; }
