#!/usr/bin/env bash
# E2E for the async WebSocket server on the reactor: build it, do the RFC 6455
# handshake with a raw client, and echo masked frames across many simultaneous
# connections on the server's single thread.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8151}"

echo "== build reactor_ws =="
"$NIMONY" c --nimcache:"$NC" \
  --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" --path:"$H/aoughwl-compress" \
  --path:"$H/aoughwl-ws" "$ROOT/examples/reactor_ws.nim" 2>&1 \
  | grep -viE '^nifmake|^FAILURE|niflink' || true
BIN="$(find "$NC" -type f -name reactor_ws -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" <<'PY'
import socket, base64, hashlib, os, struct, threading, sys
PORT=int(sys.argv[1]); GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
def handshake(s):
    key=base64.b64encode(os.urandom(16)).decode()
    s.sendall(('GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n'%key).encode())
    resp=b''
    while b'\r\n\r\n' not in resp: resp+=s.recv(4096)
    exp=base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
    assert ('Sec-WebSocket-Accept: '+exp).encode() in resp
def send_text(s,msg):
    b=msg.encode(); mask=os.urandom(4); n=len(b); hdr=bytes([0x81])
    hdr+=(bytes([0x80|n]) if n<126 else bytes([0x80|126])+struct.pack('>H',n))
    s.sendall(hdr+mask+bytes(b[i]^mask[i%4] for i in range(n)))
def recv_frame(s):
    d=b''
    while len(d)<2: d+=s.recv(2-len(d))
    n=d[1]&0x7f
    if n==126: n=struct.unpack('>H',s.recv(2))[0]
    elif n==127: n=struct.unpack('>Q',s.recv(8))[0]
    p=b''
    while len(p)<n: p+=s.recv(n-len(p))
    return d[0]&0x0f, p
results=[]
def worker(i):
    s=socket.create_connection(("127.0.0.1",PORT),timeout=5); handshake(s); ok=0
    for r in range(4):
        m="c%d-r%d"%(i,r); send_text(s,m); op,pl=recv_frame(s)
        if op==1 and pl.decode()==m: ok+=1
    s.close(); results.append(ok)
N=40; ts=[threading.Thread(target=worker,args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()
tot=N*4; got=sum(results)
print("async WS: %d/%d echoes across %d simultaneous clients"%(got,tot,N))
sys.exit(0 if got==tot else 1)
PY
RC=$?
THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$RC" -eq 0 && "$THREADS" -eq 1 ]] && echo "PASS" || { echo "FAIL"; exit 1; }
