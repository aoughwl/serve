#!/usr/bin/env bash
# Autobahn-style conformance for the async WebSocket server (serve/reactorws.nim):
# UTF-8 validation (6.x), close-code handling (7.x), fragmentation (5.x), control
# frames, RSV/opcode rejection, and permessage-deflate (12.x/13.x) — all against
# the live single-thread reactor server.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8153}"

echo "== build reactor_ws =="
BIN="$(build_example "$ROOT" "$NC" reactor_ws)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

"$BIN" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" <<'PY'
import socket, base64, hashlib, os, struct, sys, zlib
PORT=int(sys.argv[1]); GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
fails=0; oks=0
def report(name, cond):
    global fails, oks
    if cond: oks+=1
    else: fails+=1; print("  FAIL:", name)

def connect(deflate=False):
    s=socket.create_connection(('127.0.0.1',PORT)); s.settimeout(3)
    key=base64.b64encode(os.urandom(16)).decode()
    ext='\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover' if deflate else ''
    s.sendall(('GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13%s\r\n\r\n'%(key,ext)).encode())
    resp=b''
    while b'\r\n\r\n' not in resp: resp+=s.recv(4096)
    exp=base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
    assert ('Sec-WebSocket-Accept: '+exp).encode() in resp, 'handshake failed'
    return s, (b'permessage-deflate' in resp)

def frame(op, payload, fin=True, rsv1=False, masked=True):
    b0=(0x80 if fin else 0)|(0x40 if rsv1 else 0)|op
    n=len(payload); out=bytes([b0])
    mb=0x80 if masked else 0
    if n<126: out+=bytes([mb|n])
    elif n<=0xffff: out+=bytes([mb|126])+struct.pack('>H',n)
    else: out+=bytes([mb|127])+struct.pack('>Q',n)
    if masked:
        m=os.urandom(4); out+=m+bytes(payload[i]^m[i%4] for i in range(n))
    else:
        out+=payload
    return out

def recv_frame(s):
    d=b''
    while len(d)<2: d+=s.recv(2-len(d))
    b0,b1=d[0],d[1]; op=b0&0x0f; fin=bool(b0&0x80); rsv1=bool(b0&0x40)
    ln=b1&0x7f;
    if ln==126: ext=b'';
    if ln==126:
        while len(ext)<2: ext+=s.recv(2-len(ext))
        ln=struct.unpack('>H',ext)[0]
    elif ln==127:
        ext=b''
        while len(ext)<8: ext+=s.recv(8-len(ext))
        ln=struct.unpack('>Q',ext)[0]
    pl=b''
    while len(pl)<ln:
        chunk=s.recv(ln-len(pl))
        if not chunk: break
        pl+=chunk
    return op, pl, fin, rsv1

def expect_close(s, code):
    op,pl,fin,rsv1=recv_frame(s)
    if op!=0x8: return False
    if code is None: return True
    got=struct.unpack('>H',pl[:2])[0] if len(pl)>=2 else None
    return got==code

def rawdeflate(data):
    c=zlib.compressobj(6, zlib.DEFLATED, -15)
    b=c.compress(data)+c.flush(zlib.Z_SYNC_FLUSH)
    return b[:-4] if b.endswith(b'\x00\x00\xff\xff') else b

def rawinflate(data):
    d=zlib.decompressobj(-15)
    return d.decompress(data+b'\x00\x00\xff\xff')

# 1. valid text echo
s,_=connect(); s.sendall(frame(0x1, 'héllo wörld'.encode()))
op,pl,fin,_=recv_frame(s); report('1 valid text echo', op==0x1 and pl.decode()=='héllo wörld'); s.close()

# 2. invalid UTF-8 in text -> Close 1007
s,_=connect(); s.sendall(frame(0x1, b'\xc3\x28'))
report('2 invalid utf8 -> 1007', expect_close(s,1007)); s.close()

# 3. fragmented text reassembly
s,_=connect(); s.sendall(frame(0x1,b'Hel',fin=False)); s.sendall(frame(0x0,b'lo',fin=True))
op,pl,fin,_=recv_frame(s); report('3 fragmented echo', op==0x1 and pl==b'Hello'); s.close()

# 4. ping -> pong
s,_=connect(); s.sendall(frame(0x9,b'hi'))
op,pl,fin,_=recv_frame(s); report('4 ping->pong', op==0xA and pl==b'hi'); s.close()

# 5. clean close 1000 -> echo 1000
s,_=connect(); s.sendall(frame(0x8, struct.pack('>H',1000)))
report('5 close 1000 echo', expect_close(s,1000)); s.close()

# 6. invalid close code 1005 -> 1002
s,_=connect(); s.sendall(frame(0x8, struct.pack('>H',1005)))
report('6 close 1005 -> 1002', expect_close(s,1002)); s.close()

# 7. invalid close code 2999 (reserved) -> 1002
s,_=connect(); s.sendall(frame(0x8, struct.pack('>H',2999)))
report('7 close 2999 -> 1002', expect_close(s,1002)); s.close()

# 8. close reason with bad UTF-8 -> 1007
s,_=connect(); s.sendall(frame(0x8, struct.pack('>H',1000)+b'\xc3\x28'))
report('8 close bad-utf8 reason -> 1007', expect_close(s,1007)); s.close()

# 9. unmasked client frame -> 1002
s,_=connect(); s.sendall(frame(0x1,b'nope',masked=False))
report('9 unmasked -> 1002', expect_close(s,1002)); s.close()

# 10. RSV1 set without negotiated deflate -> 1002
s,_=connect(); s.sendall(frame(0x1,b'x',rsv1=True))
report('10 rsv1 (no deflate) -> 1002', expect_close(s,1002)); s.close()

# 11. reserved opcode 0x3 -> 1002
s,_=connect(); s.sendall(frame(0x3,b''))
report('11 reserved opcode -> 1002', expect_close(s,1002)); s.close()

# 12. control frame >125 bytes -> 1002
s,_=connect(); s.sendall(frame(0x9, b'x'*126))
report('12 oversized control -> 1002', expect_close(s,1002)); s.close()

# 13. continuation with no start -> 1002
s,_=connect(); s.sendall(frame(0x0,b'orphan'))
report('13 orphan continuation -> 1002', expect_close(s,1002)); s.close()

# 14. new data frame during fragmentation -> 1002
s,_=connect(); s.sendall(frame(0x1,b'a',fin=False)); s.sendall(frame(0x1,b'b'))
report('14 data-mid-fragment -> 1002', expect_close(s,1002)); s.close()

# 15. valid multibyte split across frames (incremental UTF-8 passes)
s,_=connect(); s.sendall(frame(0x1,b'\xc3',fin=False)); s.sendall(frame(0x0,b'\xa9',fin=True))
op,pl,fin,_=recv_frame(s); report('15 split multibyte ok', op==0x1 and pl==b'\xc3\xa9'); s.close()

# 16. invalid multibyte split across frames -> 1007
s,_=connect(); s.sendall(frame(0x1,b'\xc3',fin=False)); s.sendall(frame(0x0,b'\x28',fin=True))
report('16 split bad multibyte -> 1007', expect_close(s,1007)); s.close()

# 17. permessage-deflate round trip
s,neg=connect(deflate=True)
report('17a deflate negotiated', neg)
if neg:
    payload=rawdeflate(b'compress me compress me compress me')
    s.sendall(frame(0x1, payload, rsv1=True))
    op,pl,fin,rsv1=recv_frame(s)
    ok = op==0x1 and rsv1 and rawinflate(pl)==b'compress me compress me compress me'
    report('17b deflate echo round-trip', ok)
s.close()

# 18. large (non-compressed) message survives (framing/limits)
s,_=connect(); big=b'z'*200000; s.sendall(frame(0x2, big))
op,pl,fin,_=recv_frame(s); report('18 200KB binary echo', op==0x2 and pl==big); s.close()

print("conformance: %d passed, %d failed" % (oks, fails))
sys.exit(1 if fails else 0)
PY
echo "server OS threads: $(ls /proc/$SRV/task | wc -l) (expected 1)"
echo PASS
