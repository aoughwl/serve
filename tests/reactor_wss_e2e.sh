#!/usr/bin/env bash
# E2E for the async wss:// server on the reactor.
#
# Many simultaneous TLS WebSocket clients, each doing a full TLS handshake, then
# the RFC 6455 Upgrade, then several echo round-trips — all served on the
# server's single thread. Frames are built and parsed here rather than with a
# library so the test depends on nothing but python3 + openssl.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8146}"; N="${N:-20}"; MSGS="${MSGS:-4}"

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl absent"; exit 0; }

echo "== build reactor_wss =="
"$NIMONY" c --nimcache:"$NC" \
  --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" --path:"$H/aoughwl-ws" \
  --path:"$H/aoughwl-compress" \
  "$ROOT/examples/reactor_wss.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' || true
BIN="$(find "$NC" -type f -name reactor_wss -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1

"$BIN" "$PORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.7

python3 - "$PORT" "$N" "$MSGS" <<'PY'
import base64, os, socket, ssl, struct, sys, threading

PORT, N, MSGS = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def send_text(s, payload):
    data = payload.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    n = len(data)
    if n < 126:
        hdr = bytes([0x81, 0x80 | n])
    else:
        hdr = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
    s.sendall(hdr + mask + masked)

def recv_text(s):
    buf = b""
    while True:
        while len(buf) < 2:
            d = s.recv(65536)
            if not d: raise IOError("closed")
            buf += d
        ln = buf[1] & 0x7F
        off = 2
        if ln == 126:
            while len(buf) < 4:
                buf += s.recv(65536)
            ln = struct.unpack(">H", buf[2:4])[0]; off = 4
        while len(buf) < off + ln:
            d = s.recv(65536)
            if not d: raise IOError("closed mid-frame")
            buf += d
        return buf[off:off+ln].decode()

results, errors = [0] * N, [None] * N

def worker(i):
    try:
        raw = socket.create_connection(("127.0.0.1", PORT), timeout=15)
        s = ctx.wrap_socket(raw, server_hostname="localhost")
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % key).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            d = s.recv(65536)
            if not d: raise IOError("closed during handshake")
            head += d
        if b"101" not in head.split(b"\r\n")[0]:
            raise IOError("no 101: %r" % head.split(b"\r\n")[0])
        ok = 0
        for m in range(MSGS):
            msg = "c%d-m%d" % (i, m)
            send_text(s, msg)
            if recv_text(s) == msg:
                ok += 1
        results[i] = ok
        s.close()
    except Exception as e:      # noqa: BLE001 - the failure text is the report
        errors[i] = repr(e)

ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()

total, want = sum(results), N * MSGS
if errors.count(None) != N or total != want:
    print("FAIL: %d/%d echoes over wss" % (total, want))
    for i, e in enumerate(errors):
        if e: print("  client %d: %s" % (i, e))
    sys.exit(1)
print("async WSS: %d/%d echoes across %d simultaneous TLS clients" % (total, want, N))
PY

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || { echo "FAIL: server is not single-threaded"; exit 1; }
echo "PASS"
