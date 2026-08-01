#!/usr/bin/env bash
# E2E for the async HTTP/1.1-over-TLS server on the reactor.
#
# The point is not that TLS works once — it is that the HANDSHAKES are async
# too. So this fires many simultaneous connections, each doing a full handshake
# and several keep-alive requests, and asserts they are all served on the
# server's single thread. A handshake run inline on the reactor thread would
# serialise them; one stalled handshake would stop everything.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"
H="$HOME"; NC="$(mktemp -d)"; PORT="${PORT:-8145}"; N="${N:-30}"; REQS="${REQS:-5}"

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl absent"; exit 0; }

echo "== build reactor_https =="
"$NIMONY" c --nimcache:"$NC" \
  --path:"$ROOT" --path:"$H/aoughwl-http" --path:"$H/aoughwl-tcp" \
  --path:"$H/aoughwl-net" --path:"$H/aoughwl-tls" --path:"$H/aoughwl-compress" \
  "$ROOT/examples/reactor_https.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' || true
BIN="$(find "$NC" -type f -name reactor_https -executable | head -1)"
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -keyout "$NC/key.pem" -out "$NC/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1

"$BIN" "$PORT" "$NC/cert.pem" "$NC/key.pem" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.7

python3 - "$PORT" "$N" "$REQS" <<'PY'
import ssl, socket, sys, threading

PORT, N, REQS = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

results = [0] * N
errors = [None] * N

def worker(i):
    try:
        raw = socket.create_connection(("127.0.0.1", PORT), timeout=15)
        s = ctx.wrap_socket(raw, server_hostname="localhost")   # full handshake
        ok = 0
        for r in range(REQS):
            body = ("c%d-r%d" % (i, r)).encode()
            s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
                      b"Connection: keep-alive\r\n\r\n%s" % (len(body), body))
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
            if rest[:n] == body:
                ok += 1
        results[i] = ok
        s.close()
    except Exception as e:      # noqa: BLE001 - the failure text is the report
        errors[i] = repr(e)

ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()

total, want = sum(results), N * REQS
if errors.count(None) != N or total != want:
    print("FAIL: %d/%d echoes over TLS" % (total, want))
    for i, e in enumerate(errors):
        if e: print("  conn %d: %s" % (i, e))
    sys.exit(1)
print("async HTTPS: %d/%d keep-alive echoes across %d simultaneous TLS conns" % (total, want, N))
PY

THREADS="$(ls /proc/$SRV/task 2>/dev/null | wc -l)"
echo "server OS threads: $THREADS (expected 1)"
[[ "$THREADS" == "1" ]] || { echo "FAIL: server is not single-threaded"; exit 1; }
echo "PASS"
