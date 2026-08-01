#!/usr/bin/env bash
# E2E for the async HTTP client, through the reverse proxy that uses it.
#
# The claim being tested is not "the proxy forwards" — it is that the OUTBOUND
# call suspends. So the upstream is deliberately slow (0.5s per request), and
# 12 clients hit the proxy at once. If the fetch blocked the reactor thread the
# run would take 12 × 0.5s ≈ 6s; if it suspends, they overlap and the whole
# thing lands near 0.5s. The gate fails above 2.5s — far enough from both
# numbers that it cannot pass by accident on a slow machine.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT/tests/lib.sh"
NC="$(mktemp -d)"; PORT="${PORT:-8160}"; UPPORT="${UPPORT:-8161}"; N="${N:-12}"

echo "== build reactor_proxy =="
BIN="$(build_example "$ROOT" "$NC" reactor_proxy)" || BIN=""
[[ -n "$BIN" ]] || { echo "build failed"; exit 1; }

# A slow upstream, in python so the delay is unambiguous. Threaded, so IT is
# never the bottleneck — any serialisation the gate sees is the proxy's.
cat > "$NC/upstream.py" <<'PY'
import socket, sys, threading, time

PORT = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(64)

def serve(c):
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d: return
            buf += d
        path = buf.split(b" ")[1].decode()
        time.sleep(0.5)                       # the whole point
        body = ("upstream said %s" % path).encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                  b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
    finally:
        c.close()

while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
python3 "$NC/upstream.py" "$UPPORT" &
UP=$!
sleep 0.5
"$BIN" "$PORT" 127.0.0.1 "$UPPORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV $UP 2>/dev/null || true; rm -rf "$NC"' EXIT
sleep 0.5

python3 - "$PORT" "$N" <<'PY'
import socket, sys, threading, time

PORT, N = int(sys.argv[1]), int(sys.argv[2])
results, errors = [None] * N, [None] * N

def one(i):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
        s.sendall(b"GET /slow%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % i)
        buf = b""
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
        s.close()
        results[i] = buf.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
    except Exception as e:     # noqa: BLE001
        errors[i] = repr(e)

t0 = time.time()
ts = [threading.Thread(target=one, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()
elapsed = time.time() - t0

bad = [(i, errors[i] or results[i]) for i in range(N)
       if errors[i] is not None or results[i] != "upstream said /slow%d" % i]
if bad:
    print("FAIL: %d/%d proxied requests wrong" % (len(bad), N))
    for i, r in bad[:5]:
        print("  request %d -> %r" % (i, r))
    sys.exit(1)

print("proxied %d concurrent requests through a 0.5s upstream in %.2fs" % (N, elapsed))
if elapsed > 2.5:
    print("FAIL: %.2fs means the outbound fetch BLOCKED the reactor thread "
          "(serial would be ~%.1fs, overlapped ~0.5s)" % (elapsed, N * 0.5))
    sys.exit(1)
PY
echo "PASS"
