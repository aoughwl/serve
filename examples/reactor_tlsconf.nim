## The same ALPN-dispatching HTTPS server, but with a TLS context the CALLER
## builds and configures — the point being that every `tls` knob stays reachable
## instead of being frozen inside the server's entry point.
##
##   bin/reactor_tlsconf 8443 cert.pem key.pem &
##   curl -k --http2 https://127.0.0.1:8443/hi
##
## Here: TLS 1.3 only, and a key-exchange group list that prefers the
## post-quantum X25519MLKEM768 (needs an OpenSSL that has it — 3.5+; on an older
## one the setter fails and the handshake falls back to X25519, which is exactly
## why the return value is reported rather than discarded).

import std/[cmdline, strutils, syncio]
import serve
import serve/reactorh2
import tls

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8443
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"

var ctx = newTlsServerContext(certFile, keyFile)
if not ctx.isValid:
  echo "failed to load cert/key: ", lastTlsError()
  quit(1)
echo "tls1.3-only: ", ctx.setMinVersion(TLS1_3_VERSION)
echo "pq groups:   ", ctx.setGroups(PostQuantumGroups)

serveHttpsAlpnReactor(port, ctx, handler)
