## Async HTTP/2 over TLS (ALPN "h2") on the reactor — the path a browser takes.
##
##   bin/reactor_h2tls 8443 cert.pem key.pem &
##   curl -k --http2 https://127.0.0.1:8443/hi
##
## Handshakes are pumped on the reactor like any other I/O, so a peer that
## stalls part-way through one stalls only itself.

import std/[cmdline, strutils]
import serve
import serve/reactorh2

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8443
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"
var idleMs = 60_000
if paramCount() >= 4:
  try: idleMs = parseInt(paramStr(4))
  except: idleMs = 60_000

serveHttp2TlsReactor(port, certFile, keyFile, handler, idleMs)
