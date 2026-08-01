## One process, one thread, three protocols: HTTP/1.1 and HTTP/2 over TLS on
## TCP, HTTP/3 over QUIC on UDP, all on the same port number and all behind one
## handler. Every TCP response carries `Alt-Svc: h3=":<port>"`, which is how a
## browser discovers the HTTP/3 side and moves itself over.
##
##   bin/reactor_all 8443 cert.pem key.pem &
##   curl -k --http1.1 https://127.0.0.1:8443/hi
##   curl -k --http2   https://127.0.0.1:8443/hi
##   curl -k --http3   https://127.0.0.1:8443/hi     # curl built with HTTP/3
##
## Needs the QUIC glue shim on the loader path (quic/build.sh).

import std/[cmdline, strutils]
import serve
import serve/reactorall

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8443
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"

serveAllReactor(port, certFile, keyFile, handler)
