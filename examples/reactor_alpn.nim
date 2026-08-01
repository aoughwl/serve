## What a real HTTPS port looks like: one TLS listener advertising both `h2` and
## `http/1.1`, serving each connection with whichever the client picked, from
## one handler, on one thread.
##
##   bin/reactor_alpn 8443 cert.pem key.pem &
##   curl -k --http2 https://127.0.0.1:8443/hi      # -> HTTP/2
##   curl -k --http1.1 https://127.0.0.1:8443/hi    # -> HTTP/1.1

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

serveHttpsAlpnReactor(port, certFile, keyFile, handler)
