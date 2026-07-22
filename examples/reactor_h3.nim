## An HTTP/3 (QUIC) server on the reactor: one thread, epoll-multiplexed over a
## single UDP socket. Build the shim first (quic/build.sh), then:
##   nimony c --path:<serve> --path:<tcp> examples/reactor_h3.nim
##   LD_LIBRARY_PATH=<serve>/quic bin/reactor_h3 8443 cert.pem key.pem

import std/[cmdline, strutils]
import serve/reactorh3

proc handle(meth, path: string): H3Response {.nimcall.} =
  response(200, "text/plain",
           "hello from aoughwl HTTP/3: " & meth & " " & path & "\n")

var port = 8443
var cert = "cert.pem"
var key = "key.pem"
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
if paramCount() >= 2: cert = paramStr(2)
if paramCount() >= 3: key = paramStr(3)

serveH3Reactor(port, cert, key, handle)
