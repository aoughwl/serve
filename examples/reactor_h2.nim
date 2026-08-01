## An async h2c (prior-knowledge HTTP/2) server on the reactor — the concurrent
## counterpart to `h2_server.nim`, and what the h2spec gate drives.
##
##   bin/reactor_h2 8090 &
##   h2spec -h 127.0.0.1 -p 8090
##
## Unlike the blocking `serveHttp2`, one connection sitting idle does not stop
## the next from being accepted: all of them are multiplexed on this one thread.

import std/[cmdline, strutils]
import serve
import serve/reactorh2

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8090
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8090

serveHttp2Reactor(port, handler)
