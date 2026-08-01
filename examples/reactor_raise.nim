## What a failing handler actually does to this server.
##
## Note what is NOT here: a handler that raises. `Handler` carries no `.raises`,
## so nimony rejects `raise` inside one at COMPILE time — the whole class of
## "one bad request takes the process down via an uncaught exception" is
## excluded by the type system rather than by a try/except in the loop.
##
## What remains is a DEFECT — an index error, a nil dereference — which is not
## an exception and not catchable. `/boom` commits one, so the consequence is
## measured rather than assumed.
##
##   bin/reactor_raise 8210 &
##   curl -s http://127.0.0.1:8210/boom
##   curl -s http://127.0.0.1:8210/hello

import std/[cmdline, strutils]
import serve/reactorhttp
import http/request
import http/response

proc handler(req: Request): Response {.nimcall.} =
  if req.path == "/boom":
    # An out-of-bounds read: a defect, not an exception.
    var xs = @[1, 2, 3]
    var i = req.path.len * 1000
    return response(200, "text/plain", $xs[i] & "\n")
  if req.path == "/hello":
    return response(200, "text/plain", "still here\n")
  response(404, "text/plain", "not found\n")

var port = 8210
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8210

serveHttpReactor(port, handler)
