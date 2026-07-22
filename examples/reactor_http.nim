## An async HTTP/1.1 server on the reactor: one thread, epoll-multiplexed.
## Build: nimony c (net-stack --path set)   Run: bin/reactor_http [port]

import std/[cmdline, strutils]
import serve/reactorhttp
import http/request
import http/response

proc handler(req: Request): Response {.nimcall.} =
  if req.path == "/hello":
    return response(200, "text/plain", "hello from the async reactor\n")
  if req.path == "/echo":
    return response(200, "text/plain", req.body)
  return response(404, "text/plain", "not found\n")

var port = 8140
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8140

serveHttpReactor(port, handler)
