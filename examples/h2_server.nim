## A plain h2c (prior-knowledge HTTP/2) server, for conformance testing.
##
## Until now the only HTTP/2 coverage was two curl smoke tests — "curl got a
## 200 back" says nothing about frame handling, flow control, HPACK edge cases,
## or error codes. This binary exists so h2spec can drive the real thing:
##
##   bin/h2_server 8090 &
##   h2spec -h 127.0.0.1 -p 8090
##
## `maxRequests = 0` means serve forever; the caller kills it.

import std/[cmdline, strutils]
import serve
import serve/http2

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8090
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8090

serveHttp2(port, handler, 0)
