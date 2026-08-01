## An async HTTP/1.1-over-TLS server on the reactor: one thread, epoll
## multiplexed, TLS handshakes pumped as ordinary async I/O.
## Run: bin/reactor_https [port] [cert.pem] [key.pem]

import std/[cmdline, strutils]
import serve/reactorhttp
import http/request
import http/response

proc handler(req: Request): Response {.nimcall.} =
  if req.path == "/hello":
    return response(200, "text/plain", "hello from the async reactor over TLS\n")
  if req.path == "/echo":
    return response(200, "text/plain", req.body)
  return response(404, "text/plain", "not found\n")

var port = 8441
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8441
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"

serveHttpsReactor(port, certFile, keyFile, handler)
