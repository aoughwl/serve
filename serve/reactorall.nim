## serve/reactorall.nim — HTTP/1.1, HTTP/2 and HTTP/3 from one handler, on one
## reactor, on one OS thread.
##
## Each of those servers already existed; what did not was a way to run them
## *together*. HTTP/3 in particular used to own a private epoll loop, so a
## process could serve QUIC or TCP but not both without threads. Two additions
## fixed that: the reactor's resume-deadline timers (QUIC has loss/idle/PTO
## timers it must service whether or not a packet arrives — `awaitReadableFor`),
## and `spawnH3`, which attaches an existing QUIC server to a reactor someone
## else owns.
##
## What a caller gets:
##
##   * TCP `port`, TLS, ALPN advertising `h2` and `http/1.1`, each connection
##     served with whichever the client picked;
##   * UDP `port`, HTTP/3 over QUIC, same certificate;
##   * an `Alt-Svc: h3=":<port>"` header on every TCP response, which is how a
##     browser learns HTTP/3 is available at all and moves itself over;
##   * one handler — `proc(req: Request): Response {.nimcall.}` — behind all
##     three, since HTTP/3's `(method, path, body)` shape is adapted here rather
##     than pushed onto the caller.

when defined(nimony):
  {.feature: "lenientnils".}

import std/strutils
import tcp
import tls
import ./reactor
import ./reactorh2
import ./reactorhttp
# selective: reactorh3 also exports a `response` builder, which would make
# every `response(...)` here ambiguous with http/response's
from ./reactorh3 import spawnH3, H3Response, H3Handler
import ./http2
import http/request
import http/response
import http/headers
import quic/quic

export H2Handler

proc unsetAllHandler(req: Request): Response {.nimcall.} =
  response(500, "text/plain", "no handler installed\n")

var gAllHandler: H2Handler = unsetAllHandler
var gAltSvc = ""

proc altSvcHandler(req: Request): Response {.nimcall.} =
  ## The TCP-side handler: run the caller's, then advertise HTTP/3. Without
  ## Alt-Svc a browser never tries QUIC, however well the UDP side works.
  result = gAllHandler(req)
  if gAltSvc.len > 0 and not hasHeader(result.headers, "Alt-Svc"):
    result.withHeader("Alt-Svc", gAltSvc)

proc h3Adapter(meth, path, body: string): H3Response {.nimcall.} =
  ## HTTP/3 hands over `(method, path, body)`; the handler wants a `Request`.
  ## Rendering those into a request line and parsing it keeps ONE handler shape
  ## across all three protocols, and reuses the parser the other two already
  ## trust rather than a second, subtly different construction path.
  var raw = meth & " " & path & " HTTP/1.1\r\nHost: h3\r\n"
  raw.add "Content-Length: " & $body.len & "\r\n\r\n"
  raw.add body
  let resp = gAllHandler(parseRequest(raw))
  var ctype = headerValue(resp.headers, "Content-Type")
  if ctype.len == 0:
    ctype = "application/octet-stream"
  H3Response(status: resp.status, ctype: ctype, body: resp.body)

proc serveAllReactor*(port: int; certFile: string; keyFile: string;
                      handler: H2Handler; host = "127.0.0.1";
                      idleTimeoutMs = 60_000) =
  ## Serve HTTP/1.1 + HTTP/2 over TLS (TCP `port`) and HTTP/3 over QUIC (UDP
  ## `port`) from `handler`, multiplexed on this one thread. Blocks; SIGINT or
  ## SIGTERM drains and returns.
  ##
  ## Requires the QUIC glue shim (`quic/build.sh` → `libaowlquic.so` on the
  ## loader path). If the QUIC side cannot start, the TCP side still does — a
  ## missing HTTP/3 is a degraded server, not a dead one, and it is reported
  ## through `http3Enabled`.
  gAllHandler = handler
  gAltSvc = "h3=\":" & $port & "\"; ma=86400"

  let ctx = newTlsServerContext(certFile, keyFile)
  if not ctx.isValid:
    return
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)

  let r = newReactor()
  r.stopOnSignals()
  r.registerListener(listenFd)
  spawnTlsAlpn(r, listenFd, ctx, altSvcHandler, @["h2", "http/1.1"], idleTimeoutMs)

  let qsrv = quicServer(host, port, certFile, keyFile)
  if qsrv != nil:
    r.spawnH3(qsrv, h3Adapter)
  r.run()
