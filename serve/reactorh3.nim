## serve/reactorh3.nim — an async HTTP/3 (QUIC) server on the reactor model.
##
## Single thread, epoll-driven, exactly like the HTTP/1.1 and WebSocket reactor
## servers — but the transport is QUIC over UDP. All the QUIC/TLS/HTTP-3 protocol
## work lives in the ngtcp2/nghttp3/GnuTLS glue shim (quic/quic.nim → libaowlquic);
## here we own only the epoll wait on the single UDP socket, feeding readiness and
## QUIC timer expiries into the shim and relaying requests to the handler.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp/epoll as ep
import quic/quic

export H3Request

type
  H3Response* = object
    status*: int
    ctype*: string
    body*: string
  H3Handler* = proc(meth, path, body: string): H3Response {.nimcall.}

proc response*(status: int; ctype, body: string): H3Response =
  H3Response(status: status, ctype: ctype, body: body)

proc serveH3Reactor*(port: int; certPath, keyPath: string; handler: H3Handler;
                     host = "127.0.0.1") =
  ## Serve HTTP/3 on `port` (UDP) with a single-thread epoll reactor. `certPath`
  ## / `keyPath` are PEM files (QUIC requires TLS 1.3). `handler` maps a request
  ## `(method, path)` to a response.
  let srv = quicServer(host, port, certPath, keyPath)
  if srv == nil:
    return
  let sfd = fd(srv)
  let epfd = ep.epollCreate()
  ep.epollAdd(epfd, cint(sfd), ep.EPOLLIN)
  var evs = ep.newEventBuf(64)
  var running = true
  while running:
    var tmo = timeoutMs(srv)
    if tmo < 0 or tmo > 1000:
      tmo = 1000                       # cap so QUIC loss/idle timers still fire
    let n = ep.epollWait(epfd, evs, cint(tmo))
    var i = 0
    while i < n:
      if ep.eventFd(evs, i) == cint(sfd):
        discard processRead(srv)
      inc i
    discard handleTimeout(srv)
    var req = takeRequest(srv)
    while req.ok:
      let r = handler(req.meth, req.path, req.body)
      respond(srv, req.id, r.status, r.ctype, r.body)
      req = takeRequest(srv)
    discard flush(srv)

proc h3Fetch*(host: string; port: int; authority, path: string;
              postBody = ""; maxIters = 200000): tuple[status: int, body: string] =
  ## Drive a single HTTP/3 request to completion on its own epoll loop and return
  ## the status + body. GET when `postBody` is empty, POST otherwise. A
  ## self-contained client for tests and simple fetches.
  result = (0, "")
  let cli = quicClient(host, port, authority, path)
  if cli == nil:
    return
  if postBody.len > 0:
    clientPost(cli, postBody)
  discard clientStart(cli)
  let cfd = fd(cli)
  let epfd = ep.epollCreate()
  ep.epollAdd(epfd, cint(cfd), ep.EPOLLIN)
  var evs = ep.newEventBuf(8)
  var iter = 0
  var done = false
  while (iter < maxIters) and (not done):
    var tmo = timeoutMs(cli)
    if tmo < 0 or tmo > 200:
      tmo = 200
    let n = ep.epollWait(epfd, evs, cint(tmo))
    var i = 0
    while i < n:
      if ep.eventFd(evs, i) == cint(cfd):
        discard processRead(cli)
      inc i
    discard handleTimeout(cli)
    discard flush(cli)
    if clientDone(cli):
      result = (clientStatus(cli), clientBody(cli))
      done = true
    inc iter
  freeCtx(cli)

proc h3Get*(host: string; port: int; authority, path: string;
            maxIters = 200000): tuple[status: int, body: string] =
  ## Convenience: an HTTP/3 GET.
  h3Fetch(host, port, authority, path, "", maxIters)

proc h3Post*(host: string; port: int; authority, path, body: string;
             maxIters = 200000): tuple[status: int, body: string] =
  ## Convenience: an HTTP/3 POST with `body`.
  h3Fetch(host, port, authority, path, body, maxIters)
