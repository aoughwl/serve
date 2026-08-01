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
import ./reactor
import ./asyncio

export H3Request

type
  H3Response* = object
    status*: int
    ctype*: string
    body*: string
  H3Handler* = proc(meth, path, body: string): H3Response {.nimcall.}

proc response*(status: int; ctype, body: string): H3Response =
  H3Response(status: status, ctype: ctype, body: body)

var gH3Handler: nil H3Handler = nil
var gH3Srv: QuicCtx = cast[QuicCtx](0)

proc h3Loop(r: Reactor; fdc: cint) {.passive.} =
  ## The QUIC server as an ordinary reactor coroutine.
  ##
  ## QUIC has timers of its own — loss detection, idle, PTO — so this waits for
  ## "the socket is readable OR my next timer is due", which is exactly
  ## `awaitReadableFor`. Before that primitive existed this module ran a private
  ## epoll loop, which is why HTTP/3 could not share a thread with HTTP/1.1 or
  ## HTTP/2 even though all three are single-threaded by design.
  var running = true
  while running:
    var tmo = timeoutMs(gH3Srv)
    if tmo < 0 or tmo > 1000:
      tmo = 1000                       # cap so loss/idle timers still fire
    var expired = false
    r.awaitReadableFor(fdc, tmo, expired)
    if not expired:
      discard processRead(gH3Srv)
    discard handleTimeout(gH3Srv)
    var req = takeRequest(gH3Srv)
    while req.ok:
      let resp = gH3Handler(req.meth, req.path, req.body)
      respond(gH3Srv, req.id, resp.status, resp.ctype, resp.body)
      req = takeRequest(gH3Srv)
    discard flush(gH3Srv)

proc spawnH3*(r: Reactor; srv: QuicCtx; handler: H3Handler) =
  ## Attach an already-created QUIC server to `r`. Exposed so one process can
  ## run HTTP/3 next to the TCP servers on the SAME reactor and the same thread.
  gH3Srv = srv
  gH3Handler = handler
  let sfd = cint(fd(srv))
  r.registerListener(sfd)
  r.spawn(delay(h3Loop(r, sfd)))

proc serveH3Reactor*(port: int; certPath, keyPath: string; handler: H3Handler;
                     host = "127.0.0.1") =
  ## Serve HTTP/3 on `port` (UDP) with a single-thread epoll reactor. `certPath`
  ## / `keyPath` are PEM files (QUIC requires TLS 1.3). `handler` maps a request
  ## `(method, path)` to a response.
  let srv = quicServer(host, port, certPath, keyPath)
  if srv == nil:
    return
  let r = newReactor()
  r.stopOnSignals()
  r.spawnH3(srv, handler)
  r.run()

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
