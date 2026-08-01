## serve/reactorh2.nim — an async HTTP/2 (h2c) server on the reactor.
##
## The blocking driver in `serve/http2.nim` serves ONE connection at a time: its
## accept loop runs a whole session to completion before accepting again, so a
## single peer that opens a connection and keeps it open wedges the listener for
## everyone else. That is not a protocol gap — the nghttp2 session answers
## PING, SETTINGS and protocol violations correctly — it is a concurrency gap,
## and it is what made h2spec time out on 51 of 146 cases that each pass when
## their section is run alone.
##
## This module multiplexes connections on the single reactor thread instead:
## every connection is a flat coroutine that drains the session's queued output,
## then suspends on socket readiness for more input. nghttp2 never touches the
## socket, so the split is clean — `h2NextOut` / `h2Feed` are the only seam.
##
## Same shape rules as the other reactor servers: the handler is a module global
## `{.nimcall.}` function pointer, and loop exits go through flags, never a
## `break`/`return` sharing a branch with a `suspend`. See REACTOR.md.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp
import net
import tls
import ./reactor
import ./asyncio
import ./asynctls
import ./asyncconn
import ./reactorhttp
import ./http2
import http/request
import http/response

export H2Handler

const
  ReadChunk = 16384
  MaxDrainBytes = 64 * 1024   ## cap on post-FIN bytes read and discarded
  IdleTimeoutMs = 60_000      ## a connection that says nothing for this long goes

proc unsetH2Handler(req: Request): Response {.nimcall.} =
  ## Stand-in so the global is never nil: a coroutine cannot carry the nil check
  ## across its suspend points, so the handler slot is non-nilable by
  ## construction rather than tested at use.
  response(500, "text/plain", "no handler installed\n")

var gH2Handler: H2Handler = unsetH2Handler
var gIdleMs = IdleTimeoutMs

proc handleH2Conn*(r: Reactor; c0: Conn) {.passive.} =
  ## Flat coroutine: drain queued frames → await more input → feed the session,
  ## until the session is idle (which includes "we just sent GOAWAY") or the
  ## peer goes away. Cleartext and TLS run this same body (asyncconn.nim); a
  ## TLS `Conn` whose handshake is already done simply completes it instantly.
  var c = c0
  var buf = default(array[ReadChunk, char])
  var handshook = false
  r.awaitConnHandshake(c, handshook)
  var slot = -1
  if handshook:
    slot = h2OpenSession(gH2Handler)
  var alive = slot >= 0
  while alive:
    # --- drain everything nghttp2 has queued --------------------------------
    var failed = false
    var pending = true
    while pending and (not failed):
      var chunk = cast[pointer](0)
      var n = 0
      if not h2NextOut(slot, chunk, n):
        failed = true
      elif n == 0:
        pending = false
      else:
        var wrote = false
        r.awaitConnWriteAll(c, chunk, n, wrote)
        if not wrote:
          failed = true
    # --- then wait for more input -------------------------------------------
    if failed or h2Idle(slot):
      alive = false
    else:
      var got = 0
      r.awaitConnRead(c, addr buf[0], ReadChunk, got)
      if got <= 0:
        alive = false
      elif not h2Feed(slot, addr buf[0], got):
        alive = false
  h2CloseSession(slot)
  # Graceful close: close_notify (TLS), FIN, then read away whatever the peer
  # had already sent. A bare close() with unread bytes queued — the PING it sent
  # right after its GOAWAY, say — makes the kernel answer with RST instead.
  r.closeConn(c, addr buf[0], ReadChunk, MaxDrainBytes)

proc acceptLoopH2(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      discard setTcpNonBlocking(fd)
      r.register(fd)
      r.setIdleTimeout(fd, gIdleMs)
      r.spawn(delay(handleH2Conn(r, plainConn(fd))))

proc serveHttp2Reactor*(port: int; handler: H2Handler;
                        idleTimeoutMs = IdleTimeoutMs) =
  ## Serve h2c (HTTP/2 cleartext, prior knowledge) on `port` with a
  ## single-threaded epoll reactor, multiplexing up to `MaxH2Conns` connections.
  ## A connection idle for `idleTimeoutMs` is dropped (0 disables that, which
  ## lets one silent peer hold a session slot forever). Blocks. Test with
  ## `curl --http2-prior-knowledge http://host:port/`.
  gH2Handler = handler
  gIdleMs = idleTimeoutMs
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.stopOnSignals()      # SIGINT/SIGTERM => graceful drain, not a killed response
  r.registerListener(listenFd)
  r.spawn(delay(acceptLoopH2(r, listenFd)))
  r.run()

# ---------------------------------------------------------------------------
# over TLS, dispatching on ALPN — the path a browser actually takes
# ---------------------------------------------------------------------------

var gTlsCtx = TlsContext(handle: nil, mode: tlsClient, stateId: 0)
var gAlpnH2Only = false

proc dispatchTlsConn(r: Reactor; fd: cint) {.passive.} =
  ## Run the TLS handshake, then hand the connection to the coroutine for
  ## whichever protocol ALPN settled on, and finish.
  ##
  ## The handshake happens HERE rather than in the accept loop: the accept loop
  ## suspending on one peer's handshake would stop every other peer from being
  ## accepted. And the protocol body is `spawn`ed rather than called, because a
  ## coroutine that calls another suspending coroutine corrupts its frame (see
  ## REACTOR.md) — spawning drives the new one to its first park and returns.
  var c = tlsConn(gTlsCtx, fd)
  var ok = false
  r.awaitConnHandshake(c, ok)
  if not ok:
    r.unregister(fd)
    closeTls(c.tls)
  elif negotiatedAlpn(c.tls) == "h2":
    r.spawn(delay(handleH2Conn(r, c)))
  elif gAlpnH2Only:
    r.unregister(fd)
    closeTls(c.tls)
  else:
    r.spawn(delay(handleHttpConn(r, c)))

proc acceptLoopTlsAlpn(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      # Non-blocking BEFORE wrapping: wrapServer starts the handshake, and on a
      # blocking fd it would run the whole thing right here, on the reactor
      # thread, stalling every other connection.
      discard setTcpNonBlocking(fd)
      r.register(fd)
      r.setIdleTimeout(fd, gIdleMs)
      r.spawn(delay(dispatchTlsConn(r, fd)))

proc serveTlsAlpn(port: int; ctx0: TlsContext; alpn: seq[string];
                  idleTimeoutMs: int): bool =
  ## Shared driver for the TLS entry points below. Returns false if the context
  ## or the listener could not be brought up; otherwise it blocks.
  ##
  ## ALPN is set here rather than left to the caller: the dispatcher's choice of
  ## protocol *is* the ALPN result, so a caller-supplied list that disagreed
  ## with the entry point would silently mean something else.
  var ctx = ctx0
  if not ctx.isValid:
    return false
  gIdleMs = idleTimeoutMs
  discard ctx.setAlpnServer(alpn)
  gTlsCtx = ctx
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return false
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.stopOnSignals()      # SIGINT/SIGTERM => graceful drain, not a killed response
  r.registerListener(listenFd)
  r.spawn(delay(acceptLoopTlsAlpn(r, listenFd)))
  r.run()
  return true

proc serveHttp2TlsReactor*(port: int; ctx: TlsContext; handler: H2Handler;
                           idleTimeoutMs = IdleTimeoutMs) =
  ## Serve HTTP/2 over TLS on `port` with a context YOU built and configured —
  ## protocol versions, cipher suites, key-exchange groups (including the
  ## post-quantum ones), extra SNI certificates, session resumption. Advertises
  ## ALPN "h2" only; a connection that does not settle on "h2" is closed.
  gH2Handler = handler
  gAlpnH2Only = true
  discard serveTlsAlpn(port, ctx, @["h2"], idleTimeoutMs)

proc serveHttp2TlsReactor*(port: int; certFile: string; keyFile: string;
                           handler: H2Handler; idleTimeoutMs = IdleTimeoutMs) =
  ## As above, with a default context built from a PEM cert chain and key.
  serveHttp2TlsReactor(port, newTlsServerContext(certFile, keyFile), handler,
                       idleTimeoutMs)

proc serveHttpsAlpnReactor*(port: int; ctx: TlsContext; handler: H2Handler;
                            idleTimeoutMs = IdleTimeoutMs) =
  ## What a real HTTPS port does: advertise both `h2` and `http/1.1`, then serve
  ## each connection with whichever the client chose — HTTP/2 for a modern
  ## browser or curl, HTTP/1.1 for anything older — from the same handler, on
  ## the one thread. Takes a context you configured.
  ##
  ## `H2Handler` and `ReactorHandler` are the same shape
  ## (`proc(req: Request): Response {.nimcall.}`), so one handler covers both
  ## protocols; the HTTP/1.1 side is `reactorhttp`'s connection body.
  gH2Handler = handler
  gAlpnH2Only = false
  setReactorHttpHandler(handler, idleTimeoutMs)
  discard serveTlsAlpn(port, ctx, @["h2", "http/1.1"], idleTimeoutMs)

proc serveHttpsAlpnReactor*(port: int; certFile: string; keyFile: string;
                            handler: H2Handler; idleTimeoutMs = IdleTimeoutMs) =
  ## As above, with a default context built from a PEM cert chain and key.
  serveHttpsAlpnReactor(port, newTlsServerContext(certFile, keyFile), handler,
                        idleTimeoutMs)
