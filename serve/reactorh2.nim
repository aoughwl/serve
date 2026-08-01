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

proc handleH2Conn(r: Reactor; fd: cint) {.passive.} =
  ## Flat coroutine: drain queued frames → await more input → feed the session,
  ## until the session is idle (which includes "we just sent GOAWAY") or the
  ## peer goes away.
  var buf = default(array[ReadChunk, char])
  let slot = h2OpenSession(gH2Handler)
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
        r.awaitWriteAll(fd, chunk, n, wrote)
        if not wrote:
          failed = true
    # --- then wait for more input -------------------------------------------
    if failed or h2Idle(slot):
      alive = false
    else:
      var got = 0
      r.awaitRead(fd, addr buf[0], ReadChunk, got)
      if got <= 0:
        alive = false
      elif not h2Feed(slot, addr buf[0], got):
        alive = false
  h2CloseSession(slot)
  # Graceful close. `close()` on a socket whose receive queue still holds
  # unread bytes makes the kernel send RST, and the peer's last frames — the
  # PING it sent right after its GOAWAY, say — are exactly such bytes. So send
  # FIN first and read the rest away until the peer closes too, bounded so a
  # peer that keeps talking cannot pin the coroutine on its own data.
  discard shutdownTcpWrite(fd)
  var drained = 0
  var draining = true
  while draining and drained < MaxDrainBytes:
    var got = 0
    r.awaitRead(fd, addr buf[0], ReadChunk, got)
    if got <= 0:
      draining = false
    else:
      drained = drained + got
  r.unregister(fd)
  closeTcp(fd)

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
      r.spawn(delay(handleH2Conn(r, fd)))

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
  r.register(listenFd)
  r.spawn(delay(acceptLoopH2(r, listenFd)))
  r.run()

# ---------------------------------------------------------------------------
# the same server over TLS (ALPN "h2") — the path a browser actually takes
# ---------------------------------------------------------------------------

var gTlsCtx = TlsContext(handle: nil, mode: tlsClient, stateId: 0)

proc handleH2TlsConn(r: Reactor; fd: cint) {.passive.} =
  ## As `handleH2Conn`, but every I/O goes through the TLS layer, and the
  ## handshake itself is pumped asynchronously — the connection is a coroutine
  ## from its first byte, so a peer that stalls mid-handshake stalls only
  ## itself. The body is spelled out rather than shared with the plaintext
  ## version: the await primitives are templates (they must inline their own
  ## suspend points), so there is no transport object to abstract over here.
  var buf = default(array[ReadChunk, char])
  var sock = Socket(handle: fd)
  var tsock = wrapServer(gTlsCtx, sock)
  var ok = false
  r.awaitTlsHandshake(tsock, fd, ok)
  var slot = -1
  if ok and negotiatedAlpn(tsock) == "h2":
    slot = h2OpenSession(gH2Handler)
  var alive = slot >= 0
  while alive:
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
        r.awaitTlsWriteAll(tsock, fd, chunk, n, wrote)
        if not wrote:
          failed = true
    if failed or h2Idle(slot):
      alive = false
    else:
      var got = 0
      r.awaitTlsRead(tsock, fd, addr buf[0], ReadChunk, got)
      if got <= 0:
        alive = false
      elif not h2Feed(slot, addr buf[0], got):
        alive = false
  h2CloseSession(slot)
  # Same graceful close as the plaintext path, and for the same reason: closing
  # while the peer's last bytes sit unread makes the kernel answer them with
  # RST, which h2spec sees instead of the GOAWAY it was owed. close_notify
  # first, then FIN, then read the rest away (ciphertext, discarded).
  closeTls(tsock, false)
  discard shutdownTcpWrite(fd)
  var drained = 0
  var draining = true
  while draining and drained < MaxDrainBytes:
    var got = 0
    r.awaitRead(fd, addr buf[0], ReadChunk, got)
    if got <= 0:
      draining = false
    else:
      drained = drained + got
  r.unregister(fd)
  closeTcp(fd)

proc acceptLoopH2Tls(r: Reactor; listenFd: cint) {.passive.} =
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
      r.spawn(delay(handleH2TlsConn(r, fd)))

proc serveHttp2TlsReactor*(port: int; certFile: string; keyFile: string;
                           handler: H2Handler; idleTimeoutMs = IdleTimeoutMs) =
  ## Serve HTTP/2 over TLS on `port`, advertising ALPN "h2", on the reactor.
  ## This is the path browsers use (they do not speak h2c). A connection whose
  ## ALPN does not settle on "h2" is closed — this entry point is h2-only.
  ## Blocks, multiplexing every connection, handshakes included, on one thread.
  gH2Handler = handler
  gIdleMs = idleTimeoutMs
  var ctx = newTlsServerContext(certFile, keyFile)
  if not ctx.isValid:
    return
  discard ctx.setAlpnServer(@["h2"])
  gTlsCtx = ctx
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.register(listenFd)
  r.spawn(delay(acceptLoopH2Tls(r, listenFd)))
  r.run()
