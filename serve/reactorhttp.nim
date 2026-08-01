## serve/reactorhttp.nim — an async HTTP/1.1 server on the reactor.
##
## This is the async counterpart to `serve/loop.nim`'s blocking accept loop: one
## OS thread multiplexes many connections via epoll + passive-proc coroutines
## (see reactor.nim / asyncio.nim). Each connection is a flat coroutine that
## reads a full request (framed by Content-Length or chunked), runs the handler,
## writes the response, and loops for keep-alive — all suspending on socket
## readiness instead of blocking a thread.
##
## The handler is a module global (`{.nimcall.}` function pointer), matching the
## worker-pool's approach in pool.nim: it composes cleanly across the coroutine
## boundary where a captured closure would not. Control flow is flag-based (no
## `break`/`return` beside a `suspend`) to stay within the coroutine transform's
## supported shape — see REACTOR.md.

when defined(nimony):
  {.feature: "lenientnils".}

import std/strutils
import tcp
import tls
import ./reactor
import ./asyncio
import ./asyncconn
import http/request
import http/response
import http/headers

type
  ReactorHandler* = proc(req: Request): Response {.nimcall.}

const
  MaxRequestBytes* = 8 * 1024 * 1024   ## default whole-request cap -> 413
  MaxKeepAlive* = 1000                 ## default requests per kept-alive connection
  ReadChunk = 4096
  IdleTimeoutMs = 60_000   ## keep-alive idle limit, nginx's neighbourhood
  MaxDrainBytes = 64 * 1024

var gHandler: nil ReactorHandler = nil
var gIdleMs = IdleTimeoutMs
var gMaxRequestBytes = MaxRequestBytes
var gMaxKeepAlive = MaxKeepAlive

proc setReactorLimits*(maxRequestBytes = MaxRequestBytes; maxKeepAlive = MaxKeepAlive) =
  ## Resource bounds for subsequently accepted connections. Both were `const`,
  ## which meant a deployment could not raise a cap for a large upload nor lower
  ## one under memory pressure.
  gMaxRequestBytes = maxRequestBytes
  gMaxKeepAlive = maxKeepAlive

proc reactorLimits*(): tuple[maxRequestBytes: int, maxKeepAlive: int] =
  (gMaxRequestBytes, gMaxKeepAlive)
var gTlsCtx = TlsContext(handle: nil, mode: tlsClient, stateId: 0)

# ---------------------------------------------------------------------------
# framing helpers (mirrors serve/loop.nim; reimplemented so this module is
# self-contained and needs nothing private from loop.nim)
# ---------------------------------------------------------------------------

proc parseNonNegInt(s: string; value: var int): bool =
  if s.len == 0: return false
  var v = 0
  var i = 0
  while i < s.len:
    let c = s[i]
    if c < '0' or c > '9': return false
    let d = ord(c) - ord('0')
    if v > (0x7fffffff - d) div 10: return false
    v = v * 10 + d
    inc i
  value = v
  return true

proc headerTerminator(raw: string): int =
  var i = 0
  while i < raw.len:
    if i + 3 < raw.len and raw[i] == '\r' and raw[i+1] == '\n' and
       raw[i+2] == '\r' and raw[i+3] == '\n':
      return i + 4
    if i + 1 < raw.len and raw[i] == '\n' and raw[i+1] == '\n':
      return i + 2
    inc i
  return -1

proc asciiLowerCh(c: char): char =
  if c >= 'A' and c <= 'Z': chr(ord(c) + 32) else: c

proc containsIgnoreCase(hay, needle: string): bool =
  if needle.len == 0: return true
  if needle.len > hay.len: return false
  var i = 0
  while i + needle.len <= hay.len:
    var j = 0
    var ok = true
    while j < needle.len:
      if asciiLowerCh(hay[i + j]) != asciiLowerCh(needle[j]):
        ok = false
        break
      inc j
    if ok: return true
    inc i
  return false

proc keepAliveWanted(req: Request): bool =
  let conn = headerValue(req.headers, "Connection")
  if eqIgnoreCase(req.version, "HTTP/1.1"):
    return not containsIgnoreCase(conn, "close")
  return containsIgnoreCase(conn, "keep-alive")

proc hexDigit(c: char): int =
  if c >= '0' and c <= '9': ord(c) - ord('0')
  elif c >= 'a' and c <= 'f': ord(c) - ord('a') + 10
  elif c >= 'A' and c <= 'F': ord(c) - ord('A') + 10
  else: -1

proc subStr(s: string; a: int; b: int): string =
  result = ""
  var i = a
  while i < b and i < s.len:
    result.add s[i]
    inc i

proc chunkedComplete(s: string; start: int): bool =
  var i = start
  while true:
    var size = 0
    var any = false
    while i < s.len and hexDigit(s[i]) >= 0:
      size = size * 16 + hexDigit(s[i])
      any = true
      inc i
    if not any:
      return false
    while i < s.len and s[i] != '\n':
      inc i
    if i >= s.len:
      return false
    inc i
    if size == 0:
      return true
    if i + size > s.len:
      return false
    i = i + size
    if i < s.len and s[i] == '\r': inc i
    if i < s.len and s[i] == '\n':
      inc i
    else:
      return false

# ---------------------------------------------------------------------------
# the per-connection coroutine
# ---------------------------------------------------------------------------

proc setReactorHttpHandler*(handler: ReactorHandler; idleTimeoutMs = IdleTimeoutMs) =
  ## Install the HTTP/1.1 handler without starting a server. This exists for
  ## `reactorh2`'s ALPN dispatcher, which serves HTTP/1.1 connections from a
  ## listener it owns.
  gHandler = handler
  gIdleMs = idleTimeoutMs

proc handleHttpConn*(r: Reactor; c0: Conn) {.passive.} =
  ## Flat coroutine: keep-alive loop of read-request → handle → write-response.
  ## All loop exits are via flags (never break/return beside a suspend).
  ## Cleartext and TLS run the same body — see asyncconn.nim.
  var c = c0
  var buf = default(array[ReadChunk, char])
  var handshook = false
  r.awaitConnHandshake(c, handshook)
  var alive = handshook
  var count = 0
  while alive and count < gMaxKeepAlive:
    # --- read one full request into `raw` -----------------------------------
    var raw = ""
    var headerEnd = -1
    var contentLen = 0
    var chunked = false
    var complete = false
    var connErr = false
    while (not complete) and (not connErr):
      if headerEnd < 0:
        headerEnd = headerTerminator(raw)
        if headerEnd >= 0:
          let req0 = parseRequest(raw)
          if containsIgnoreCase(headerValue(req0.headers, "Transfer-Encoding"), "chunked"):
            chunked = true
          else:
            let cl = headerValue(req0.headers, "Content-Length")
            if cl.len > 0:
              var v = 0
              if parseNonNegInt(cl, v):
                contentLen = v
      if headerEnd >= 0:
        if chunked:
          if chunkedComplete(raw, headerEnd):
            complete = true
        else:
          if raw.len >= headerEnd + contentLen:
            complete = true
      if (not complete) and raw.len >= gMaxRequestBytes:
        connErr = true
      if (not complete) and (not connErr):
        var n = 0
        r.awaitConnRead(c, addr buf[0], ReadChunk, n)
        if n <= 0:
          connErr = true
        else:
          var k = 0
          while k < n:
            raw.add buf[k]
            inc k
    # --- handle + write -----------------------------------------------------
    if connErr:
      alive = false
    else:
      if chunked and headerEnd >= 0:
        let header = subStr(raw, 0, headerEnd)
        let body = decodeChunked(subStr(raw, headerEnd, raw.len))
        raw = header & body
      let req = parseRequest(raw)
      var resp = gHandler(req)
      let ka = keepAliveWanted(req) and (count + 1 < gMaxKeepAlive)
      if not hasHeader(resp.headers, "Connection"):
        if ka:
          resp.withHeader("Connection", "keep-alive")
        else:
          resp.withHeader("Connection", "close")
      let includeBody = not isMethod(req, "HEAD")
      let outStr = responseToString(resp, includeBody)
      # copy to an addressable seq (nimony string indexing is not addressable)
      var outBuf = newSeq[char](outStr.len)
      var w = 0
      while w < outStr.len:
        outBuf[w] = outStr[w]
        inc w
      var wrote = false
      if outBuf.len == 0:
        wrote = true
      else:
        r.awaitConnWriteAll(c, addr outBuf[0], outBuf.len, wrote)
      if not wrote:
        alive = false
      else:
        inc count
        if not ka:
          alive = false
  r.closeConn(c, addr buf[0], ReadChunk, MaxDrainBytes)

proc acceptLoopHttp(r: Reactor; listenFd: cint) {.passive.} =
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
      r.spawn(delay(handleHttpConn(r, plainConn(fd))))

proc acceptLoopHttps(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      discard setTcpNonBlocking(fd)   # BEFORE tlsConn: wrapServer starts the handshake
      r.register(fd)
      r.setIdleTimeout(fd, gIdleMs)
      r.spawn(delay(handleHttpConn(r, tlsConn(gTlsCtx, fd))))

proc serveHttpReactor*(port: int; handler: ReactorHandler;
                       idleTimeoutMs = IdleTimeoutMs) =
  ## Serve HTTP/1.1 on `port` with a single-threaded epoll reactor. Blocks,
  ## multiplexing all connections on this one thread. A connection that goes
  ## silent for `idleTimeoutMs` — mid-request or between keep-alive requests —
  ## is dropped; 0 disables that, which is what lets a slowloris peer hold a
  ## coroutine indefinitely.
  gHandler = handler
  gIdleMs = idleTimeoutMs
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.stopOnSignals()      # SIGINT/SIGTERM => graceful drain, not a killed response
  r.registerListener(listenFd)
  r.spawn(delay(acceptLoopHttp(r, listenFd)))
  r.run()

proc serveHttpsReactor*(port: int; ctx0: TlsContext; handler: ReactorHandler;
                        idleTimeoutMs = IdleTimeoutMs) =
  ## Serve HTTP/1.1 over TLS on `port` with the same reactor and the same
  ## connection coroutine — the transport is the only difference (asyncconn.nim).
  ## Handshakes are pumped asynchronously too, so one stalled handshake costs
  ## one coroutine, not the thread. ALPN advertises `http/1.1`.
  ##
  ## The context is the caller's, so every TLS knob stays reachable: protocol
  ## versions, cipher suites, key-exchange groups (post-quantum included), extra
  ## SNI certificates, session resumption.
  gHandler = handler
  gIdleMs = idleTimeoutMs
  var ctx = ctx0
  if not ctx.isValid:
    return
  discard ctx.setAlpnServer(@["http/1.1"])
  gTlsCtx = ctx
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.stopOnSignals()      # SIGINT/SIGTERM => graceful drain, not a killed response
  r.registerListener(listenFd)
  r.spawn(delay(acceptLoopHttps(r, listenFd)))
  r.run()

proc serveHttpsReactor*(port: int; certFile: string; keyFile: string;
                        handler: ReactorHandler;
                        idleTimeoutMs = IdleTimeoutMs) =
  ## As above, with a default context built from a PEM cert chain and key.
  serveHttpsReactor(port, newTlsServerContext(certFile, keyFile), handler,
                    idleTimeoutMs)
