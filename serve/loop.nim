## serve/loop.aowl — the accept/read/write event loop.
##
## Entry points, all on top of ONE connection core (`serveConnCore`) that reads
## a complete request, calls the handler, and streams the response:
##
##   * `serve(port, handler, maxRequests = 0)`    — PROGRAMMABLE plaintext server.
##   * `serve(root, port, maxRequests = 0)`       — static-file server (uses
##     `staticHandler`), on the same core.
##   * `serveTls(port, certFile, keyFile, handler, maxRequests = 0)` — HTTPS: the
##     same handler API, each accepted socket wrapped in a server-side TLS
##     session (`tls`, OpenSSL 3) before the request/response core runs.
##
## Transport independence: the request-read / response-write code operates on a
## `ServerConn` that is either a raw `TcpHandle` or a `TlsSocket`, so the HTTP
## logic (complete-request read with an 8 MB cap → 413, a 15 s slowloris read
## timeout, keep-alive, HEAD, streamed unbounded response bodies) is shared byte
## for byte between HTTP and HTTPS.
##
## nimony notes: closures need an explicit `.closure` pragma; string elements
## cannot be `addr`-ed, so response bytes are streamed through a stack chunk
## buffer rather than a pointer into the string.

import std/syncio
import http/headers
import http/request
import http/response
import tcp
import net
import tls
import static

const
  MaxRequestBytes* = 8 * 1024 * 1024   ## reject requests larger than this → 413
  ReadTimeoutMillis* = 15000           ## per-socket blocking read timeout (slowloris guard)
  ReadChunkBytes = 8192
  WriteChunkBytes = 65536
  MaxKeepAliveRequests* = 100          ## max requests served on one kept-alive connection

# --- runtime knobs and the stop signal ---------------------------------------
#
# `ReadTimeoutMillis` stays the DEFAULT rather than the law: a slowloris guard
# a deployment cannot move is not a guard, it is a guess.

var gReadTimeoutMs = ReadTimeoutMillis

proc setServeReadTimeout*(ms: int) =
  ## Per-socket read timeout for every subsequently served connection.
  ## `ms <= 0` disables it (and with it the slowloris guard).
  gReadTimeoutMs = ms

proc serveReadTimeout*(): int =
  gReadTimeoutMs

# The blocking servers sit in `accept()`, which no flag can interrupt — the
# listener has to be shut down under them. So the stop path is: set the flag,
# then shutdown the listening fd, which makes the pending accept return.
# `shutdown` is a bare syscall and safe from a signal handler.
type SigHandler = proc(sig: cint) {.cdecl.}
proc csignal(sig: cint; handler: SigHandler): nil pointer {.cdecl,
  importc: "signal", header: "<signal.h>".}
const
  SIGINT = 2.cint
  SIGTERM = 15.cint

var gServeStop = false
var gListenFds: seq[TcpHandle] = @[]

proc stopServing*() =
  ## Ask every running blocking server in this process to stop accepting and
  ## return once the connection in hand is finished.
  gServeStop = true
  for fd in gListenFds:
    discard shutdownTcpBoth(fd)

proc serveStopRequested*(): bool =
  gServeStop

proc registerServeListener*(fd: TcpHandle) =
  ## Track a listening socket so `stopServing` can shut it down under whatever
  ## is blocked in `accept` on it. The worker pool registers its shared listener
  ## this way.
  gListenFds.add fd

proc onServeSignal(sig: cint) {.cdecl.} =
  stopServing()

proc serveStopOnSignals*() =
  ## Make SIGINT/SIGTERM stop the blocking servers instead of killing them
  ## mid-response. Opt-in, unlike the reactor entry points, because a blocking
  ## server is often one part of a larger program that owns its own signals.
  discard csignal(SIGINT, onServeSignal)
  discard csignal(SIGTERM, onServeSignal)

type
  Handler* = proc(req: Request): Response {.closure.}
    ## A request handler: takes the parsed `Request`, returns the `Response` to
    ## send. Must be `.closure` so it can capture state (e.g. a root directory).

  NimcallHandler* = proc(req: Request): Response {.nimcall.}
    ## A handler as a plain function pointer (no captured environment). Used by
    ## the threaded worker pool: a bare `{.nimcall.}` proc crosses module and
    ## thread boundaries cleanly, where a closure stored in another module's
    ## global does not. Per-request state must come from thread-safe globals.

  ServerConn* = object
    ## The transport under one served connection: a plaintext `TcpHandle` or a
    ## `TlsSocket`. `fd` is always the underlying descriptor (also for TLS, so
    ## socket options like the read timeout apply to both).
    isTls*: bool
    fd*: TcpHandle
    tls*: TlsSocket

proc plainConn(fd: TcpHandle): ServerConn =
  ServerConn(isTls: false, fd: fd, tls: TlsSocket(socket: invalidSocket(), ssl: nil, handshakeDone: false))

proc connRead(c: var ServerConn; buf: pointer; n: int): int =
  ## Read up to `n` bytes; <=0 means EOF/error (matching `readTcp`).
  if c.isTls:
    var st = tlsOk
    return tlsReadInto(c.tls, buf, n, st)
  return readTcp(c.fd, buf, n)

proc connWriteAll(c: var ServerConn; buf: pointer; n: int): int =
  ## Write all `n` bytes; a short return signals a socket/TLS error.
  if not c.isTls:
    return writeAllTcp(c.fd, buf, n)
  var total = 0
  var st = tlsOk
  while total < n:
    let p = cast[pointer](cast[uint](buf) + uint(total))
    let w = tlsWriteFrom(c.tls, p, n - total, st)
    if w <= 0:
      break
    total = total + w
  return total

proc connSetReadTimeout(c: var ServerConn; millis: int) =
  discard setTcpReadTimeoutMillis(c.fd, millis)

proc connClose(c: var ServerConn) =
  if c.isTls:
    c.tls.closeTls()   # sends close_notify and closes the underlying socket
  else:
    closeTcp(c.fd)

proc writeStringConn(c: var ServerConn; s: string): bool =
  ## Stream an in-memory string to the connection in chunks. No size cap: this
  ## is what replaces the old fixed 1 MB response buffer. Returns false on a
  ## short write / socket error.
  var chunk = default(array[WriteChunkBytes, char])
  var i = 0
  while i < s.len:
    var n = 0
    while n < chunk.len and i < s.len:
      chunk[n] = s[i]
      inc n
      inc i
    if connWriteAll(c, addr chunk[0], n) != n:
      return false
  return true

proc parseNonNegInt(s: string; value: var int): bool =
  ## Parse a non-negative decimal integer; false on empty/overflow/garbage.
  if s.len == 0: return false
  var v = 0
  var i = 0
  while i < s.len:
    let c = s[i]
    if c < '0' or c > '9': return false
    let d = ord(c) - ord('0')
    if v > (0x7fffffff - d) div 10: return false   # guard against overflow
    v = v * 10 + d
    inc i
  value = v
  return true

proc headerTerminator(raw: string): int =
  ## Index just past the blank line ending the header block, or -1 if not seen.
  ## Accepts both CRLFCRLF and bare LFLF (tolerant, like `parseRequest`).
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
  ## Case-insensitive substring test (char-walk; no slicing).
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
  ## HTTP/1.1 defaults to keep-alive unless `Connection: close`; HTTP/1.0
  ## defaults to close unless `Connection: keep-alive`.
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
  ## Copy `s[a ..< b]` by char-walk (nimony string slices are `.raises`).
  result = ""
  var i = a
  while i < b and i < s.len:
    result.add s[i]
    inc i

proc chunkedComplete(s: string; start: int): bool =
  ## True once the `Transfer-Encoding: chunked` body beginning at `start`
  ## contains its terminating zero-size chunk in full. Conservatively returns
  ## false while any chunk (size line, data, or trailing CRLF) is still partial,
  ## so the caller keeps reading.
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
    inc i                      # consume the '\n' ending the size line
    if size == 0:
      return true              # terminating chunk (trailers ignored)
    if i + size > s.len:
      return false
    i = i + size
    if i < s.len and s[i] == '\r': inc i
    if i < s.len and s[i] == '\n':
      inc i
    else:
      return false             # data's trailing CRLF not fully arrived yet

proc readFullRequest(c: var ServerConn; raw: var string; tooLarge: var bool): bool =
  ## Accumulate a complete HTTP request: the header block, then the body framed
  ## by either `Content-Length` or `Transfer-Encoding: chunked`. Honors
  ## `Expect: 100-continue` (sends the interim 100 before reading the body). For
  ## a chunked request the body is de-chunked in place, so the handler always
  ## sees a plain body regardless of transfer encoding. Returns false on
  ## EOF/error/timeout before a full request, or `tooLarge` at the size cap.
  raw = ""
  tooLarge = false
  var buf = default(array[ReadChunkBytes, char])
  var headerEnd = -1
  var contentLen = 0
  var chunked = false
  var expectContinue = false
  var sentContinue = false
  while true:
    if headerEnd < 0:
      headerEnd = headerTerminator(raw)
      if headerEnd >= 0:
        let req = parseRequest(raw)
        if containsIgnoreCase(headerValue(req.headers, "Transfer-Encoding"), "chunked"):
          chunked = true
        else:
          let cl = headerValue(req.headers, "Content-Length")
          if cl.len > 0:
            var v = 0
            if parseNonNegInt(cl, v):
              contentLen = v
        if containsIgnoreCase(headerValue(req.headers, "Expect"), "100-continue"):
          expectContinue = true
    # A client that sent `Expect: 100-continue` waits for the interim response
    # before streaming its body; send it once, after the headers, before we
    # block waiting for body bytes.
    if headerEnd >= 0 and expectContinue and not sentContinue and (chunked or contentLen > 0):
      discard writeStringConn(c, "HTTP/1.1 100 Continue\r\n\r\n")
      sentContinue = true
    if headerEnd >= 0:
      if chunked:
        if chunkedComplete(raw, headerEnd):
          # Rebuild the request with the de-chunked body so the handler sees a
          # plain body (parseRequest treats everything after the headers as body).
          let header = subStr(raw, 0, headerEnd)
          let body = decodeChunked(subStr(raw, headerEnd, raw.len))
          raw = header & body
          return true
      elif raw.len >= headerEnd + contentLen:
        return true
    if raw.len >= MaxRequestBytes:
      tooLarge = true
      return false
    let n = connRead(c, addr buf[0], buf.len)
    if n <= 0:
      return false
    var k = 0
    while k < n:
      raw.add buf[k]
      inc k

proc sendResponse(c: var ServerConn; resp: Response; includeBody: bool): bool =
  ## Serialize the header block (Content-Length from the full body), then stream
  ## the body separately — avoids concatenating a second whole-response copy.
  if not writeStringConn(c, responseToString(resp, false)):
    return false
  if includeBody and resp.body.len > 0:
    if not writeStringConn(c, resp.body):
      return false
  return true

proc serveConnCore(c: var ServerConn; handler: Handler) =
  ## The shared request/response loop over any `ServerConn` (plain or TLS):
  ## read → handle → write, looping for HTTP keep-alive, then close.
  connSetReadTimeout(c, gReadTimeoutMs)
  var count = 0
  var alive = true
  while alive and count < MaxKeepAliveRequests:
    var raw = ""
    var tooLarge = false
    if not readFullRequest(c, raw, tooLarge):
      if tooLarge:
        var resp = response(413, "text/plain", "Payload Too Large\n")
        resp.withHeader("Connection", "close")
        discard sendResponse(c, resp, true)
      alive = false
    else:
      let req = parseRequest(raw)
      var resp = handler(req)
      let ka = keepAliveWanted(req) and (count + 1 < MaxKeepAliveRequests)
      if not hasHeader(resp.headers, "Connection"):
        if ka:
          resp.withHeader("Connection", "keep-alive")
        else:
          resp.withHeader("Connection", "close")
      let includeBody = not isMethod(req, "HEAD")
      if not sendResponse(c, resp, includeBody):
        alive = false
      else:
        inc count
        if not ka:
          alive = false
  connClose(c)

proc serveConnection*(fd: TcpHandle; handler: Handler) =
  ## Serve one accepted plaintext socket to completion. Exposed so tests/drivers
  ## can hand it a socket.
  var c = plainConn(fd)
  serveConnCore(c, handler)

proc serveConnCoreNimcall(c: var ServerConn; handler: NimcallHandler) =
  ## Identical to `serveConnCore` but drives a `{.nimcall.}` function-pointer
  ## handler. Duplicated rather than closure-wrapped: nimony's lambda lifter
  ## cannot lift a closure that captures a proc-typed variable, so the worker
  ## pool must call the bare function pointer directly.
  connSetReadTimeout(c, gReadTimeoutMs)
  var count = 0
  var alive = true
  while alive and count < MaxKeepAliveRequests:
    var raw = ""
    var tooLarge = false
    if not readFullRequest(c, raw, tooLarge):
      if tooLarge:
        var resp = response(413, "text/plain", "Payload Too Large\n")
        resp.withHeader("Connection", "close")
        discard sendResponse(c, resp, true)
      alive = false
    else:
      let req = parseRequest(raw)
      var resp = handler(req)
      let ka = keepAliveWanted(req) and (count + 1 < MaxKeepAliveRequests)
      if not hasHeader(resp.headers, "Connection"):
        if ka:
          resp.withHeader("Connection", "keep-alive")
        else:
          resp.withHeader("Connection", "close")
      let includeBody = not isMethod(req, "HEAD")
      if not sendResponse(c, resp, includeBody):
        alive = false
      else:
        inc count
        if not ka:
          alive = false
  connClose(c)

proc serveConnectionNimcall*(fd: TcpHandle; handler: NimcallHandler) =
  ## Serve one accepted plaintext socket with a `{.nimcall.}` handler — the
  ## thread-safe entry the worker pool uses.
  var c = plainConn(fd)
  serveConnCoreNimcall(c, handler)

proc serveConnectionTlsNimcall*(fd: TcpHandle; ctx: TlsContext; handler: NimcallHandler) =
  ## TLS variant of `serveConnectionNimcall`.
  var sock = Socket(handle: fd)
  var tsock = wrapServer(ctx, sock)
  if not tsock.handshakeDone:
    tsock.closeTls()
    return
  var c = ServerConn(isTls: true, fd: fd, tls: tsock)
  serveConnCoreNimcall(c, handler)

proc serveConnectionTls*(fd: TcpHandle; ctx: TlsContext; handler: Handler) =
  ## Wrap one accepted socket in a server-side TLS session, then serve it with
  ## the same core. Drops the connection silently if the handshake fails.
  var sock = Socket(handle: fd)
  var tsock = wrapServer(ctx, sock)
  if not tsock.handshakeDone:
    tsock.closeTls()   # closes the underlying fd too
    return
  var c = ServerConn(isTls: true, fd: fd, tls: tsock)
  serveConnCore(c, handler)

proc serve*(port: int; handler: Handler; maxRequests = 0) =
  ## Run a programmable plaintext server on `port`. Loops forever unless
  ## `maxRequests > 0`, in which case it exits after that many CONNECTIONS.
  initTcp()
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    shutdownTcp()
    return
  echo "serving on :", port, " (fd=", l, ")"
  gListenFds.add l
  var served = 0
  while (maxRequests == 0 or served < maxRequests) and not gServeStop:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      serveConnection(clientFd, handler)
      inc served
    elif not tcpErrorWouldRetry(lastTcpErrorCode()):
      # A hard accept error — the listener was shut down by `stopServing`, or
      # the fd is gone. Previously this branch did nothing, so the loop spun on
      # a dead listener at 100% CPU forever.
      break
  closeTcp(l)
  shutdownTcp()
  echo "served ", served, " connection(s); exiting"

proc serveTls*(port: int; ctx0: TlsContext; handler: Handler;
               maxRequests = 0) =
  ## Run a programmable HTTPS server on `port` with a context YOU built and
  ## configured — protocol versions, cipher suites, key-exchange groups
  ## (post-quantum included), ALPN, extra SNI certificates, session resumption.
  ## Each accepted connection gets its own TLS session over that shared context,
  ## then runs the same handler loop as `serve`.
  initTcp()
  var ctx = ctx0
  if not ctx.isValid:
    echo "invalid TLS context: ", lastTlsError()
    shutdownTcp()
    return
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    ctx.close()
    shutdownTcp()
    return
  echo "serving TLS on :", port, " (fd=", l, ")"
  gListenFds.add l
  var served = 0
  while (maxRequests == 0 or served < maxRequests) and not gServeStop:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      serveConnectionTls(clientFd, ctx, handler)
      inc served
    elif not tcpErrorWouldRetry(lastTcpErrorCode()):
      break
  ctx.close()
  closeTcp(l)
  shutdownTcp()
  echo "served ", served, " TLS connection(s); exiting"

proc serveTls*(port: int; certFile: string; keyFile: string; handler: Handler;
               maxRequests = 0) =
  ## As above, with a default context built from a PEM certificate chain and
  ## private key.
  serveTls(port, newTlsServerContext(certFile, keyFile), handler, maxRequests)

proc staticRoute*(root: string; req: Request): Response =
  ## Route one request against a static-file `root`: validate, handle
  ## OPTIONS/HEAD/GET, reject other methods, and map the path to a file
  ## (`..` rejection and MIME types live in `serve/static`). This is a plain
  ## top-level proc so it can be reused without nesting closures.
  if not isValidRequest(req):
    return response(400, "text/plain", "Bad Request\n")
  if isMethod(req, "OPTIONS"):
    var r = response(204, "text/plain", "")
    r.withHeader("Allow", "GET, HEAD, OPTIONS")
    return r
  if not (isMethod(req, "GET") or isMethod(req, "HEAD")):
    return response(405, "text/plain", "Method Not Allowed\n")
  return staticResponseObj(root, req.path)

proc staticHandler*(root: string): Handler =
  ## Build a handler that serves static files under `root`. This is how the
  ## classic `serve(root, port)` is expressed on top of the handler API.
  proc(req: Request): Response {.closure.} =
    staticRoute(root, req)

proc serve*(root: string; port: int; maxRequests = 0) =
  ## Serve static files under `root` on `port` (backwards-compatible API).
  ## Implemented on top of the handler loop via `staticHandler`.
  serve(port, staticHandler(root), maxRequests)
