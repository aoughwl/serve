## serve/loop.aowl — the accept/read/write event loop.
##
## Two public entry points, both on top of ONE connection loop:
##
##   * `serve(port, handler, maxRequests = 0)` — PROGRAMMABLE server. `handler`
##     is a `proc(req: Request): Response {.closure.}` called once per request;
##     whatever `Response` it returns is streamed back to the client.
##   * `serve(root, port, maxRequests = 0)`    — the original static-file server,
##     implemented in terms of the handler API via `staticHandler(root)`.
##
## The connection loop:
##   1. reads a COMPLETE request (headers up to CRLFCRLF, then the body per
##      `Content-Length`), guarded by an 8 MB cap (→ 413) and a 15 s read
##      timeout (slowloris guard);
##   2. calls the handler;
##   3. streams the response header, then the body in chunks straight through
##      `writeAllTcp` (NO fixed response-size cap, so large bodies are not
##      truncated and `Content-Length` always matches the bytes written);
##   4. for HTTP/1.1 (or HTTP/1.0 + `Connection: keep-alive`) keeps the socket
##      open and serves the next request, up to `MaxKeepAliveRequests`.
##
## nimony notes: closures need an explicit `.closure` pragma; string elements
## cannot be `addr`-ed, so response bytes are streamed through a stack chunk
## buffer rather than a pointer into the string.

import std/syncio
import http/headers
import http/request
import http/response
import tcp
import static

const
  MaxRequestBytes* = 8 * 1024 * 1024   ## reject requests larger than this → 413
  ReadTimeoutMillis* = 15000           ## per-socket blocking read timeout (slowloris guard)
  ReadChunkBytes = 8192
  WriteChunkBytes = 65536
  MaxKeepAliveRequests* = 100          ## max requests served on one kept-alive connection

type
  Handler* = proc(req: Request): Response {.closure.}
    ## A request handler: takes the parsed `Request`, returns the `Response` to
    ## send. Must be `.closure` so it can capture state (e.g. a root directory).

proc writeStringTcp(fd: TcpHandle; s: string): bool =
  ## Stream an in-memory string to the socket in chunks. No size cap: this is
  ## what replaces the old fixed 1 MB response buffer. Returns false on a short
  ## write / socket error.
  var chunk = default(array[WriteChunkBytes, char])
  var i = 0
  while i < s.len:
    var n = 0
    while n < chunk.len and i < s.len:
      chunk[n] = s[i]
      inc n
      inc i
    if writeAllTcp(fd, addr chunk[0], n) != n:
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

proc readFullRequest(fd: TcpHandle; raw: var string; tooLarge: var bool): bool =
  ## Accumulate a complete HTTP request: header block, then `Content-Length`
  ## body bytes. Returns false on EOF/error/timeout before a full request, or
  ## when the size cap is hit (with `tooLarge = true`).
  raw = ""
  tooLarge = false
  var buf = default(array[ReadChunkBytes, char])
  var headerEnd = -1
  var contentLen = 0
  while true:
    if headerEnd < 0:
      headerEnd = headerTerminator(raw)
      if headerEnd >= 0:
        let req = parseRequest(raw)
        let cl = headerValue(req.headers, "Content-Length")
        if cl.len > 0:
          var v = 0
          if parseNonNegInt(cl, v):
            contentLen = v
    if headerEnd >= 0 and raw.len >= headerEnd + contentLen:
      return true
    if raw.len >= MaxRequestBytes:
      tooLarge = true
      return false
    let n = readTcp(fd, addr buf[0], buf.len)
    if n <= 0:
      return false
    var k = 0
    while k < n:
      raw.add buf[k]
      inc k

proc sendResponse(fd: TcpHandle; resp: Response; includeBody: bool): bool =
  ## Serialize the header block (Content-Length from the full body), then stream
  ## the body separately — avoids concatenating a second whole-response copy.
  if not writeStringTcp(fd, responseToString(resp, false)):
    return false
  if includeBody and resp.body.len > 0:
    if not writeStringTcp(fd, resp.body):
      return false
  return true

proc serveConnection*(fd: TcpHandle; handler: Handler) =
  ## Serve one accepted socket to completion: read → handle → write, looping for
  ## HTTP keep-alive, then close. Exposed so tests/drivers can hand it a socket.
  discard setTcpReadTimeoutMillis(fd, ReadTimeoutMillis)
  var count = 0
  var alive = true
  while alive and count < MaxKeepAliveRequests:
    var raw = ""
    var tooLarge = false
    if not readFullRequest(fd, raw, tooLarge):
      if tooLarge:
        var resp = response(413, "text/plain", "Payload Too Large\n")
        resp.withHeader("Connection", "close")
        discard sendResponse(fd, resp, true)
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
      if not sendResponse(fd, resp, includeBody):
        alive = false
      else:
        inc count
        if not ka:
          alive = false
  closeTcp(fd)

proc serve*(port: int; handler: Handler; maxRequests = 0) =
  ## Run a programmable server on `port`: every request is passed to `handler`
  ## and its returned `Response` is sent back. Loops forever unless
  ## `maxRequests > 0`, in which case it exits after that many CONNECTIONS.
  initTcp()
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    shutdownTcp()
    return
  echo "serving on :", port, " (fd=", l, ")"
  var served = 0
  while maxRequests == 0 or served < maxRequests:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      serveConnection(clientFd, handler)
      inc served
  closeTcp(l)
  shutdownTcp()
  echo "served ", served, " connection(s); exiting"

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
