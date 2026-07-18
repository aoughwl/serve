## tserve_router.aowl — end-to-end test for the opt-in routing + middleware
## layer (`serve/router`).
##
## Runs the REAL server loop (`serveConnection`, same path `serve` uses) on a
## background thread, driving a blocking loopback client on the main thread.
##
## Assertions:
##   * a `:id` path param is captured and readable via `param(req, "id")`;
##   * a trailing `*` wildcard captures the remainder of the path;
##   * a middleware (registered with `use`) wraps the handler and its header is
##     present on the response (and also on 404/405 responses);
##   * an unknown path returns 404;
##   * a known path with the wrong method returns 405 with an `Allow` header
##     listing the registered method(s).

import std/syncio
import std/strutils
import std/rawthreads
import serve
import serve/router

var gListen = InvalidTcpHandle
var gHandler: NimcallHandler
var gMax = 0

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc serverThread(arg: pointer) {.nimcall.} =
  discard arg
  var served = 0
  while served < gMax:
    let fd = acceptTcp(gListen)
    if fd != InvalidTcpHandle:
      serveConnectionNimcall(fd, gHandler)
      inc served

# --- route handlers --------------------------------------------------------

proc getUser(req: Request): Response {.nimcall.} =
  ## Echoes the captured :id param so the client can assert extraction worked.
  response(200, "text/plain", "user=" & param(req, "id") & "\n")

proc getAsset(req: Request): Response {.nimcall.} =
  ## Echoes the wildcard remainder captured by "/static/*".
  response(200, "text/plain", "asset=" & wildcard(req) & "\n")

proc createUser(req: Request): Response {.nimcall.} =
  response(201, "text/plain", "created\n")

# --- middleware: stamp a header onto every response ------------------------

proc stampMw(req: Request; nxt: Chain): Response {.nimcall.} =
  var resp = proceed(nxt, req)
  resp.withHeader("X-Middleware", "on")
  return resp

# --- client plumbing (same style as tserve_e2e) ----------------------------

proc writeAll(fd: TcpHandle; s: string): bool =
  var chunk = default(array[4096, char])
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

proc readAll(fd: TcpHandle): string =
  result = ""
  var buf = default(array[4096, char])
  while true:
    let n = readTcp(fd, addr buf[0], buf.len)
    if n <= 0:
      break
    var i = 0
    while i < n:
      result.add buf[i]
      inc i

proc statusOf(resp: string): int =
  var i = 0
  while i < resp.len and resp[i] != ' ':
    inc i
  while i < resp.len and resp[i] == ' ':
    inc i
  var code = 0
  var any = false
  while i < resp.len and resp[i] >= '0' and resp[i] <= '9':
    code = code * 10 + (ord(resp[i]) - ord('0'))
    any = true
    inc i
  if not any: return -1
  return code

proc bodyOf(resp: string): string =
  var i = 0
  while i + 3 < resp.len:
    if resp[i] == '\r' and resp[i+1] == '\n' and resp[i+2] == '\r' and resp[i+3] == '\n':
      var j = i + 4
      result = ""
      while j < resp.len:
        result.add resp[j]
        inc j
      return result
    inc i
  return ""

proc headerVal(resp, name: string): string =
  ## Case-insensitive lookup of a response header value from the raw response
  ## (searches only the header block, before the blank line).
  var i = 0
  let lname = lowerAscii(name)
  while i < resp.len:
    # end of header block?
    if i + 1 < resp.len and resp[i] == '\r' and resp[i+1] == '\n' and
       i + 3 < resp.len and resp[i+2] == '\r' and resp[i+3] == '\n':
      break
    # start of a line: read "name: value" up to CRLF
    let lineStart = i
    var colon = -1
    var j = lineStart
    while j < resp.len and resp[j] != '\r' and resp[j] != '\n':
      if colon < 0 and resp[j] == ':':
        colon = j
      inc j
    if colon > lineStart:
      var nm = ""
      var k = lineStart
      while k < colon:
        nm.add resp[k]
        inc k
      if lowerAscii(trimHttp(nm)) == lname:
        var v = ""
        var m = colon + 1
        while m < j:
          v.add resp[m]
          inc m
        return trimHttp(v)
    # advance past CRLF
    i = j
    if i < resp.len and resp[i] == '\r': inc i
    if i < resp.len and resp[i] == '\n': inc i
  return ""

proc request(port: int; raw: string): string =
  let fd = connectLocalhostTcp(port)
  check(fd != InvalidTcpHandle, "client connect failed")
  check(writeAll(fd, raw), "client write failed")
  result = readAll(fd)
  closeTcp(fd)

proc main() =
  # --- build the router ---------------------------------------------------
  var r = newRouter()
  r.use(stampMw)
  r.get("/users/:id", getUser)
  r.post("/users", createUser)
  r.get("/static/*", getAsset)
  gHandler = r.toHandler

  # --- start the real server on a background thread -----------------------
  initTcp()
  gListen = listenTcp(0)
  check(gListen != InvalidTcpHandle, "listen failed")
  let port = localTcpEndpoint(gListen).port
  check(port > 0, "no ephemeral port")
  gMax = 5

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  # 1. :id param extraction + middleware header present
  block:
    let resp = request(port, "GET /users/42 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "user status not 200 (got " & $statusOf(resp) & ")")
    check(bodyOf(resp) == "user=42\n", "param not extracted: body=" & bodyOf(resp))
    check(headerVal(resp, "X-Middleware") == "on", "middleware header missing on 200")

  # 2. wildcard capture
  block:
    let resp = request(port, "GET /static/js/app.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "asset status not 200 (got " & $statusOf(resp) & ")")
    check(bodyOf(resp) == "asset=js/app.js\n", "wildcard not captured: body=" & bodyOf(resp))

  # 3. unknown path -> 404 (middleware still runs)
  block:
    let resp = request(port, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 404, "unknown path not 404 (got " & $statusOf(resp) & ")")
    check(headerVal(resp, "X-Middleware") == "on", "middleware header missing on 404")

  # 4. wrong method on a known path -> 405 with Allow
  block:
    let resp = request(port, "DELETE /users/42 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 405, "wrong method not 405 (got " & $statusOf(resp) & ")")
    let allow = headerVal(resp, "Allow")
    check(allow.len > 0, "405 missing Allow header")
    check(find(allow, "GET") >= 0, "Allow does not list GET: " & allow)

  # 5. POST /users routes to the create handler (method dispatch)
  block:
    let resp = request(port, "POST /users HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 201, "post status not 201 (got " & $statusOf(resp) & ")")

  join(t)
  closeTcp(gListen)
  shutdownTcp()
  echo "tserve_router: all checks passed"

main()
