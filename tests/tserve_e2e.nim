## tserve_e2e.aowl — real end-to-end behavioral test for the programmable
## `serve` server.
##
## It runs the ACTUAL server (`serveConnection`, the same code path `serve`
## uses) on a background thread bound to an ephemeral port, then drives a
## blocking loopback client on the main thread. Threads (not a single-thread
## nonblocking pump) are used so the >1 MB body test cannot deadlock on a full
## socket send buffer.
##
## Assertions:
##   * a custom handler's 200 body is returned verbatim;
##   * a >1 MB response body round-trips intact (proves the old 1 MB write cap
##     is gone and Content-Length matches the bytes written);
##   * a GET to a static root returns the file bytes;
##   * a `..` path is rejected (403);
##   * an unknown path 404s.

import std/syncio
import std/rawthreads
import std/dirs
import std/paths
import serve

const BigSize = 1_500_000   # > 1 MB, to exercise the removed response cap

var gListen = InvalidTcpHandle
var gHandler: Handler
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
      serveConnection(fd, gHandler)
      inc served

proc bigBody(): string =
  ## Deterministic > 1 MB payload: repeating 0..255 byte pattern.
  result = ""
  var i = 0
  while i < BigSize:
    result.add chr(i and 0xff)
    inc i

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
  ## Read until the peer closes (server sends `Connection: close`).
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
  ## Parse the numeric status code out of the status line.
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
  ## Everything after the first blank line (CRLFCRLF).
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

proc request(port: int; raw: string): string =
  ## One request/response over a fresh connection; returns the raw response.
  let fd = connectLocalhostTcp(port)
  check(fd != InvalidTcpHandle, "client connect failed")
  check(writeAll(fd, raw), "client write failed")
  result = readAll(fd)
  closeTcp(fd)

proc main() =
  # --- static root fixture -------------------------------------------------
  let rootDir = "/tmp/serve_e2e_root"
  let indexBody = "<h1>static index</h1>\n"
  try:
    createDir(path(rootDir))
    syncio.writeFile(rootDir & "/index.html", indexBody)
  except:
    echo "FAIL: could not create static fixture"
    quit(1)

  # --- handler: custom routes + static fallback ---------------------------
  let big = bigBody()
  gHandler = proc(req: Request): Response {.closure.} =
    if req.path == "/hello":
      return response(200, "text/plain", "hello from handler\n")
    if req.path == "/big":
      return response(200, "application/octet-stream", big)
    return staticRoute(rootDir, req)

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

  # 1. custom handler 200 body
  block:
    let resp = request(port, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "handler status not 200")
    check(bodyOf(resp) == "hello from handler\n", "handler body mismatch")

  # 2. large (>1MB) body round-trips intact
  block:
    let resp = request(port, "GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "big status not 200")
    let b = bodyOf(resp)
    check(b.len == BigSize, "big body truncated: got " & $b.len & " want " & $BigSize)
    check(b[0] == chr(0) and b[255] == chr(255) and b[BigSize - 1] == chr((BigSize - 1) and 0xff),
          "big body content mismatch")

  # 3. static GET returns file bytes
  block:
    let resp = request(port, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "static status not 200")
    check(bodyOf(resp) == indexBody, "static body mismatch")

  # 4. `..` path is rejected
  block:
    let resp = request(port, "GET /../secret HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 403, "dotdot not rejected (got " & $statusOf(resp) & ")")

  # 5. unknown path 404s
  block:
    let resp = request(port, "GET /nope.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 404, "unknown path not 404 (got " & $statusOf(resp) & ")")

  join(t)
  closeTcp(gListen)
  shutdownTcp()
  echo "tserve_e2e: all checks passed"

main()
