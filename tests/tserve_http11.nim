## tserve_http11.nim — HTTP/1.1 request-framing correctness: chunked request
## bodies are de-chunked before the handler sees them, and `Expect: 100-continue`
## gets an interim 100 response.
##
## Runs the real `serveConnection` on a background thread; an /echo handler
## returns the request body verbatim, so a decoded chunked body proves the
## de-chunking, and a 100-continue exchange proves the interim response.

import std/syncio
import std/rawthreads
import serve

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

proc contains(hay: string; needle: string): bool =
  if needle.len == 0: return true
  var i = 0
  while i + needle.len <= hay.len:
    var j = 0
    var ok = true
    while j < needle.len:
      if hay[i + j] != needle[j]:
        ok = false
        break
      inc j
    if ok: return true
    inc i
  return false

proc request(port: int; raw: string): string =
  let fd = connectLocalhostTcp(port)
  check(fd != InvalidTcpHandle, "client connect failed")
  check(writeAll(fd, raw), "client write failed")
  result = readAll(fd)
  closeTcp(fd)

proc main =
  initTcp()

  var tag = "echo"   # captured so the handler closure has a non-empty env
  gHandler = proc(req: Request): Response {.closure.} =
    if req.path == "/echo":
      return response(200, "text/plain", req.body)
    return response(404, tag, "no\n")

  gListen = listenTcp(0)
  check(gListen != InvalidTcpHandle, "listen failed")
  let port = localTcpEndpoint(gListen).port
  gMax = 2

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  # 1. Chunked request body is de-chunked before the handler sees it.
  block:
    let req = "POST /echo HTTP/1.1\r\nHost: x\r\n" &
              "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" &
              "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    let resp = request(port, req)
    check(bodyOf(resp) == "hello world",
          "chunked body not decoded: '" & bodyOf(resp) & "'")

  # 2. Expect: 100-continue yields an interim 100 before the final 200.
  block:
    let req = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" &
              "Expect: 100-continue\r\nConnection: close\r\n\r\nhello"
    let resp = request(port, req)
    check(contains(resp, "100 Continue"), "no interim 100 Continue sent")
    check(contains(resp, "200"), "no final 200")
    # The stream is the interim 100 response followed by the final 200 whose body
    # is the echoed "hello", so it lands at the very end after a blank line.
    check(contains(resp, "\r\n\r\nhello"), "100-continue echoed body missing")

  join(t)
  closeTcp(gListen)
  shutdownTcp()
  echo "tserve_http11: all checks passed"

main()
