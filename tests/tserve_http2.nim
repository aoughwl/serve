## tserve_http2.nim — real HTTP/2 (h2c) end-to-end against curl.
##
## Binds a listener, spawns `curl --http2-prior-knowledge` at it on a background
## thread, accepts the connection on the main thread and drives it with the
## nghttp2 session, then checks curl received the handler's HTTP/2 response body.

import std/syncio
import std/os
import std/rawthreads
import serve
import serve/http2

var gPort = 0

proc h2handler(req: Request): Response {.nimcall.} =
  return response(200, "text/plain", "h2 path=" & req.path & "\n")

proc clientThread(arg: pointer) {.nimcall.} =
  discard arg
  var cmd = "curl -s --http2-prior-knowledge http://localhost:"
  cmd.add $gPort
  cmd.add "/hello -o /tmp/aoughwl_h2out.txt 2>/dev/null"
  discard execShellCmd(cmd)

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

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

proc main =
  # curl must support HTTP/2.
  if execShellCmd("curl --version 2>/dev/null | grep -q -i http2") != 0:
    echo "SKIP: curl lacks HTTP/2 support"
    quit(0)

  initTcp()
  let l = listenTcp(0)
  check(l != InvalidTcpHandle, "listen failed")
  gPort = localTcpEndpoint(l).port
  check(gPort > 0, "no ephemeral port")

  var t = default(RawThread)
  try:
    create(t, clientThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  let fd = acceptTcp(l)
  check(fd != InvalidTcpHandle, "accept failed")
  serveHttp2Connection(fd, h2handler)

  join(t)
  closeTcp(l)
  shutdownTcp()

  var body = ""
  try:
    body = readFile("/tmp/aoughwl_h2out.txt")
  except:
    echo "FAIL: could not read curl output"
    quit(1)
  check(contains(body, "h2 path=/hello"), "curl did not receive HTTP/2 body: '" & body & "'")
  echo "tserve_http2: all checks passed"

main()
