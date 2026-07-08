## tserve_compress.nim — end-to-end response compression against curl.
##
## A handler wraps a large compressible body in `compressResponse`. `curl
## --compressed` sends `Accept-Encoding` and transparently decompresses, so we
## verify both that the decompressed body matches AND that the response actually
## carried `Content-Encoding` (from a header dump).

import std/syncio
import std/os
import std/rawthreads
import serve
import serve/encoding

var gListen = InvalidTcpHandle
var gHandler: Handler
var gMax = 0

proc bigBody(): string =
  result = ""
  var i = 0
  while i < 400:
    result.add "the quick brown fox jumps over the lazy dog. "
    inc i

proc serverThread(arg: pointer) {.nimcall.} =
  discard arg
  var served = 0
  while served < gMax:
    let fd = acceptTcp(gListen)
    if fd != InvalidTcpHandle:
      serveConnection(fd, gHandler)
      inc served

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
      var a = hay[i + j]
      var b = needle[j]
      if a >= 'A' and a <= 'Z': a = chr(ord(a) + 32)
      if b >= 'A' and b <= 'Z': b = chr(ord(b) + 32)
      if a != b:
        ok = false
        break
      inc j
    if ok: return true
    inc i
  return false

proc main =
  initTcp()
  let big = bigBody()
  gHandler = proc(req: Request): Response {.closure.} =
    return compressResponse(req, response(200, "text/plain", big))

  gListen = listenTcp(0)
  check(gListen != InvalidTcpHandle, "listen failed")
  let port = localTcpEndpoint(gListen).port
  gMax = 1

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  var cmd = "curl -s --compressed -o /tmp/aoughwl_cmp_body.txt -D /tmp/aoughwl_cmp_hdr.txt http://localhost:"
  cmd.add $port
  cmd.add "/ 2>/dev/null"
  discard execShellCmd(cmd)

  join(t)
  closeTcp(gListen)
  shutdownTcp()

  var body = ""
  var hdr = ""
  try:
    body = readFile("/tmp/aoughwl_cmp_body.txt")
    hdr = readFile("/tmp/aoughwl_cmp_hdr.txt")
  except:
    echo "FAIL: could not read curl output"
    quit(1)

  check(contains(hdr, "content-encoding: gzip") or contains(hdr, "content-encoding: br"),
        "no Content-Encoding in response headers")
  check(body == big, "decompressed body mismatch (" & $body.len & " vs " & $big.len & ")")
  echo "tserve_compress: all checks passed (", big.len, " bytes, encoded on the wire)"

main()
