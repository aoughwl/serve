## tserve_http2tls.nim — HTTP/2 over TLS (ALPN "h2") end-to-end against curl.
##
## Generates a self-signed cert, runs the nghttp2 TLS session on a background
## thread, and drives it with `curl -k --http2 https://…`, which negotiates h2
## via ALPN. Confirms curl received the handler's response over HTTP/2.

import std/syncio
import std/os
import std/rawthreads
import serve
import serve/http2
import net
import tls

const
  certPath = "/tmp/aoughwl_h2_cert.pem"
  keyPath = "/tmp/aoughwl_h2_key.pem"

var gPort = 0
var gCtx: TlsContext
var gListen = InvalidTcpHandle
var gHandler: H2Handler

proc h2handler(req: Request): Response {.nimcall.} =
  return response(200, "text/plain", "h2tls path=" & req.path & "\n")

proc serverThread(arg: pointer) {.nimcall.} =
  discard arg
  let clientFd = acceptTcp(gListen)
  if clientFd == InvalidTcpHandle:
    return
  var sock = Socket(handle: clientFd)
  var tsock = wrapServer(gCtx, sock)
  if tsock.handshakeDone and tsock.negotiatedAlpn() == "h2":
    serveHttp2ConnectionTls(tsock, gHandler)
  else:
    tsock.closeTls()

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
  if execShellCmd("curl --version 2>/dev/null | grep -q -i http2") != 0:
    echo "SKIP: curl lacks HTTP/2 support"
    quit(0)
  let gen = "openssl req -x509 -newkey rsa:2048 -keyout " & keyPath &
            " -out " & certPath & " -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1"
  if execShellCmd(gen) != 0:
    echo "SKIP: openssl unavailable"
    quit(0)

  initNet()
  gCtx = newTlsServerContext(certPath, keyPath)
  check(gCtx.isValid, "server ctx invalid: " & lastTlsError())
  discard gCtx.setAlpnServer(@["h2", "http/1.1"])
  gHandler = h2handler

  gListen = listenTcp(0)
  check(gListen != InvalidTcpHandle, "listen failed")
  gPort = localTcpEndpoint(gListen).port

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  var cmd = "curl -s -k --http2 https://localhost:"
  cmd.add $gPort
  cmd.add "/secure -o /tmp/aoughwl_h2tls_out.txt 2>/dev/null"
  discard execShellCmd(cmd)

  join(t)
  gCtx.close()
  closeTcp(gListen)
  shutdownNet()

  var body = ""
  try:
    body = readFile("/tmp/aoughwl_h2tls_out.txt")
  except:
    echo "FAIL: could not read curl output"
    quit(1)
  check(contains(body, "h2tls path=/secure"), "curl did not receive h2-over-TLS body: '" & body & "'")
  echo "tserve_http2tls: all checks passed"

main()
