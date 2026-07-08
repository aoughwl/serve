## tserve_tls_e2e.nim — end-to-end HTTPS test for `serveTls` / `serveConnectionTls`.
##
## Generates a throwaway self-signed cert, runs the ACTUAL TLS server path
## (`serveConnectionTls`, same code `serveTls` uses) on a background thread bound
## to an ephemeral port, and drives a real TLS client (our own `net/tls`) on the
## main thread over an encrypted connection.
##
## Assertions:
##   * a custom handler's 200 body is returned verbatim over TLS;
##   * a > 1 MB body round-trips intact through the encrypted stream;
##   * an unknown path 404s.

import std/syncio
import std/os
import std/rawthreads
import serve
import net

const
  certPath = "/tmp/aoughwl_serve_tls_cert.pem"
  keyPath = "/tmp/aoughwl_serve_tls_key.pem"
  BigSize = 1_500_000

var gListen = InvalidTcpHandle
var gHandler: Handler
var gMax = 0
var gCtx: TlsContext

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
      serveConnectionTls(fd, gCtx, gHandler)
      inc served

proc bigBody(): string =
  result = ""
  var i = 0
  while i < BigSize:
    result.add chr(i and 0xff)
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

var gClientCtx: TlsContext

proc tlsRequest(port: int; raw: string): string =
  ## One request/response over a fresh TLS connection; returns the raw plaintext
  ## HTTP response (server sends `Connection: close`, so `readAll` ends at the
  ## TLS close_notify).
  let sock = connectLocalhost(port)
  check(sock.isValid, "client connect failed")
  var c = wrapClient(gClientCtx, sock, "localhost")
  check(c.handshakeDone, "client TLS handshake failed: " & lastTlsError())
  check(c.sendAll(raw), "client TLS write failed")
  result = c.readAll()
  c.closeTls()

proc main() =
  initNet()

  let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " & keyPath &
            " -out " & certPath &
            " -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1"
  if execShellCmd(cmd) != 0:
    echo "SKIP: openssl CLI unavailable"
    quit(0)

  gCtx = newTlsServerContext(certPath, keyPath)
  check(gCtx.isValid, "server ctx invalid: " & lastTlsError())
  gClientCtx = newTlsClientContext(verify = false)
  check(gClientCtx.isValid, "client ctx invalid")

  let big = bigBody()
  gHandler = proc(req: Request): Response {.closure.} =
    if req.path == "/hello":
      return response(200, "text/plain", "hello over https\n")
    if req.path == "/big":
      return response(200, "application/octet-stream", big)
    return response(404, "text/plain", "Not Found\n")

  gListen = listenTcp(0)
  check(gListen != InvalidTcpHandle, "listen failed")
  let port = localTcpEndpoint(gListen).port
  check(port > 0, "no ephemeral port")
  gMax = 3

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  block:
    let resp = tlsRequest(port, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "handler status not 200 (got " & $statusOf(resp) & ")")
    check(bodyOf(resp) == "hello over https\n", "handler body mismatch")

  block:
    let resp = tlsRequest(port, "GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 200, "big status not 200")
    let b = bodyOf(resp)
    check(b.len == BigSize, "big body truncated over TLS: got " & $b.len)
    check(b[0] == chr(0) and b[BigSize - 1] == chr((BigSize - 1) and 0xff),
          "big body content mismatch over TLS")

  block:
    let resp = tlsRequest(port, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check(statusOf(resp) == 404, "unknown path not 404")

  join(t)
  closeTcp(gListen)
  gCtx.close()
  gClientCtx.close()
  shutdownNet()
  echo "tserve_tls_e2e: all checks passed"

main()
