## A reverse proxy on the reactor — the thing an async client exists for.
##
## Every request is forwarded to an upstream server and its response returned,
## with the outbound call suspending like any other I/O: while one connection
## waits on the upstream, the same thread keeps serving everyone else.
##
##   bin/reactor_proxy 8160 127.0.0.1 8161 &      # listen 8160, upstream 8161
##   curl http://127.0.0.1:8160/hello
##
## The handler is a `{.nimcall.}` function pointer, which cannot capture — and
## the fetch must happen inside the connection coroutine anyway, since that is
## what suspends. So the proxy is written as its own connection coroutine rather
## than as a handler passed to `serveHttpReactor`.

import std/[cmdline, strutils]
import tcp
import serve/reactor
import serve/asyncio
import serve/asyncconn
import serve/asyncclient
import http/request
import http/response

const ReadChunk = 4096

var gUpHost = "127.0.0.1"
var gUpPort = 8161

proc proxyConn(r: Reactor; c0: Conn) {.passive.} =
  var c = c0
  var buf = default(array[ReadChunk, char])
  var raw = ""
  var headEnd = -1
  var failed = false

  # Read the request head (this proxy forwards method + path + body-less GETs
  # and small bodies framed by Content-Length).
  while headEnd < 0 and not failed:
    var got = 0
    r.awaitConnRead(c, addr buf[0], ReadChunk, got)
    if got <= 0:
      failed = true
    else:
      var k = 0
      while k < got:
        raw.add buf[k]
        inc k
      headEnd = responseHeaderEnd(raw)

  if not failed:
    let req = parseRequest(raw)
    var up = Response(status: 0, contentType: "", headers: @[], body: "")
    var ok = false
    r.awaitFetch(gUpHost, gUpPort, false, req.meth, req.path, req.body, up, ok)
    if not ok:
      up = response(502, "text/plain", "upstream unreachable\n")
    let outStr = responseToString(up, true)
    var outBuf = newSeq[char](outStr.len)
    var w = 0
    while w < outStr.len:
      outBuf[w] = outStr[w]
      inc w
    var wrote = false
    if outBuf.len > 0:
      r.awaitConnWriteAll(c, addr outBuf[0], outBuf.len, wrote)

  r.closeConn(c, addr buf[0], ReadChunk, 64 * 1024)

proc acceptProxy(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      discard setTcpNonBlocking(fd)
      r.register(fd)
      r.setIdleTimeout(fd, 30_000)
      r.spawn(delay(proxyConn(r, plainConn(fd))))

var port = 8160
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8160
if paramCount() >= 2:
  gUpHost = paramStr(2)
if paramCount() >= 3:
  try: gUpPort = parseInt(paramStr(3))
  except: gUpPort = 8161

let listenFd = listenTcp(port)
if isValidTcp(listenFd):
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.stopOnSignals()
  r.registerListener(listenFd)
  r.spawn(delay(acceptProxy(r, listenFd)))
  r.run()
