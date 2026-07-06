## serve/loop.aowl — the accept/read/write event loop over `std/ioring`
## (io_uring-style TCP; Linux-only).
##
## `serve(root, port)` loops forever, accepting connections, reading the
## request, routing it to a static file under `root`, writing the response, and
## closing (HTTP/1.1 `Connection: close`). Pass `maxRequests > 0` to stop after
## N served responses (used by demos/tests).
##
## This loop is deliberately simple and single-response-at-a-time. The generic
## HTTP parsing/response helpers live in `http`; this module owns only the
## ioring transport glue.

import std/syncio
import std/ioring
import http/request
import http/response
import static

var readBuf = default(array[8192, char])
var respBuf = default(array[1048576, char])
var respLen = 0

proc stageResponse(resp: string) =
  ## Copy an HTTP response string into the addressable write buffer.
  respLen = 0
  var i = 0
  while i < resp.len and i < respBuf.len:
    respBuf[i] = resp[i]
    inc i
  respLen = i

proc bufToString(n: int): string =
  ## Materialise the first `n` bytes of the read buffer as a string.
  result = ""
  var i = 0
  while i < n and i < readBuf.len:
    result.add readBuf[i]
    inc i

proc route(root: string; raw: string): string =
  ## Turn a raw request into a full HTTP response.
  let req = parseRequest(raw)
  if not isValidRequest(req):
    return httpResponse(400, "text/plain", "Bad Request\n")
  if isMethod(req, "OPTIONS"):
    return optionsResponse("GET, HEAD, OPTIONS")
  if isMethod(req, "HEAD"):
    return staticResponse(root, req.path, false)
  if not isMethod(req, "GET"):
    return httpResponse(405, "text/plain", "Method Not Allowed\n")
  return staticResponse(root, req.path, true)

proc serve*(root: string; port: int; maxRequests = 0) =
  ## Serve static files under `root` on `port`. Loops forever unless
  ## `maxRequests > 0`, in which case it exits after that many responses.
  initPool()
  initIoRing()
  let l = listenTcp(uint16(port))
  echo "serving ", root, " on :", port, " (fd=", l, ")"
  discard submitAccept(l)

  var comps = default(array[16, IoCompletion])
  var served = 0
  while maxRequests == 0 or served < maxRequests:
    let n = waitCompletions(comps)
    var i = 0
    while i < n:
      let c = comps[i]
      case c.op
      of opAccept:
        discard submitAccept(l)
        let clientFd = c.result.cint
        if clientFd >= 0:
          setNonBlocking(clientFd)
          discard submitRead(clientFd, addr readBuf[0], readBuf.len)
      of opRead:
        if c.result <= 0:
          closeFd(c.fd)
        else:
          let raw = bufToString(c.result)
          stageResponse(route(root, raw))
          discard submitWrite(c.fd, addr respBuf[0], respLen)
      of opWrite:
        closeFd(c.fd)
        inc served
      inc i
  closeFd(l)
  shutdownPool()
  echo "served ", served, " request(s); exiting"
