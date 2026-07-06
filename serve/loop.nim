## serve/loop.aowl — the accept/read/write event loop over `std/ioring`
## (io_uring-style TCP; Linux-only). Standard-library only.
##
## `serve(root, port)` loops forever, accepting connections, reading the
## request, routing a GET to a static file under `root`, writing the response,
## and closing (HTTP/1.1 `Connection: close`). Pass `maxRequests > 0` to stop
## after N served responses (used by the demo/tests).
##
## nimony gotchas handled here:
##   * strings are not addressable (`addr resp[0]` is rejected) — each
##     connection slot owns fixed read/write arrays and we hand ioring pointers
##     into those arrays.
##   * the init-checker rejects loop-based array init — arrays are built with
##     `default(array[N, T])`.
##   * `echo` needs `import std/syncio`.

import std/syncio
import std/ioring
import http/request
import http/response
import static

const
  MaxConnections = 64
  MaxRequestCap = 16384
  MaxResponseCap = 1048576

type
  ServeOptions* = object
    ## Runtime limits for the fixed-buffer ioring server.
    maxRequests*: int       ## 0 = serve forever
    maxConnections*: int    ## capped to 64 by this implementation
    maxRequestBytes*: int   ## capped to 16 KiB
    maxResponseBytes*: int  ## capped to 1 MiB
    backlog*: int
    verbose*: bool

  ConnSlot = object
    active: bool
    fd: cint
    readId: SeqNum
    writeId: SeqNum
    respLen: int
    writeSent: int
    readBuf: array[MaxRequestCap, char]
    respBuf: array[MaxResponseCap, char]

var slots = default(array[MaxConnections, ConnSlot])

proc defaultServeOptions*(maxRequests = 0): ServeOptions =
  ServeOptions(
    maxRequests: maxRequests,
    maxConnections: MaxConnections,
    maxRequestBytes: 8192,
    maxResponseBytes: MaxResponseCap,
    backlog: 128,
    verbose: true)

proc clampLimit(n, cap: int): int =
  if n <= 0: cap
  elif n > cap: cap
  else: n

proc activeConnectionLimit(opts: ServeOptions): int =
  clampLimit(opts.maxConnections, MaxConnections)

proc requestLimit(opts: ServeOptions): int =
  clampLimit(opts.maxRequestBytes, MaxRequestCap)

proc responseLimit(opts: ServeOptions): int =
  clampLimit(opts.maxResponseBytes, MaxResponseCap)

proc resetSlot(i: int) =
  slots[i].active = false
  slots[i].fd = 0
  slots[i].readId = SeqNum(0)
  slots[i].writeId = SeqNum(0)
  slots[i].respLen = 0
  slots[i].writeSent = 0

proc findFreeSlot(limit: int): int =
  result = -1
  var i = 0
  while i < limit:
    if not slots[i].active:
      return i
    inc i

proc findSlotByFd(fd: cint): int =
  result = -1
  var i = 0
  while i < slots.len:
    if slots[i].active and slots[i].fd == fd:
      return i
    inc i

proc closeSlot(i: int) =
  if i >= 0 and i < slots.len and slots[i].active:
    closeFd(slots[i].fd)
    resetSlot(i)

proc stageResponseInSlot(slotIndex: int; resp: string; maxBytes: int) =
  slots[slotIndex].respLen = 0
  slots[slotIndex].writeSent = 0
  var i = 0
  let limit = clampLimit(maxBytes, MaxResponseCap)
  while i < resp.len and i < limit:
    slots[slotIndex].respBuf[i] = resp[i]
    inc i
  slots[slotIndex].respLen = i

proc submitRemainingWrite(slotIndex: int) =
  let left = slots[slotIndex].respLen - slots[slotIndex].writeSent
  if left > 0:
    let off = slots[slotIndex].writeSent
    slots[slotIndex].writeId = submitWrite(
      slots[slotIndex].fd,
      addr slots[slotIndex].respBuf[off],
      left)

proc bufToString(slotIndex, n: int): string =
  ## Materialise the first `n` bytes of the read buffer as a string.
  result = ""
  var i = 0
  while i < n and i < MaxRequestCap:
    result.add slots[slotIndex].readBuf[i]
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

proc limitedRoute(root: string; raw: string; requestLimit, responseLimit: int): string =
  if raw.len >= requestLimit:
    return httpResponse(413, "text/plain", "Payload Too Large\n")
  let resp = route(root, raw)
  if resp.len > responseLimit:
    return httpResponse(500, "text/plain", "Response Too Large\n")
  return resp

proc serveWithOptions*(root: string; port: int; options: ServeOptions) =
  ## Serve static files under `root` on `port`.
  var opts = options
  let connLimit = activeConnectionLimit(opts)
  let reqLimit = requestLimit(opts)
  let respLimit = responseLimit(opts)

  var i = 0
  while i < slots.len:
    resetSlot(i)
    inc i

  initPool()
  initIoRing()
  let l = listenTcp(uint16(port), opts.backlog)
  if opts.verbose:
    echo "serving ", root, " on :", port, " (fd=", l, ")"
  discard submitAccept(l)

  var comps = default(array[16, IoCompletion])
  var served = 0
  while opts.maxRequests == 0 or served < opts.maxRequests:
    let n = waitCompletions(comps)
    var ci = 0
    while ci < n:
      let c = comps[ci]
      case c.op
      of opAccept:
        discard submitAccept(l)
        let clientFd = c.result.cint
        if clientFd >= 0:
          let si = findFreeSlot(connLimit)
          if si < 0:
            closeFd(clientFd)
          else:
            slots[si].active = true
            slots[si].fd = clientFd
            slots[si].respLen = 0
            setNonBlocking(clientFd)
            slots[si].readId = submitRead(clientFd, addr slots[si].readBuf[0], reqLimit)
      of opRead:
        let si = findSlotByFd(c.fd)
        if si >= 0:
          if c.result <= 0:
            closeSlot(si)
          else:
            let raw = bufToString(si, c.result)
            let resp = limitedRoute(root, raw, reqLimit, respLimit)
            stageResponseInSlot(si, resp, respLimit)
            submitRemainingWrite(si)
      of opWrite:
        let si = findSlotByFd(c.fd)
        if si >= 0:
          if c.result <= 0:
            closeSlot(si)
            inc served
          else:
            slots[si].writeSent = slots[si].writeSent + c.result
            if slots[si].writeSent < slots[si].respLen:
              submitRemainingWrite(si)
            else:
              closeSlot(si)
              inc served
      inc ci
  closeFd(l)
  shutdownPool()
  if opts.verbose:
    echo "served ", served, " request(s); exiting"

proc serve*(root: string; port: int; maxRequests = 0) =
  ## Serve static files under `root` on `port`. Loops forever unless
  ## `maxRequests > 0`, in which case it exits after that many responses.
  serveWithOptions(root, port, defaultServeOptions(maxRequests))
