## serve/reactorws.nim — an async WebSocket (RFC 6455) server on the reactor.
##
## One thread, epoll-multiplexed: each connection is a flat coroutine that reads
## the HTTP Upgrade request, completes the server handshake, then runs a frame
## loop — decoding client frames incrementally, reassembling fragmented
## messages, auto-answering ping/close, and sending the handler's reply — all
## suspending on socket readiness (asyncio templates) rather than blocking.
##
## The frame decoder is buffer-based (`tryDecodeFrame`): the ws package only
## ships a transport-coupled reader, so async needs its own incremental one.
## Encoding and the handshake reuse the ws package.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp
import ./reactor
import ./asyncio
import http/request
import ws/frame
import ws/handshake

type
  WsHandler* = proc(msg: string; isBinary: bool): string {.nimcall.}
    ## Given a complete received message, return a reply to send back
    ## (empty string = send nothing). Ping/pong/close are handled automatically.

const ReadChunk = 4096

var gWsHandler: nil WsHandler = nil

# ---------------------------------------------------------------------------
# incremental frame decoding (pure; RFC 6455)
# ---------------------------------------------------------------------------

proc subStr(s: string; a, b: int): string =
  result = ""
  var i = a
  while i < b and i < s.len:
    result.add s[i]
    inc i

proc headerEndOf(raw: string): int =
  var i = 0
  while i + 3 < raw.len:
    if raw[i] == '\r' and raw[i+1] == '\n' and raw[i+2] == '\r' and raw[i+3] == '\n':
      return i + 4
    inc i
  return -1

proc tryDecodeFrame(buf: string; opOut: var int; payload: var string;
                    finOut: var bool; consumed: var int): int =
  ## 1 = one full frame decoded (opOut/payload/finOut/consumed set),
  ## 0 = incomplete (need more bytes), -1 = protocol error.
  let n = buf.len
  if n < 2: return 0
  let b0 = uint8(ord(buf[0]))
  let b1 = uint8(ord(buf[1]))
  finOut = (b0 and 0x80'u8) != 0'u8
  opOut = int(b0 and 0x0f'u8)
  let masked = (b1 and 0x80'u8) != 0'u8
  let len7 = int(b1 and 0x7f'u8)
  var hdr = 2
  var plen = len7
  if len7 == 126:
    if n < 4: return 0
    plen = (int(uint8(ord(buf[2]))) shl 8) or int(uint8(ord(buf[3])))
    hdr = 4
  elif len7 == 127:
    if n < 10: return 0
    plen = 0
    var k = 0
    while k < 8:
      plen = (plen shl 8) or int(uint8(ord(buf[2 + k])))
      inc k
    hdr = 10
  var maskKey = [0'u8, 0'u8, 0'u8, 0'u8]
  if masked:
    if n < hdr + 4: return 0
    var m = 0
    while m < 4:
      maskKey[m] = uint8(ord(buf[hdr + m]))
      inc m
    hdr = hdr + 4
  if n < hdr + plen: return 0
  payload = ""
  var p = 0
  while p < plen:
    var c = uint8(ord(buf[hdr + p]))
    if masked:
      c = c xor maskKey[p and 3]
    payload.add char(c)
    inc p
  consumed = hdr + plen
  return 1

# ---------------------------------------------------------------------------
# send helper (template: inlines its suspend into the calling coroutine)
# ---------------------------------------------------------------------------

template awaitSendFrame(r: Reactor; fd: cint; op: Opcode; payload: string; okOut: var bool) =
  let frameStr = encodeFrame(op, payload, true, false, [0'u8, 0'u8, 0'u8, 0'u8])
  var sbuf = newSeq[char](frameStr.len)
  var si = 0
  while si < frameStr.len:
    sbuf[si] = frameStr[si]
    inc si
  if sbuf.len == 0:
    okOut = true
  else:
    r.awaitWriteAll(fd, addr sbuf[0], sbuf.len, okOut)

# ---------------------------------------------------------------------------
# the per-connection coroutine
# ---------------------------------------------------------------------------

proc handleWsConn(r: Reactor; fd: cint) {.passive.} =
  var buf = default(array[ReadChunk, char])
  var inbuf = ""
  var alive = true

  # --- read the HTTP Upgrade request (until end of headers) ---------------
  var hEnd = -1
  var reqErr = false
  while (hEnd < 0) and (not reqErr):
    hEnd = headerEndOf(inbuf)
    if hEnd < 0:
      var n = 0
      r.awaitRead(fd, addr buf[0], ReadChunk, n)
      if n <= 0:
        reqErr = true
      else:
        var k = 0
        while k < n:
          inbuf.add buf[k]
          inc k
  if reqErr:
    alive = false
  else:
    let req = parseRequest(subStr(inbuf, 0, hEnd))
    if not isWebSocketUpgrade(req):
      alive = false
    else:
      inbuf = subStr(inbuf, hEnd, inbuf.len)   # any bytes past headers
      let resp = serverHandshakeResponse(websocketKey(req))
      var sbuf = newSeq[char](resp.len)
      var si = 0
      while si < resp.len:
        sbuf[si] = resp[si]
        inc si
      var ok = false
      if sbuf.len == 0:
        ok = true
      else:
        r.awaitWriteAll(fd, addr sbuf[0], sbuf.len, ok)
      if not ok:
        alive = false

  # --- frame loop ---------------------------------------------------------
  var msg = ""
  var msgBinary = false
  while alive:
    var op = 0
    var payload = ""
    var fin = false
    var consumed = 0
    let rc = tryDecodeFrame(inbuf, op, payload, fin, consumed)
    if rc < 0:
      alive = false
    elif rc == 0:
      # need more bytes
      var n = 0
      r.awaitRead(fd, addr buf[0], ReadChunk, n)
      if n <= 0:
        alive = false
      else:
        var k = 0
        while k < n:
          inbuf.add buf[k]
          inc k
    else:
      inbuf = subStr(inbuf, consumed, inbuf.len)
      if op == 0x8:            # close
        var ok = false
        r.awaitSendFrame(fd, opClose, "", ok)
        alive = false
      elif op == 0x9:          # ping -> pong
        var ok = false
        r.awaitSendFrame(fd, opPong, payload, ok)
        if not ok: alive = false
      elif op == 0xA:          # pong -> ignore
        discard
      else:                    # continuation(0) / text(1) / binary(2)
        if op == 0x1:
          msgBinary = false
        elif op == 0x2:
          msgBinary = true
        msg.add payload
        if fin:
          let reply = gWsHandler(msg, msgBinary)
          msg = ""
          if reply.len > 0:
            var replyOp = opText
            if msgBinary: replyOp = opBinary
            var ok = false
            r.awaitSendFrame(fd, replyOp, reply, ok)
            if not ok: alive = false

  r.unregister(fd)
  closeTcp(fd)

proc acceptLoopWs(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      discard setTcpNonBlocking(fd)
      r.register(fd)
      r.spawn(delay(handleWsConn(r, fd)))

proc serveWsReactor*(port: int; handler: WsHandler) =
  ## Serve WebSocket on `port` with a single-threaded epoll reactor. `handler`
  ## receives each complete message and returns a reply (or "").
  gWsHandler = handler
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.register(listenFd)
  r.spawn(delay(acceptLoopWs(r, listenFd)))
  r.run()
