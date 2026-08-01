## serve/reactorws.nim — an async, RFC 6455-conformant WebSocket server on the
## reactor.
##
## One thread, epoll-multiplexed: each connection is a flat coroutine that reads
## the HTTP Upgrade request, completes the server handshake (negotiating
## permessage-deflate when offered), then runs a frame loop that is Autobahn-grade
## strict:
##
##   * every client frame must be masked (else Close 1002);
##   * RSV2/RSV3 always illegal, RSV1 only on the first frame of a data message
##     and only when permessage-deflate was negotiated (else 1002);
##   * reserved opcodes (3..7, 0xB..0xF) are refused (1002);
##   * control frames must be FIN and <= 125 bytes (1002);
##   * a proper fragmentation state machine (continuation only mid-message, no new
##     data frame mid-message);
##   * text payloads are UTF-8 validated incrementally as fragments arrive, and a
##     Close reason is validated too (bad UTF-8 -> Close 1007);
##   * Close frames have their status code validated and echoed (1002 on a bad
##     code, empty echo on an empty Close);
##   * ping -> pong automatically; permessage-deflate compress/inflate per message
##     (no_context_takeover).
##
## The frame decoder is buffer-based (`tryDecodeFrame`): the ws package only
## ships a transport-coupled reader, so async needs its own incremental one.
## Encoding, the handshake, the UTF-8/close-code predicates, and the deflate codec
## all reuse the ws package.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp
import tls
import ./reactor
import ./asyncio
import ./asyncconn
import http/request
import ws/frame
import ws/handshake
import ws/protocol
import ws/deflate

type
  WsHandler* = proc(msg: string; isBinary: bool): string {.nimcall.}
    ## Given a complete received message, return a reply to send back
    ## (empty string = send nothing). Ping/pong/close are handled automatically.

  DecodedFrame = object
    op: int
    payload: string
    fin, rsv1, rsv2, rsv3, masked: bool
    consumed: int

const ReadChunk = 4096
const MaxMessage = 64 * 1024 * 1024   # reassembly cap -> Close 1009 past this
const MaxDrainBytes = 64 * 1024

var gWsHandler: nil WsHandler = nil
var gWsIdleMs = 0
var gWsTlsCtx = TlsContext(handle: nil, mode: tlsClient, stateId: 0)

# ---------------------------------------------------------------------------
# small pure helpers
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

proc closePayload(code: int; reason: string): string =
  ## 2-byte big-endian status code + optional UTF-8 reason. code <= 0 => empty.
  result = ""
  if code <= 0:
    return result
  result.add char((code shr 8) and 0xff)
  result.add char(code and 0xff)
  result.add reason

# ---------------------------------------------------------------------------
# incremental frame decoding (pure; RFC 6455 §5.2)
# ---------------------------------------------------------------------------

proc tryDecodeFrame(buf: string; f: var DecodedFrame): int =
  ## 1 = one full frame decoded into `f`, 0 = incomplete (need more bytes),
  ## -1 = framing error (oversized 64-bit length with the high bit set).
  let n = buf.len
  if n < 2: return 0
  let b0 = uint8(ord(buf[0]))
  let b1 = uint8(ord(buf[1]))
  f.fin = (b0 and 0x80'u8) != 0'u8
  f.rsv1 = (b0 and 0x40'u8) != 0'u8
  f.rsv2 = (b0 and 0x20'u8) != 0'u8
  f.rsv3 = (b0 and 0x10'u8) != 0'u8
  f.op = int(b0 and 0x0f'u8)
  f.masked = (b1 and 0x80'u8) != 0'u8
  let len7 = int(b1 and 0x7f'u8)
  var hdr = 2
  var plen = len7
  if len7 == 126:
    if n < 4: return 0
    plen = (int(uint8(ord(buf[2]))) shl 8) or int(uint8(ord(buf[3])))
    hdr = 4
  elif len7 == 127:
    if n < 10: return 0
    # The high bit of a 64-bit length MUST be 0 (RFC 6455 §5.2); reject if set.
    if (uint8(ord(buf[2])) and 0x80'u8) != 0'u8:
      return -1
    plen = 0
    var k = 0
    while k < 8:
      plen = (plen shl 8) or int(uint8(ord(buf[2 + k])))
      inc k
    hdr = 10
  var maskKey = [0'u8, 0'u8, 0'u8, 0'u8]
  if f.masked:
    if n < hdr + 4: return 0
    var m = 0
    while m < 4:
      maskKey[m] = uint8(ord(buf[hdr + m]))
      inc m
    hdr = hdr + 4
  if n < hdr + plen: return 0
  f.payload = ""
  var p = 0
  while p < plen:
    var c = uint8(ord(buf[hdr + p]))
    if f.masked:
      c = c xor maskKey[p and 3]
    f.payload.add char(c)
    inc p
  f.consumed = hdr + plen
  return 1

# ---------------------------------------------------------------------------
# send helper (template: inlines its suspend into the calling coroutine)
# ---------------------------------------------------------------------------

template awaitSendFrame(r: Reactor; c: var Conn; op: Opcode; payload: string;
                        okOut: var bool; rsv1 = false) =
  let frameStr = encodeFrame(op, payload, true, false, [0'u8, 0'u8, 0'u8, 0'u8], rsv1)
  var sbuf = newSeq[char](frameStr.len)
  var si = 0
  while si < frameStr.len:
    sbuf[si] = frameStr[si]
    inc si
  if sbuf.len == 0:
    okOut = true
  else:
    r.awaitConnWriteAll(c, addr sbuf[0], sbuf.len, okOut)

# ---------------------------------------------------------------------------
# the per-connection coroutine
# ---------------------------------------------------------------------------

proc handleWsConn(r: Reactor; c0: Conn) {.passive.} =
  ## Cleartext and TLS run the same body; the transport is a Conn (asyncconn.nim).
  var c = c0
  var buf = default(array[ReadChunk, char])
  var inbuf = ""
  var handshook = false
  r.awaitConnHandshake(c, handshook)
  var alive = handshook
  var useDeflate = false

  # --- read the HTTP Upgrade request (until end of headers) ---------------
  var hEnd = -1
  var reqErr = not handshook
  while (hEnd < 0) and (not reqErr):
    hEnd = headerEndOf(inbuf)
    if hEnd < 0:
      var n = 0
      r.awaitConnRead(c, addr buf[0], ReadChunk, n)
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
      useDeflate = requestOffersDeflate(req)
      inbuf = subStr(inbuf, hEnd, inbuf.len)   # any bytes past headers
      let resp = serverHandshakeResponse(websocketKey(req), useDeflate)
      var sbuf = newSeq[char](resp.len)
      var si = 0
      while si < resp.len:
        sbuf[si] = resp[si]
        inc si
      var ok = false
      if sbuf.len == 0:
        ok = true
      else:
        r.awaitConnWriteAll(c, addr sbuf[0], sbuf.len, ok)
      if not ok:
        alive = false

  # --- frame loop ---------------------------------------------------------
  # message-assembly state
  var msg = ""                 # reassembled payload (all fragments)
  var fragOpcode = -1          # -1 = idle, else 1 (text) or 2 (binary) in progress
  var msgIsText = false
  var msgCompressed = false
  var utf8State = Utf8Accept   # incremental UTF-8 state for uncompressed text
  var pendingClose = -1        # >=0 => send this Close code then stop
  var pendingReason = ""

  while alive:
    var f = default(DecodedFrame)
    let rc = tryDecodeFrame(inbuf, f)
    if rc < 0:
      pendingClose = CloseProtocolError
    elif rc == 0:
      # need more bytes
      var n = 0
      r.awaitConnRead(c, addr buf[0], ReadChunk, n)
      if n <= 0:
        alive = false
      else:
        var k = 0
        while k < n:
          inbuf.add buf[k]
          inc k
    else:
      inbuf = subStr(inbuf, f.consumed, inbuf.len)
      let isControl = f.op >= 0x8

      # ---- frame-level validation (any failure -> Close 1002) ------------
      if not f.masked:
        pendingClose = CloseProtocolError          # client frames must be masked
      elif f.rsv2 or f.rsv3:
        pendingClose = CloseProtocolError          # no extension defines RSV2/3
      elif f.rsv1 and (isControl or f.op == 0x0 or not useDeflate):
        # RSV1 only legal on the first frame of a data message under deflate.
        pendingClose = CloseProtocolError
      elif isControl and ((not f.fin) or f.payload.len > 125):
        pendingClose = CloseProtocolError          # control frames: FIN, <=125
      elif (f.op >= 0x3 and f.op <= 0x7) or f.op >= 0xB:
        pendingClose = CloseProtocolError          # reserved opcodes

      # ---- control frames -----------------------------------------------
      elif f.op == 0x8:                            # close
        # validate the peer's close code / reason, then echo.
        var echoCode = CloseNormal
        var echoReason = ""
        if f.payload.len == 1:
          echoCode = CloseProtocolError            # 1-byte body is illegal
        elif f.payload.len >= 2:
          let code = (int(uint8(ord(f.payload[0]))) shl 8) or int(uint8(ord(f.payload[1])))
          let reason = subStr(f.payload, 2, f.payload.len)
          if not isValidCloseCode(code):
            echoCode = CloseProtocolError
          elif not validateUtf8(reason):
            echoCode = CloseInvalidPayload          # bad UTF-8 in reason -> 1007
          else:
            echoCode = code
            echoReason = reason
        else:
          echoCode = -1                             # empty Close -> empty echo
        var ok = false
        r.awaitSendFrame(c, opClose, closePayload(echoCode, echoReason), ok)
        alive = false

      elif f.op == 0x9:                            # ping -> pong (echo payload)
        var ok = false
        r.awaitSendFrame(c, opPong, f.payload, ok)
        if not ok: alive = false

      elif f.op == 0xA:                            # pong -> ignore
        discard

      # ---- data frames (text / binary / continuation) -------------------
      else:
        var protoErr = false
        if f.op == 0x1 or f.op == 0x2:
          if fragOpcode != -1:
            protoErr = true                         # new data frame mid-message
          else:
            msgIsText = (f.op == 0x1)
            msgCompressed = f.rsv1
            msg = ""
            utf8State = Utf8Accept
            if not f.fin:
              fragOpcode = f.op
        else:                                       # continuation (op 0)
          if fragOpcode == -1:
            protoErr = true                         # continuation with no message

        if protoErr:
          pendingClose = CloseProtocolError
        elif msg.len + f.payload.len > MaxMessage:
          pendingClose = CloseMessageTooBig
        else:
          msg.add f.payload
          # incremental UTF-8 check for uncompressed text, as bytes arrive.
          var badUtf8 = false
          if msgIsText and (not msgCompressed):
            var i = 0
            while i < f.payload.len:
              utf8State = utf8Step(utf8State, uint8(ord(f.payload[i])))
              if utf8State == Utf8Reject:
                badUtf8 = true
                i = f.payload.len
              else:
                inc i
          if badUtf8:
            pendingClose = CloseInvalidPayload
          elif f.fin:
            fragOpcode = -1
            # finalize the message
            var body = msg
            var deliver = true
            if msgCompressed:
              let inf = inflateMessage(body, MaxMessage)
              if not inf.ok:
                pendingClose = CloseInvalidPayload
                deliver = false
              else:
                body = inf.data
                if msgIsText and (not validateUtf8(body)):
                  pendingClose = CloseInvalidPayload
                  deliver = false
            elif msgIsText and utf8State != Utf8Accept:
              pendingClose = CloseInvalidPayload     # truncated multibyte at FIN
              deliver = false
            if deliver:
              let reply = gWsHandler(body, not msgIsText)
              if reply.len > 0:
                var replyOp = opText
                if not msgIsText: replyOp = opBinary
                var outPayload = reply
                var replyRsv1 = false
                if useDeflate:
                  let df = deflateMessage(reply)
                  if df.ok:
                    outPayload = df.data
                    replyRsv1 = true
                var ok = false
                r.awaitSendFrame(c, replyOp, outPayload, ok, replyRsv1)
                if not ok: alive = false

      # ---- a queued protocol failure: send Close then stop --------------
      if pendingClose >= 0 and alive:
        var ok = false
        r.awaitSendFrame(c, opClose, closePayload(pendingClose, pendingReason), ok)
        alive = false

  r.closeConn(c, addr buf[0], ReadChunk, MaxDrainBytes)

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
      r.setIdleTimeout(fd, gWsIdleMs)
      r.spawn(delay(handleWsConn(r, plainConn(fd))))

proc acceptLoopWss(r: Reactor; listenFd: cint) {.passive.} =
  var running = true
  while running:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      running = false
    else:
      discard setTcpNonBlocking(fd)   # BEFORE tlsConn: wrapServer starts the handshake
      r.register(fd)
      r.setIdleTimeout(fd, gWsIdleMs)
      r.spawn(delay(handleWsConn(r, tlsConn(gWsTlsCtx, fd))))

proc serveWsReactor*(port: int; handler: WsHandler; idleTimeoutMs = 0) =
  ## Serve WebSocket on `port` with a single-threaded epoll reactor. `handler`
  ## receives each complete message and returns a reply (or "").
  ##
  ## `idleTimeoutMs` defaults to 0 — OFF — because a silent WebSocket is not a
  ## stalled one: a subscription that says nothing for an hour is the normal
  ## case. Set it (with an application-level ping) if the deployment wants dead
  ## peers reaped.
  gWsHandler = handler
  gWsIdleMs = idleTimeoutMs
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.register(listenFd)
  r.spawn(delay(acceptLoopWs(r, listenFd)))
  r.run()

proc serveWssReactor*(port: int; certFile: string; keyFile: string;
                      handler: WsHandler; idleTimeoutMs = 0) =
  ## Serve **wss://** — the same WebSocket server over TLS, same coroutine, same
  ## thread (asyncconn.nim), with the handshake pumped asynchronously. ALPN
  ## advertises `http/1.1`, which is what the Upgrade dance rides on.
  gWsHandler = handler
  gWsIdleMs = idleTimeoutMs
  var ctx = newTlsServerContext(certFile, keyFile)
  if not ctx.isValid:
    return
  discard ctx.setAlpnServer(@["http/1.1"])
  gWsTlsCtx = ctx
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    return
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.register(listenFd)
  r.spawn(delay(acceptLoopWss(r, listenFd)))
  r.run()
