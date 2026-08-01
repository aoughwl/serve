## quic/quic.nim — nimony bindings to the ngtcp2/nghttp3/GnuTLS glue shim
## (`libaowlquic.so`, built from quic/quicglue.c).
##
## The shim owns the UDP socket, QUIC connections, TLS sessions, timers, and the
## HTTP/3 layer; nimony drives it through a small pull-based API and epoll-waits
## on `fd()`. This is the same FFI stance the stack already takes with OpenSSL
## (tls) and zlib (compress) — QUIC is simply an ngtcp2 binding.

when defined(nimony):
  {.feature: "lenientnils".}

const lib = "libaowlquic.so"

type QuicCtx* = pointer

# ---- raw C API -------------------------------------------------------------
proc aqServerNew(host: cstring; port: uint16; cert, key: cstring): QuicCtx
  {.importc: "aq_server_new", dynlib: lib.}
proc aqClientNew(host: cstring; port: uint16; authority, path: cstring): QuicCtx
  {.importc: "aq_client_new", dynlib: lib.}
proc aqClientStart(c: QuicCtx): cint {.importc: "aq_client_start", dynlib: lib.}
proc aqFd(c: QuicCtx): cint {.importc: "aq_fd", dynlib: lib.}
proc aqProcessRead(c: QuicCtx): cint {.importc: "aq_process_read", dynlib: lib.}
proc aqFlush(c: QuicCtx): cint {.importc: "aq_flush", dynlib: lib.}
proc aqTimeoutMs(c: QuicCtx): clong {.importc: "aq_timeout_ms", dynlib: lib.}
proc aqHandleTimeout(c: QuicCtx): cint {.importc: "aq_handle_timeout", dynlib: lib.}
proc aqTakeRequest(c: QuicCtx; reqId: ptr uint64; meth: ptr char; mcap: cint;
                   path: ptr char; pcap: cint): cint
  {.importc: "aq_take_request", dynlib: lib.}
proc aqRespond(c: QuicCtx; reqId: uint64; status: cint; ctype, body: cstring;
               bodyLen: cint): cint {.importc: "aq_respond", dynlib: lib.}
proc aqClientPost(c: QuicCtx; body: cstring; len: cint): cint
  {.importc: "aq_client_post", dynlib: lib.}
proc aqRequestBody(c: QuicCtx; reqId: uint64; buf: ptr char; cap: cint): cint
  {.importc: "aq_request_body", dynlib: lib.}
proc aqTakeDatagram(c: QuicCtx; buf: ptr char; cap: cint; connToken: ptr uint64): cint
  {.importc: "aq_take_datagram", dynlib: lib.}
proc aqSendDatagram(c: QuicCtx; connToken: uint64; data: ptr char; len: cint): cint
  {.importc: "aq_send_datagram", dynlib: lib.}
proc aqClientSendDatagram(c: QuicCtx; data: ptr char; len: cint): cint
  {.importc: "aq_client_send_datagram", dynlib: lib.}
proc aqClientWtConnect(c: QuicCtx): cint {.importc: "aq_client_wt_connect", dynlib: lib.}
proc aqClientWtReady(c: QuicCtx): cint {.importc: "aq_client_wt_ready", dynlib: lib.}
proc aqClientWtSendDatagram(c: QuicCtx; data: ptr char; len: cint): cint
  {.importc: "aq_client_wt_send_datagram", dynlib: lib.}
proc aqWtSendDatagram(c: QuicCtx; connToken: uint64; data: ptr char; len: cint): cint
  {.importc: "aq_wt_send_datagram", dynlib: lib.}
proc aqStats(c: QuicCtx; dest: ptr uint64; n: cint): cint
  {.importc: "aq_stats", dynlib: lib.}
proc aqConnToken(c: QuicCtx): cint {.importc: "aq_conn_token", dynlib: lib.}
proc aqWtOpenStream(c: QuicCtx; connToken: uint64; uni: cint): int64
  {.importc: "aq_wt_open_stream", dynlib: lib.}
proc aqWtStreamSend(c: QuicCtx; connToken: uint64; streamId: int64;
                    data: ptr char; len: cint; fin: cint): cint
  {.importc: "aq_wt_stream_send", dynlib: lib.}
proc aqWtTakeStream(c: QuicCtx; connToken: ptr uint64; streamId: ptr int64;
                    uni: ptr cint): cint
  {.importc: "aq_wt_take_stream", dynlib: lib.}
proc aqWtStreamRecv(c: QuicCtx; connToken: uint64; streamId: int64;
                    buf: ptr char; cap: cint): cint
  {.importc: "aq_wt_stream_recv", dynlib: lib.}
proc aqWtStreamFin(c: QuicCtx; connToken: uint64; streamId: int64): cint
  {.importc: "aq_wt_stream_fin", dynlib: lib.}
proc aqClientDone(c: QuicCtx): cint {.importc: "aq_client_done", dynlib: lib.}
proc aqClientStatus(c: QuicCtx): cint {.importc: "aq_client_status", dynlib: lib.}
proc aqClientBody(c: QuicCtx; buf: ptr char; cap: cint): cint
  {.importc: "aq_client_body", dynlib: lib.}
proc aqFree(c: QuicCtx) {.importc: "aq_free", dynlib: lib.}

# ---- nimony-friendly wrappers ---------------------------------------------
type H3Request* = object
  ok*: bool
  id*: uint64
  meth*: string
  path*: string
  body*: string

proc quicServer*(host: string; port: int; certPath, keyPath: string): QuicCtx =
  ## A bound HTTP/3 (QUIC) server context on `host:port` with a PEM cert/key.
  var h = host
  var c = certPath
  var k = keyPath
  aqServerNew(toCString(h), uint16(port), toCString(c), toCString(k))

proc quicClient*(host: string; port: int; authority, path: string): QuicCtx =
  ## An HTTP/3 client context targeting `host:port`, requesting `path` with the
  ## given `:authority` (SNI).
  var h = host
  var a = authority
  var p = path
  aqClientNew(toCString(h), uint16(port), toCString(a), toCString(p))

proc clientPost*(c: QuicCtx; body: string) =
  ## Switch a client context to POST with `body` (call before `clientStart`).
  var b = body
  discard aqClientPost(c, toCString(b), cint(b.len))

proc clientStart*(c: QuicCtx): int = int(aqClientStart(c))
proc fd*(c: QuicCtx): int = int(aqFd(c))
proc processRead*(c: QuicCtx): int = int(aqProcessRead(c))
proc flush*(c: QuicCtx): int = int(aqFlush(c))
proc timeoutMs*(c: QuicCtx): int = int(aqTimeoutMs(c))
proc handleTimeout*(c: QuicCtx): int = int(aqHandleTimeout(c))
proc clientDone*(c: QuicCtx): bool = aqClientDone(c) == 1.cint
proc clientStatus*(c: QuicCtx): int = int(aqClientStatus(c))
proc freeCtx*(c: QuicCtx) = aqFree(c)

proc takeRequest*(c: QuicCtx): H3Request =
  ## Pull one completed HTTP/3 request (or `ok = false` if none pending).
  result = default(H3Request)
  var id = 0'u64
  var mbuf = default(array[16, char])
  var pbuf = default(array[2048, char])
  let got = aqTakeRequest(c, addr id, addr mbuf[0], 16.cint, addr pbuf[0],
                          2048.cint)
  if got == 1.cint:
    result.ok = true
    result.id = id
    result.meth = ""
    var i = 0
    while i < 16 and mbuf[i] != '\0':
      result.meth.add mbuf[i]
      inc i
    result.path = ""
    i = 0
    while i < 2048 and pbuf[i] != '\0':
      result.path.add pbuf[i]
      inc i
    # request body (POST payloads); empty for GET
    const bcap = 1 shl 20
    var bbuf = newSeq[char](bcap)
    let bn = aqRequestBody(c, id, addr bbuf[0], bcap.cint)
    result.body = ""
    i = 0
    while i < bn:
      result.body.add bbuf[i]
      inc i

proc respond*(c: QuicCtx; id: uint64; status: int; ctype, body: string) =
  ## Answer a request pulled by `takeRequest`.
  var ct = ctype
  var bd = body
  discard aqRespond(c, id, cint(status), toCString(ct), toCString(bd),
                    cint(bd.len))

proc clientBody*(c: QuicCtx; maxLen = 1 shl 20): string =
  ## The received response body (client contexts).
  var buf = newSeq[char](maxLen)
  let n = aqClientBody(c, addr buf[0], cint(maxLen))
  result = ""
  var i = 0
  while i < n:
    result.add buf[i]
    inc i

# ---- RFC 9221 unreliable datagrams ----------------------------------------
type Datagram* = object
  ok*: bool
  connToken*: uint64     ## which connection it arrived on (for a reply)
  data*: string

proc takeDatagram*(c: QuicCtx; maxLen = 65535): Datagram =
  ## Pull one received QUIC datagram (or `ok = false` if none pending).
  result = default(Datagram)
  var buf = newSeq[char](maxLen)
  var tok = 0'u64
  let n = aqTakeDatagram(c, addr buf[0], cint(maxLen), addr tok)
  if n > 0:
    result.ok = true
    result.connToken = tok
    result.data = ""
    var i = 0
    while i < n:
      result.data.add buf[i]
      inc i

proc sendDatagram*(c: QuicCtx; connToken: uint64; data: string) =
  ## Queue an unreliable datagram on the connection `connToken` (from a received
  ## `Datagram`). Sent on the next flush.
  if data.len == 0: return
  var buf = newSeq[char](data.len)
  var i = 0
  while i < data.len:
    buf[i] = data[i]
    inc i
  discard aqSendDatagram(c, connToken, addr buf[0], cint(buf.len))

proc clientSendDatagram*(c: QuicCtx; data: string) =
  ## Queue an unreliable datagram on a client's single connection.
  if data.len == 0: return
  var buf = newSeq[char](data.len)
  var i = 0
  while i < data.len:
    buf[i] = data[i]
    inc i
  discard aqClientSendDatagram(c, addr buf[0], cint(buf.len))

# ---- WebTransport (extended CONNECT + WT datagrams over H3 datagrams) -------
proc clientWtConnect*(c: QuicCtx) =
  ## Mark a client context to open a WebTransport session (extended CONNECT
  ## `:protocol=webtransport`) instead of a plain request. Call before
  ## `clientStart`. Requires a WebTransport-enabled build of the shim
  ## (vendored nghttp3 >= 1.x).
  discard aqClientWtConnect(c)

proc clientWtReady*(c: QuicCtx): bool =
  ## True once the server has accepted the WebTransport session (CONNECT 200).
  aqClientWtReady(c) == 1.cint

proc clientWtSendDatagram*(c: QuicCtx; data: string) =
  ## Send a WebTransport datagram on the client's session.
  if data.len == 0: return
  var buf = newSeq[char](data.len)
  var i = 0
  while i < data.len:
    buf[i] = data[i]
    inc i
  discard aqClientWtSendDatagram(c, addr buf[0], cint(buf.len))

# ---- drop counters ---------------------------------------------------------
type QuicStats* = object
  ## Every bounded resource in the shim can fill up. With fixed capacities a
  ## drop is unavoidable — but it must never be invisible, so each one is
  ## counted here. A non-zero field means a capacity needs raising.
  sendFailed*: uint64      ## `sendto` failed (full kernel send buffer)
  dgramOutDropped*: uint64 ## outgoing datagram queue full
  dgramInDropped*: uint64  ## incoming datagram queue full
  connRefused*: uint64     ## connection table full
  cidDropped*: uint64      ## CID routing table full
  reqDropped*: uint64      ## request queue full
  truncated*: uint64       ## a request `:path` / `:method` did not fit

proc stats*(c: QuicCtx): QuicStats =
  ## Read the shim's drop counters. All zero is the healthy case.
  result = default(QuicStats)
  var v = default(array[7, uint64])
  discard aqStats(c, addr v[0], 7.cint)
  result.sendFailed = v[0]
  result.dgramOutDropped = v[1]
  result.dgramInDropped = v[2]
  result.connRefused = v[3]
  result.cidDropped = v[4]
  result.reqDropped = v[5]
  result.truncated = v[6]

proc anyDrops*(s: QuicStats): bool =
  ## True if the shim dropped anything at all — a one-line health check.
  s.sendFailed > 0'u64 or s.dgramOutDropped > 0'u64 or
    s.dgramInDropped > 0'u64 or s.connRefused > 0'u64 or
    s.cidDropped > 0'u64 or s.reqDropped > 0'u64 or s.truncated > 0'u64

proc connToken*(c: QuicCtx): int =
  ## The first live connection's token. A client has exactly one connection, so
  ## this is how a client names it for the WebTransport stream API; -1 if none.
  int(aqConnToken(c))

# ---- WebTransport streams (reliable, ordered — bidi and uni) ----------------
type WtStream* = object
  ok*: bool
  connToken*: uint64
  id*: int64            ## the QUIC stream id
  uni*: bool            ## unidirectional (receive-only for the accepting peer)

proc wtOpenStream*(c: QuicCtx; connToken: uint64; uni = false): int64 =
  ## Open a WebTransport stream on an established session. Returns the stream id,
  ## or -1 if the session is not established / no stream credit is available.
  ## The `WEBTRANSPORT_STREAM` signal prefix is written for you.
  aqWtOpenStream(c, connToken, if uni: 1.cint else: 0.cint)

proc wtTakeStream*(c: QuicCtx): WtStream =
  ## Pull one newly-accepted incoming WebTransport stream (`ok = false` if none).
  result = default(WtStream)
  var tok = 0'u64
  var sid = 0'i64
  var uni = 0.cint
  if aqWtTakeStream(c, addr tok, addr sid, addr uni) == 1.cint:
    result.ok = true
    result.connToken = tok
    result.id = sid
    result.uni = uni == 1.cint

proc wtStreamSend*(c: QuicCtx; connToken: uint64; streamId: int64;
                   data: string; fin = false) =
  ## Append `data` to a WebTransport stream (sent on the next flush). `fin`
  ## half-closes the sending side once the buffered payload has gone out.
  if data.len == 0:
    if fin:
      discard aqWtStreamSend(c, connToken, streamId, cast[ptr char](0), 0.cint,
                             1.cint)
    return
  var buf = newSeq[char](data.len)
  var i = 0
  while i < data.len:
    buf[i] = data[i]
    inc i
  discard aqWtStreamSend(c, connToken, streamId, addr buf[0], cint(buf.len),
                         if fin: 1.cint else: 0.cint)

proc wtStreamRecv*(c: QuicCtx; connToken: uint64; streamId: int64;
                   maxLen = 65536): string =
  ## Read whatever payload has arrived on a WebTransport stream ("" if none).
  var buf = newSeq[char](maxLen)
  let n = aqWtStreamRecv(c, connToken, streamId, addr buf[0], cint(maxLen))
  result = ""
  var i = 0
  while i < n:
    result.add buf[i]
    inc i

proc wtStreamFin*(c: QuicCtx; connToken: uint64; streamId: int64): bool =
  ## True once the peer has finished the stream AND everything it sent has been
  ## read out by `wtStreamRecv`.
  aqWtStreamFin(c, connToken, streamId) == 1.cint

proc wtSendDatagram*(c: QuicCtx; connToken: uint64; data: string) =
  ## Send a WebTransport datagram on a server session (identified by the
  ## `connToken` from a received `Datagram`).
  if data.len == 0: return
  var buf = newSeq[char](data.len)
  var i = 0
  while i < data.len:
    buf[i] = data[i]
    inc i
  discard aqWtSendDatagram(c, connToken, addr buf[0], cint(buf.len))
