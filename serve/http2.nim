## serve/http2.nim — an HTTP/2 server over libnghttp2 (`libnghttp2.so.14`).
##
## nghttp2 is a callback-driven codec: we feed received bytes to
## `nghttp2_session_mem_recv` (which fires our callbacks as it parses frames)
## and drain produced bytes from `nghttp2_session_mem_send`. Per-stream request
## state (`:method`, `:path`, headers, body) is accumulated across callbacks; on
## END_STREAM the stream's `Request` is handed to the same `proc(req): Response`
## handler shape the rest of `serve` uses, and the `Response` is submitted with a
## data provider that streams its body back.
##
## This module is opt-in (`import serve/http2`) so plain `serve` users don't pull
## the nghttp2 dependency. It speaks **h2c** (cleartext, prior-knowledge); the
## same session driver works over TLS once ALPN negotiates "h2".
##
## No nghttp2 headers are installed, so structs are laid out by hand to match the
## C ABI (verified against the shared library at runtime).

import std/syncio
import http/headers
import http/request
import http/response
import tcp
import net
import tls

const nghttp2Lib = "libnghttp2.so.14"

type
  H2Handler* = proc(req: Request): Response {.nimcall.}
    ## HTTP/2 request handler — a bare function pointer (called from C callbacks,
    ## so not a closure). Per-request state lives in the parsed `Request`.

# --- ABI structs (must match nghttp2.h layout on LP64) -----------------------

type
  Nghttp2Nv = object
    name: nil pointer       # uint8_t*
    value: nil pointer      # uint8_t*
    namelen: csize_t
    valuelen: csize_t
    flags: uint8

  Nghttp2SettingsEntry = object
    settingsId: int32
    value: uint32

  Nghttp2DataProvider = object
    source: nil pointer     # union { int fd; void* ptr } — unused, 0
    readCallback: nil pointer

# --- FFI ---------------------------------------------------------------------

proc nghttp2_session_callbacks_new(cbs: ptr pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_del(cbs: nil pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_frame_recv_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_header_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_begin_headers_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_stream_close_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_server_new(session: ptr pointer; cbs: pointer; userData: pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_del(session: nil pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_mem_recv(session: nil pointer; data: pointer; len: csize_t): int {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_mem_send(session: nil pointer; dataPtr: ptr pointer): int {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_submit_settings(session: nil pointer; flags: uint8; iv: pointer; niv: csize_t): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_submit_response(session: nil pointer; streamId: int32; nva: pointer; nvlen: csize_t; dataPrd: pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_want_read(session: nil pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_want_write(session: nil pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}

# --- constants ---------------------------------------------------------------

const
  NGHTTP2_FLAG_END_STREAM = 0x01'u8
  FRAME_TYPE_DATA = 0'u8
  FRAME_TYPE_HEADERS = 1'u8
  NGHTTP2_DATA_FLAG_EOF = 0x01'u32
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 3'i32

# --- per-connection session state --------------------------------------------

type
  H2Stream = object
    id: int32
    used: bool
    meth: string
    path: string
    scheme: string
    authority: string
    reqHeaders: string   # accumulated "name: value\r\n" for the handler request
    body: string
    respBody: string
    respOffset: int
    responded: bool

  H2Session = object
    session: nil pointer
    handler: H2Handler
    streams: array[64, H2Stream]

proc findStream(s: var H2Session; id: int32): int =
  var i = 0
  while i < s.streams.len:
    if s.streams[i].used and s.streams[i].id == id:
      return i
    inc i
  return -1

proc allocStream(s: var H2Session; id: int32): int =
  var i = 0
  while i < s.streams.len:
    if not s.streams[i].used:
      s.streams[i] = H2Stream(id: id, used: true, meth: "", path: "", scheme: "",
                              authority: "", reqHeaders: "", body: "",
                              respBody: "", respOffset: 0, responded: false)
      return i
    inc i
  return -1

# --- frame header field reads (nghttp2_frame_hd at offset 0 of nghttp2_frame) --

proc frameStreamId(frame: pointer): int32 =
  cast[ptr int32](cast[uint](frame) + 8'u)[]

proc frameType(frame: pointer): uint8 =
  cast[ptr uint8](cast[uint](frame) + 12'u)[]

proc frameFlags(frame: pointer): uint8 =
  cast[ptr uint8](cast[uint](frame) + 13'u)[]

proc ptrToStr(p: pointer; n: int): string =
  result = ""
  if p == nil or n <= 0: return
  let a = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    result.add a[i]
    inc i

# --- callbacks (cdecl, dispatched via user_data → H2Session) ------------------

proc onBeginHeaders(session: nil pointer; frame: pointer; userData: pointer): cint {.cdecl.} =
  if frameType(frame) == FRAME_TYPE_HEADERS:
    let s = cast[ptr H2Session](userData)
    discard allocStream(s[], frameStreamId(frame))
  0

proc onHeader(session: nil pointer; frame: pointer; name: pointer; namelen: csize_t;
              value: pointer; valuelen: csize_t; flags: uint8; userData: pointer): cint {.cdecl.} =
  let s = cast[ptr H2Session](userData)
  let idx = findStream(s[], frameStreamId(frame))
  if idx < 0: return 0
  let nm = ptrToStr(name, int(namelen))
  let vl = ptrToStr(value, int(valuelen))
  if nm == ":method": s[].streams[idx].meth = vl
  elif nm == ":path": s[].streams[idx].path = vl
  elif nm == ":scheme": s[].streams[idx].scheme = vl
  elif nm == ":authority": s[].streams[idx].authority = vl
  elif nm.len > 0 and nm[0] != ':':
    s[].streams[idx].reqHeaders.add nm
    s[].streams[idx].reqHeaders.add ": "
    s[].streams[idx].reqHeaders.add vl
    s[].streams[idx].reqHeaders.add "\r\n"
  0

proc onDataChunk(session: nil pointer; flags: uint8; streamId: int32; data: pointer;
                 len: csize_t; userData: pointer): cint {.cdecl.} =
  let s = cast[ptr H2Session](userData)
  let idx = findStream(s[], streamId)
  if idx >= 0:
    s[].streams[idx].body.add ptrToStr(data, int(len))
  0

proc dataReadCallback(session: nil pointer; streamId: int32; buf: pointer; length: csize_t;
                      dataFlags: ptr uint32; source: pointer; userData: pointer): int {.cdecl.} =
  ## Copy up to `length` bytes of the staged response body into `buf`, flagging
  ## EOF when drained.
  let s = cast[ptr H2Session](userData)
  let idx = findStream(s[], streamId)
  if idx < 0:
    dataFlags[] = dataFlags[] or NGHTTP2_DATA_FLAG_EOF
    return 0
  let remaining = s[].streams[idx].respBody.len - s[].streams[idx].respOffset
  var n = remaining
  if n > int(length): n = int(length)
  let dst = cast[ptr UncheckedArray[char]](buf)
  var i = 0
  while i < n:
    dst[i] = s[].streams[idx].respBody[s[].streams[idx].respOffset + i]
    inc i
  s[].streams[idx].respOffset = s[].streams[idx].respOffset + n
  if s[].streams[idx].respOffset >= s[].streams[idx].respBody.len:
    dataFlags[] = dataFlags[] or NGHTTP2_DATA_FLAG_EOF
  n

proc lowerAscii(s: string): string =
  result = ""
  var i = 0
  while i < s.len:
    var c = s[i]
    if c >= 'A' and c <= 'Z': c = chr(ord(c) + 32)
    result.add c
    inc i

proc appendInt(s: var string; v: int) =
  if v == 0:
    s.add '0'
    return
  var n = v
  var digits = default(array[24, char])
  var c = 0
  while n > 0:
    digits[c] = char(ord('0') + (n mod 10))
    n = n div 10
    inc c
  var i = c - 1
  while i >= 0:
    s.add digits[i]
    dec i

proc submitResponseFor(s: var H2Session; idx: int) =
  ## Build the `Request`, call the handler, and submit the `Response` headers +
  ## a body data provider for stream `idx`.
  if s.streams[idx].responded: return
  s.streams[idx].responded = true

  # Reconstruct an HTTP/1.1-style raw request so the shared parser can build it.
  var raw = ""
  var m = s.streams[idx].meth
  if m.len == 0: m = "GET"
  var p = s.streams[idx].path
  if p.len == 0: p = "/"
  raw.add m
  raw.add ' '
  raw.add p
  raw.add " HTTP/2\r\n"
  if s.streams[idx].authority.len > 0:
    raw.add "Host: "
    raw.add s.streams[idx].authority
    raw.add "\r\n"
  raw.add s.streams[idx].reqHeaders
  raw.add "\r\n"
  raw.add s.streams[idx].body
  let req = parseRequest(raw)

  var resp = s.handler(req)
  s.streams[idx].respBody = resp.body

  # Build response header list. :status first, then the response's own headers.
  var names = default(array[40, string])
  var values = default(array[40, string])
  var nv = default(array[40, Nghttp2Nv])
  var count = 0
  var statusStr = ""
  appendInt(statusStr, resp.status)
  names[0] = ":status"
  values[0] = statusStr
  count = 1
  var hi = 0
  while hi < resp.headers.len and count < names.len:
    names[count] = lowerAscii(resp.headers[hi].name)
    values[count] = resp.headers[hi].value
    inc count
    inc hi

  var k = 0
  while k < count:
    nv[k] = Nghttp2Nv(name: cast[pointer](toCString(names[k])),
                      value: cast[pointer](toCString(values[k])),
                      namelen: csize_t(names[k].len),
                      valuelen: csize_t(values[k].len),
                      flags: 0'u8)
    inc k

  var prd = Nghttp2DataProvider(source: nil, readCallback: dataReadCallback)
  discard nghttp2_submit_response(s.session, s.streams[idx].id, addr nv[0],
                                  csize_t(count), addr prd)

proc onFrameRecv(session: nil pointer; frame: pointer; userData: pointer): cint {.cdecl.} =
  let ft = frameType(frame)
  if (ft == FRAME_TYPE_HEADERS or ft == FRAME_TYPE_DATA) and
     (frameFlags(frame) and NGHTTP2_FLAG_END_STREAM) != 0'u8:
    let s = cast[ptr H2Session](userData)
    let idx = findStream(s[], frameStreamId(frame))
    if idx >= 0:
      submitResponseFor(s[], idx)
  0

proc onStreamClose(session: nil pointer; streamId: int32; errorCode: uint32;
                   userData: pointer): cint {.cdecl.} =
  let s = cast[ptr H2Session](userData)
  let idx = findStream(s[], streamId)
  if idx >= 0:
    s[].streams[idx].used = false
  0

# --- transport (plaintext fd / TLS) + driver ---------------------------------

type
  H2Transport = object
    isTls: bool
    fd: TcpHandle
    tls: TlsSocket

proc h2Read(t: var H2Transport; buf: pointer; n: int): int =
  if t.isTls:
    var st = tlsOk
    return tlsReadInto(t.tls, buf, n, st)
  return readTcp(t.fd, buf, n)

proc h2WriteAll(t: var H2Transport; buf: pointer; n: int): bool =
  if not t.isTls:
    return writeAllTcp(t.fd, buf, n) == n
  var total = 0
  var st = tlsOk
  while total < n:
    let p = cast[pointer](cast[uint](buf) + uint(total))
    let w = tlsWriteFrom(t.tls, p, n - total, st)
    if w <= 0:
      return false
    total = total + w
  return true

proc h2Close(t: var H2Transport) =
  if t.isTls:
    t.tls.closeTls()
  else:
    closeTcp(t.fd)

proc flushSend(s: var H2Session; t: var H2Transport): bool =
  ## Drain all queued output frames to the transport.
  while nghttp2_session_want_write(s.session) != 0:
    var dataPtr = cast[pointer](0)
    let n = nghttp2_session_mem_send(s.session, addr dataPtr)
    if n < 0:
      return false
    if n == 0:
      break
    if not h2WriteAll(t, dataPtr, int(n)):
      return false
  return true

proc runH2(t: var H2Transport; handler: H2Handler) =
  ## Drive one HTTP/2 connection over `t` (plaintext or TLS) to completion.
  var cbsPtr = cast[pointer](0)
  if nghttp2_session_callbacks_new(addr cbsPtr) != 0:
    h2Close(t)
    return
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbsPtr, onBeginHeaders)
  nghttp2_session_callbacks_set_on_header_callback(cbsPtr, onHeader)
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbsPtr, onFrameRecv)
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbsPtr, onDataChunk)
  nghttp2_session_callbacks_set_on_stream_close_callback(cbsPtr, onStreamClose)

  var state = H2Session(session: nil, handler: handler,
                        streams: default(array[64, H2Stream]))
  var sessionPtr = cast[pointer](0)
  if nghttp2_session_server_new(addr sessionPtr, cbsPtr, addr state) != 0:
    nghttp2_session_callbacks_del(cbsPtr)
    h2Close(t)
    return
  state.session = sessionPtr
  nghttp2_session_callbacks_del(cbsPtr)

  # Server connection preface: an initial SETTINGS frame.
  var iv = default(array[1, Nghttp2SettingsEntry])
  iv[0] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, value: 100'u32)
  discard nghttp2_submit_settings(state.session, 0'u8, addr iv[0], csize_t(1))
  discard flushSend(state, t)

  var buf = default(array[16384, char])
  var alive = true
  while alive:
    if not flushSend(state, t):
      break
    if nghttp2_session_want_read(state.session) == 0 and
       nghttp2_session_want_write(state.session) == 0:
      break
    let got = h2Read(t, addr buf[0], buf.len)
    if got <= 0:
      break
    let consumed = nghttp2_session_mem_recv(state.session, addr buf[0], csize_t(got))
    if consumed < 0:
      break
    if not flushSend(state, t):
      break

  nghttp2_session_del(state.session)
  h2Close(t)

proc serveHttp2Connection*(fd: TcpHandle; handler: H2Handler) =
  ## Drive one h2c (cleartext, prior-knowledge) connection to completion.
  var t = H2Transport(isTls: false, fd: fd,
                      tls: TlsSocket(socket: invalidSocket(), ssl: nil, handshakeDone: false))
  runH2(t, handler)

proc serveHttp2ConnectionTls*(tlsSock: TlsSocket; handler: H2Handler) =
  ## Drive one HTTP/2-over-TLS connection (ALPN "h2" already negotiated).
  var t = H2Transport(isTls: true, fd: tlsSock.socket.handle, tls: tlsSock)
  runH2(t, handler)

proc serveHttp2*(port: int; handler: H2Handler; maxRequests = 0) =
  ## Run an h2c (HTTP/2 cleartext) server on `port`. Test with
  ## `curl --http2-prior-knowledge http://host:port/`.
  initTcp()
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    shutdownTcp()
    return
  echo "serving HTTP/2 (h2c) on :", port
  var served = 0
  while maxRequests == 0 or served < maxRequests:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      serveHttp2Connection(clientFd, handler)
      inc served
  closeTcp(l)
  shutdownTcp()

proc serveHttp2Tls*(port: int; certFile: string; keyFile: string;
                    handler: H2Handler; maxRequests = 0) =
  ## Run HTTP/2 over TLS on `port`, advertising ALPN "h2". Each connection whose
  ## ALPN negotiates "h2" is driven by the nghttp2 session; a connection that
  ## does not negotiate h2 is dropped (this entry point is h2-only). This is the
  ## path real browsers use.
  initTcp()
  var ctx = newTlsServerContext(certFile, keyFile)
  if not ctx.isValid:
    echo "failed to load TLS cert/key: ", lastTlsError()
    shutdownTcp()
    return
  discard ctx.setAlpnServer(@["h2", "http/1.1"])
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    freeContext(ctx)
    shutdownTcp()
    return
  echo "serving HTTP/2 (h2, TLS) on :", port
  var served = 0
  while maxRequests == 0 or served < maxRequests:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      var sock = Socket(handle: clientFd)
      var tsock = wrapServer(ctx, sock)
      if tsock.handshakeDone and tsock.negotiatedAlpn() == "h2":
        serveHttp2ConnectionTls(tsock, handler)
      else:
        tsock.closeTls()
      inc served
  freeContext(ctx)
  closeTcp(l)
  shutdownTcp()
