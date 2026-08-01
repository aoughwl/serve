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
proc nghttp2_session_callbacks_set_on_begin_frame_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_stream_close_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs: nil pointer; cb: pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_server_new(session: ptr pointer; cbs: pointer; userData: pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_del(session: nil pointer) {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_mem_recv(session: nil pointer; data: pointer; len: csize_t): int {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_mem_send(session: nil pointer; dataPtr: ptr pointer): int {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_submit_settings(session: nil pointer; flags: uint8; iv: pointer; niv: csize_t): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_submit_response(session: nil pointer; streamId: int32; nva: pointer; nvlen: csize_t; dataPrd: pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_want_read(session: nil pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_terminate_session(session: nil pointer; errorCode: uint32): cint {.cdecl, importc, dynlib: nghttp2Lib.}
proc nghttp2_session_want_write(session: nil pointer): cint {.cdecl, importc, dynlib: nghttp2Lib.}

# --- constants ---------------------------------------------------------------

const
  NGHTTP2_FLAG_END_STREAM = 0x01'u8
  FRAME_TYPE_DATA = 0'u8
  FRAME_TYPE_HEADERS = 1'u8
  NGHTTP2_DATA_FLAG_EOF = 0x01'u32
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 1'i32
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 3'i32
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 4'i32
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 5'i32
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 6'i32
  NGHTTP2_PROTOCOL_ERROR = 1'u32

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
    lastRecvStreamId: int32   ## highest client stream id accepted so far

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

proc onBeginFrame(session: nil pointer; hd: pointer; userData: pointer): cint {.cdecl.} =
  ## Fires for EVERY frame header, before nghttp2 decides what to do with it —
  ## which is the only place this check can live: a HEADERS naming an already
  ## used stream id never reaches `on_begin_headers`, nghttp2 discards it in
  ## silence and answers nothing.
  ##
  ## RFC 7540 §5.1.1: a HEADERS opening a stream whose identifier is not greater
  ## than every identifier received so far is a CONNECTION error of type
  ## PROTOCOL_ERROR. Terminating the session here queues the GOAWAY the peer is
  ## owed. Even-numbered ids are nghttp2's own business (it does flag those);
  ## a HEADERS on a stream we still hold open is trailers, not a new stream,
  ## hence the findStream guard.
  ##
  ## `nghttp2_frame_hd` has the same prefix layout as `nghttp2_frame`, so the
  ## frame-header accessors apply unchanged.
  if frameType(hd) == FRAME_TYPE_HEADERS:
    let s = cast[ptr H2Session](userData)
    let sid = frameStreamId(hd)
    if sid > 0'i32 and (sid and 1'i32) == 1'i32:
      if sid <= s[].lastRecvStreamId and findStream(s[], sid) < 0:
        discard nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR)
      elif sid > s[].lastRecvStreamId:
        s[].lastRecvStreamId = sid
  0

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

const MaxH2ResponseHeaders* = 128
  ## Response header slots per stream, `:status` included. Past this the
  ## response is refused rather than trimmed — see `submitResponseFor`.

var gH2HeaderOverflows = 0

proc h2HeaderOverflows*(): int =
  ## Responses refused because they carried more headers than a stream can
  ## submit. Counted rather than shrugged off: this used to trim silently.
  gH2HeaderOverflows

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

  # A response with more headers than a stream can carry used to be TRIMMED
  # here, silently: the 40th header onwards simply never went out. A dropped
  # `Set-Cookie` or `Location` is a wrong response, and a wrong response that
  # looks fine is worse than a refused one — so overflow is a 500, and counted.
  if resp.headers.len + 1 > MaxH2ResponseHeaders:
    inc gH2HeaderOverflows
    resp = response(500, "text/plain", "response header list too long\n")

  s.streams[idx].respBody = resp.body

  # Build response header list. :status first, then the response's own headers.
  var names = default(array[MaxH2ResponseHeaders, string])
  var values = default(array[MaxH2ResponseHeaders, string])
  var nv = default(array[MaxH2ResponseHeaders, Nghttp2Nv])
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

# --- transport-agnostic session seam -----------------------------------------
#
# nghttp2 is a pure codec — it never touches a socket — so the session can be
# driven by anything that can hand it bytes and take bytes back. The blocking
# driver below is one such caller; `serve/reactorh2.nim` is the other, and it
# suspends between the two halves instead of blocking.
#
# Sessions live in a fixed global table rather than on a coroutine's stack: the
# pointer handed to nghttp2 as `user_data` must stay valid for the life of the
# connection, and a global slot is address-stable where a coroutine local is
# not. The table size is therefore also the concurrent-connection bound, and an
# overflow is COUNTED (`h2RejectedConns`), never silently dropped.

const MaxH2Conns* = 128

type
  H2Settings* = object
    ## The SETTINGS this server announces in its connection preface. Until now
    ## exactly one was sent — MAX_CONCURRENT_STREAMS=100 — and the other four
    ## were whatever nghttp2 defaults to, unreachable. They are the knobs that
    ## decide how much memory one peer can make a server hold (window size ×
    ## streams) and how large a header block it will accept, so a deployment
    ## that cannot set them cannot be tuned or hardened.
    ##
    ## A field of 0 means "do not announce this one", leaving nghttp2's default
    ## in place — except `maxConcurrentStreams`, where 0 legitimately means
    ## "accept no new streams" and is therefore always announced.
    maxConcurrentStreams*: uint32   ## default 100
    initialWindowSize*: uint32      ## per-stream flow-control window; 0 = leave (64 KiB - 1)
    maxFrameSize*: uint32           ## 0 = leave (16 KiB); valid range 16 KiB..16 MiB - 1
    headerTableSize*: uint32        ## HPACK dynamic table; 0 = leave (4 KiB)
    maxHeaderListSize*: uint32      ## 0 = leave (unbounded, which is a choice worth revisiting)

proc defaultH2Settings*(): H2Settings =
  H2Settings(maxConcurrentStreams: 100'u32, initialWindowSize: 0'u32,
             maxFrameSize: 0'u32, headerTableSize: 0'u32,
             maxHeaderListSize: 0'u32)

var gH2Settings = defaultH2Settings()

proc setH2Settings*(s: H2Settings) =
  ## Announce `s` on every subsequently opened HTTP/2 session.
  gH2Settings = s

proc h2Settings*(): H2Settings =
  gH2Settings

var gH2Sessions: array[MaxH2Conns, H2Session]
var gH2Used: array[MaxH2Conns, bool]
var gH2Rejected = 0

proc h2RejectedConns*(): int =
  ## Connections refused because the session table was full.
  gH2Rejected

proc h2OpenSession*(handler: H2Handler): int =
  ## Take a free session slot, install the callbacks, and queue the server
  ## connection preface (SETTINGS). Returns the slot, or -1 when the table is
  ## full or nghttp2 refuses to build the session.
  var slot = -1
  var i = 0
  while i < MaxH2Conns:
    if not gH2Used[i]:
      slot = i
      break
    inc i
  if slot < 0:
    inc gH2Rejected
    return -1

  var cbsPtr = cast[pointer](0)
  if nghttp2_session_callbacks_new(addr cbsPtr) != 0:
    return -1
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbsPtr, onBeginHeaders)
  nghttp2_session_callbacks_set_on_begin_frame_callback(cbsPtr, onBeginFrame)
  nghttp2_session_callbacks_set_on_header_callback(cbsPtr, onHeader)
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbsPtr, onFrameRecv)
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbsPtr, onDataChunk)
  nghttp2_session_callbacks_set_on_stream_close_callback(cbsPtr, onStreamClose)

  gH2Sessions[slot] = H2Session(session: nil, handler: handler,
                                streams: default(array[64, H2Stream]),
                                lastRecvStreamId: 0'i32)
  var sessionPtr = cast[pointer](0)
  if nghttp2_session_server_new(addr sessionPtr, cbsPtr, addr gH2Sessions[slot]) != 0:
    nghttp2_session_callbacks_del(cbsPtr)
    return -1
  gH2Sessions[slot].session = sessionPtr
  nghttp2_session_callbacks_del(cbsPtr)
  gH2Used[slot] = true

  var iv = default(array[5, Nghttp2SettingsEntry])
  var n = 0
  iv[n] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                               value: gH2Settings.maxConcurrentStreams)
  inc n
  if gH2Settings.initialWindowSize > 0'u32:
    iv[n] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                                 value: gH2Settings.initialWindowSize)
    inc n
  if gH2Settings.maxFrameSize > 0'u32:
    iv[n] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
                                 value: gH2Settings.maxFrameSize)
    inc n
  if gH2Settings.headerTableSize > 0'u32:
    iv[n] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
                                 value: gH2Settings.headerTableSize)
    inc n
  if gH2Settings.maxHeaderListSize > 0'u32:
    iv[n] = Nghttp2SettingsEntry(settingsId: NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
                                 value: gH2Settings.maxHeaderListSize)
    inc n
  discard nghttp2_submit_settings(gH2Sessions[slot].session, 0'u8, addr iv[0], csize_t(n))
  return slot

proc h2CloseSession*(slot: int) =
  ## Free the nghttp2 session and release the slot.
  if slot >= 0 and slot < MaxH2Conns and gH2Used[slot]:
    nghttp2_session_del(gH2Sessions[slot].session)
    gH2Sessions[slot].session = nil
    gH2Sessions[slot].streams = default(array[64, H2Stream])
    gH2Sessions[slot].lastRecvStreamId = 0'i32
    gH2Used[slot] = false

proc h2Feed*(slot: int; data: pointer; n: int): bool =
  ## Hand `n` received bytes to the session. False means a fatal codec error —
  ## a *protocol* violation is not fatal here: nghttp2 queues the GOAWAY or
  ## RST_STREAM and the caller must still drain the output before closing.
  ##
  ## `nghttp2_session_mem_recv` may consume LESS than it was given, so this
  ## loops until the buffer is drained. Feeding it once and discarding the
  ## remainder silently drops whole frames: that is what made h2spec's
  ## "stream identifier numerically smaller than previous" hang — the offending
  ## HEADERS sat in the tail of the same read that carried the valid one, was
  ## never parsed, and so never produced the GOAWAY it should have.
  if slot < 0 or slot >= MaxH2Conns or not gH2Used[slot]:
    return false
  var off = 0
  while off < n:
    let p = cast[pointer](cast[uint](data) + uint(off))
    let consumed = nghttp2_session_mem_recv(gH2Sessions[slot].session, p, csize_t(n - off))
    if consumed < 0:
      return false
    if consumed == 0:
      break            # session is paused (no callback of ours pauses it today)
    off = off + consumed
  return true

proc h2NextOut*(slot: int; outPtr: var pointer; outLen: var int): bool =
  ## Take the next queued output chunk. False = fatal session error. True with
  ## `outLen == 0` = nothing queued right now. The returned buffer belongs to
  ## nghttp2 and stays valid until the next call on this session, so a caller
  ## may suspend mid-write.
  outPtr = cast[pointer](0)
  outLen = 0
  if slot < 0 or slot >= MaxH2Conns or not gH2Used[slot]:
    return false
  if nghttp2_session_want_write(gH2Sessions[slot].session) == 0:
    return true
  var p = cast[pointer](0)
  let n = nghttp2_session_mem_send(gH2Sessions[slot].session, addr p)
  if n < 0:
    return false
  outPtr = p
  outLen = int(n)
  return true

proc h2Idle*(slot: int): bool =
  ## True once the session neither wants more input nor has output left — i.e.
  ## the connection is finished (including after a GOAWAY it just sent).
  if slot < 0 or slot >= MaxH2Conns or not gH2Used[slot]:
    return true
  return nghttp2_session_want_read(gH2Sessions[slot].session) == 0 and
         nghttp2_session_want_write(gH2Sessions[slot].session) == 0

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
  nghttp2_session_callbacks_set_on_begin_frame_callback(cbsPtr, onBeginFrame)
  nghttp2_session_callbacks_set_on_header_callback(cbsPtr, onHeader)
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbsPtr, onFrameRecv)
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbsPtr, onDataChunk)
  nghttp2_session_callbacks_set_on_stream_close_callback(cbsPtr, onStreamClose)

  var state = H2Session(session: nil, handler: handler,
                        streams: default(array[64, H2Stream]),
                        lastRecvStreamId: 0'i32)
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
    # mem_recv may consume less than it is given; feed the whole read or whole
    # frames are silently dropped (see h2Feed).
    var off = 0
    var recvErr = false
    while off < got and not recvErr:
      let p = cast[pointer](cast[uint](addr buf[0]) + uint(off))
      let consumed = nghttp2_session_mem_recv(state.session, p, csize_t(got - off))
      if consumed <= 0:
        recvErr = consumed < 0
        off = got
      else:
        off = off + consumed
    if recvErr:
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
  ##
  ## ONE CONNECTION AT A TIME: this loop drives a whole session to completion
  ## before accepting again, so a peer that opens a connection and keeps it open
  ## stops every other peer from being served. For anything facing more than one
  ## client use `serve/reactorh2.nim`'s `serveHttp2Reactor`, which multiplexes
  ## connections on the same thread.
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
