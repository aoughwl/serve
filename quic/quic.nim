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
  var pbuf = default(array[512, char])
  let got = aqTakeRequest(c, addr id, addr mbuf[0], 16.cint, addr pbuf[0], 512.cint)
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
    while i < 512 and pbuf[i] != '\0':
      result.path.add pbuf[i]
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
