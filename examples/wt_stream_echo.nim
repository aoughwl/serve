## WebTransport STREAMS over HTTP/3, driven from nimony: a server and a client
## context on one epoll loop. Once the WebTransport session is established the
## client opens
##   * a bidirectional stream, sends a message and half-closes it — the server
##     reads it and echoes it back on the same stream;
##   * a unidirectional stream carrying a second message — the server reads it
##     and answers on a unidirectional stream of its own.
## Both are ordinary QUIC streams carrying the WEBTRANSPORT_STREAM signal, so
## they never touch the HTTP/3 layer. Requires a WebTransport-enabled shim
## (vendored nghttp3 >= 1.x — build with quic/build-nghttp3.sh then quic/build.sh).
##   LD_LIBRARY_PATH=<serve>/quic:<serve>/quic/vendor/lib bin/wt_stream_echo 8497 cert.pem key.pem

import std/[cmdline, strutils, syncio]
import tcp/epoll as ep
import quic/quic

var port = 8497
var cert = "cert.pem"
var key = "key.pem"
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8497
if paramCount() >= 2: cert = paramStr(2)
if paramCount() >= 3: key = paramStr(3)

let srv = quicServer("127.0.0.1", port, cert, key)
let cli = quicClient("127.0.0.1", port, "localhost", "/wt")
if srv == nil or cli == nil:
  echo "setup failed"
  quit(1)
clientWtConnect(cli)
discard clientStart(cli)

let epfd = ep.epollCreate()
ep.epollAdd(epfd, cint(fd(srv)), ep.EPOLLIN)
ep.epollAdd(epfd, cint(fd(cli)), ep.EPOLLIN)
var evs = ep.newEventBuf(8)

var iter = 0
var opened = false
var cliBidi = -1'i64
var cliUni = -1'i64
var cliTok = 0'u64
var gotBidiEcho = false
var gotUniAnswer = false
var srvUniSent = false
# what the server has accepted so far
var srvBidi = -1'i64
var srvUniIn = -1'i64
var srvTok = 0'u64
var srvBidiBuf = ""
var srvUniBuf = ""
var cliBidiBuf = ""
var cliUniBuf = ""
var cliUniIn = -1'i64

while (iter < 8000) and not (gotBidiEcho and gotUniAnswer):
  let n = ep.epollWait(epfd, evs, 5.cint)
  var i = 0
  while i < n:
    let f = ep.eventFd(evs, i)
    if f == cint(fd(srv)): discard processRead(srv)
    elif f == cint(fd(cli)): discard processRead(cli)
    inc i
  discard handleTimeout(srv)
  discard handleTimeout(cli)

  # ---- client: once the session is up, open the two streams ----------------
  if (not opened) and clientWtReady(cli):
    let t = connToken(cli)
    if t >= 0:
      cliTok = uint64(t)
      cliBidi = wtOpenStream(cli, cliTok, false)
      cliUni = wtOpenStream(cli, cliTok, true)
      if cliBidi >= 0'i64 and cliUni >= 0'i64:
        wtStreamSend(cli, cliTok, cliBidi, "wt-bidi-hello", true)
        wtStreamSend(cli, cliTok, cliUni, "wt-uni-hello", true)
        opened = true
        echo "WT_SESSION=established"

  # ---- server: accept incoming WebTransport streams ------------------------
  var acc = wtTakeStream(srv)
  while acc.ok:
    srvTok = acc.connToken
    if acc.uni: srvUniIn = acc.id
    else: srvBidi = acc.id
    acc = wtTakeStream(srv)

  if srvBidi >= 0'i64:
    srvBidiBuf.add wtStreamRecv(srv, srvTok, srvBidi)
    if wtStreamFin(srv, srvTok, srvBidi) and srvBidiBuf.len > 0:
      wtStreamSend(srv, srvTok, srvBidi, srvBidiBuf, true)   # echo on the same stream
      srvBidiBuf = ""
      srvBidi = -1'i64

  if srvUniIn >= 0'i64:
    srvUniBuf.add wtStreamRecv(srv, srvTok, srvUniIn)
    if wtStreamFin(srv, srvTok, srvUniIn) and srvUniBuf.len > 0 and not srvUniSent:
      let back = wtOpenStream(srv, srvTok, true)             # answer on our own uni
      if back >= 0'i64:
        wtStreamSend(srv, srvTok, back, "srv:" & srvUniBuf, true)
        srvUniSent = true
      srvUniBuf = ""
      srvUniIn = -1'i64

  # ---- client: read the bidi echo and the server's uni answer --------------
  if opened and not gotBidiEcho:
    cliBidiBuf.add wtStreamRecv(cli, cliTok, cliBidi)
    if cliBidiBuf == "wt-bidi-hello":
      echo "WT_BIDI_ECHO=", cliBidiBuf
      gotBidiEcho = true

  if opened and not gotUniAnswer:
    var acc2 = wtTakeStream(cli)          # the server's answering uni stream
    while acc2.ok:
      if acc2.uni: cliUniIn = acc2.id
      acc2 = wtTakeStream(cli)
    if cliUniIn >= 0'i64:
      cliUniBuf.add wtStreamRecv(cli, cliTok, cliUniIn)
      if cliUniBuf == "srv:wt-uni-hello":
        echo "WT_UNI_ANSWER=", cliUniBuf
        gotUniAnswer = true

  discard flush(srv)
  discard flush(cli)
  inc iter

if not (gotBidiEcho and gotUniAnswer):
  echo "TIMEOUT: bidi=", gotBidiEcho, " uni=", gotUniAnswer

# a clean run must not have dropped anything on either side
let ss = stats(srv)
let cs = stats(cli)
if anyDrops(ss) or anyDrops(cs):
  echo "QUIC_DROPS=yes send=", ss.sendFailed + cs.sendFailed,
       " dgram_out=", ss.dgramOutDropped + cs.dgramOutDropped,
       " dgram_in=", ss.dgramInDropped + cs.dgramInDropped,
       " conn=", ss.connRefused + cs.connRefused,
       " cid=", ss.cidDropped + cs.cidDropped,
       " req=", ss.reqDropped + cs.reqDropped,
       " trunc=", ss.truncated + cs.truncated
else:
  echo "QUIC_DROPS=none"
freeCtx(srv)
freeCtx(cli)
