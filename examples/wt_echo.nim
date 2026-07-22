## WebTransport over HTTP/3, driven from nimony: a server and a client context on
## one epoll loop. The client opens a WebTransport session (extended CONNECT),
## sends a WT datagram; the server echoes it on the session; the client prints
## the echo. Requires a WebTransport-enabled shim (vendored nghttp3 >= 1.x —
## build with quic/build-nghttp3.sh then quic/build.sh).
##   LD_LIBRARY_PATH=<serve>/quic:<serve>/quic/vendor/lib bin/wt_echo 8494 cert.pem key.pem

import std/[cmdline, strutils, syncio]
import tcp/epoll as ep
import quic/quic

var port = 8494
var cert = "cert.pem"
var key = "key.pem"
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8494
if paramCount() >= 2: cert = paramStr(2)
if paramCount() >= 3: key = paramStr(3)

let srv = quicServer("127.0.0.1", port, cert, key)
let cli = quicClient("127.0.0.1", port, "localhost", "/wt")
if srv == nil or cli == nil:
  echo "setup failed"
  quit(1)
clientWtConnect(cli)              # open a WebTransport session, not a plain request
discard clientStart(cli)

let epfd = ep.epollCreate()
ep.epollAdd(epfd, cint(fd(srv)), ep.EPOLLIN)
ep.epollAdd(epfd, cint(fd(cli)), ep.EPOLLIN)
var evs = ep.newEventBuf(8)
var iter = 0
var sent = false
var done = false
while (iter < 5000) and (not done):
  let n = ep.epollWait(epfd, evs, 5.cint)
  var i = 0
  while i < n:
    let f = ep.eventFd(evs, i)
    if f == cint(fd(srv)): discard processRead(srv)
    elif f == cint(fd(cli)): discard processRead(cli)
    inc i
  discard handleTimeout(srv)
  discard handleTimeout(cli)

  if (not sent) and clientWtReady(cli):
    clientWtSendDatagram(cli, "wt-hello")
    sent = true
    echo "WT_SESSION=established"

  let sd = takeDatagram(srv)
  if sd.ok:
    wtSendDatagram(srv, sd.connToken, sd.data)     # echo on the WT session
  let cd = takeDatagram(cli)
  if cd.ok:
    echo "WT_DGRAM_ECHO=", cd.data
    done = true
  discard flush(srv)
  discard flush(cli)
  inc iter

if not done:
  echo "TIMEOUT: no WebTransport datagram echo"
freeCtx(srv)
freeCtx(cli)
