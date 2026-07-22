## RFC 9221 QUIC datagram round-trip, driven entirely from nimony: a server and a
## client context sharing one epoll loop. The client sends an unreliable
## datagram; the server echoes it back on the same connection; the client prints
## the echo. Proves the datagram bindings end to end.
##   LD_LIBRARY_PATH=<serve>/quic bin/dgram_echo 8490 cert.pem key.pem

import std/[cmdline, strutils, syncio]
import tcp/epoll as ep
import quic/quic

var port = 8490
var cert = "cert.pem"
var key = "key.pem"
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8490
if paramCount() >= 2: cert = paramStr(2)
if paramCount() >= 3: key = paramStr(3)

let srv = quicServer("127.0.0.1", port, cert, key)
let cli = quicClient("127.0.0.1", port, "localhost", "/")
if srv == nil or cli == nil:
  echo "setup failed"
  quit(1)
discard clientStart(cli)
clientSendDatagram(cli, "ping-datagram")     # queued until the handshake carries it

let epfd = ep.epollCreate()
ep.epollAdd(epfd, cint(fd(srv)), ep.EPOLLIN)
ep.epollAdd(epfd, cint(fd(cli)), ep.EPOLLIN)
var evs = ep.newEventBuf(8)
var iter = 0
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
  let sd = takeDatagram(srv)
  if sd.ok:
    sendDatagram(srv, sd.connToken, sd.data)   # echo to origin connection
  let cd = takeDatagram(cli)
  if cd.ok:
    echo "DGRAM_ECHO=", cd.data
    done = true
  discard flush(srv)
  discard flush(cli)
  inc iter

if not done:
  echo "TIMEOUT: no datagram echo"
freeCtx(srv)
freeCtx(cli)
