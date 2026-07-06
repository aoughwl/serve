## serve/tcp_ioring.aowl — ioring-backed TCP primitives.
##
## This is a backend module. Higher layers should import `serve/tcp`, not this
## file directly.

import std/ioring

type
  TcpOp* = enum
    tcpRead, tcpWrite, tcpAccept

  TcpCompletion* = object
    op*: TcpOp
    fd*: cint
    result*: int

proc initTcp*() =
  initPool()
  initIoRing()

proc shutdownTcp*() =
  shutdownPool()

proc listenTcpPort*(port: int; backlog = 128): cint =
  listenTcp(uint16(port), backlog)

proc closeTcp*(fd: cint) =
  closeFd(fd)

proc setTcpNonBlocking*(fd: cint) =
  setNonBlocking(fd)

proc submitTcpAccept*(listenFd: cint) =
  discard submitAccept(listenFd)

proc submitTcpRead*(fd: cint; buf: pointer; len: int) =
  discard submitRead(fd, buf, len)

proc submitTcpWrite*(fd: cint; buf: pointer; len: int) =
  discard submitWrite(fd, buf, len)

proc waitTcpCompletions*(comps: var openArray[TcpCompletion]): int =
  var raw = default(array[16, IoCompletion])
  let n = waitCompletions(raw)
  var i = 0
  while i < n and i < comps.len:
    case raw[i].op
    of opAccept:
      comps[i].op = tcpAccept
    of opRead:
      comps[i].op = tcpRead
    of opWrite:
      comps[i].op = tcpWrite
    comps[i].fd = raw[i].fd
    comps[i].result = raw[i].result
    inc i
  result = i
