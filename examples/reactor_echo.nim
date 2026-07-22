## reactor_echo — a single-threaded, epoll-multiplexed TCP echo server built on
## the reactor. One OS thread serves many concurrent connections cooperatively:
## every connection is a passive `echoConn` coroutine parked on socket readiness.
##
## Build: nimony c (with the net-stack --path set)   Run: bin/reactor_echo [port]

import std/[syncio, cmdline, strutils]
import serve/reactor
import serve/asyncio
import tcp

proc echoConn(r: Reactor; fd: cint) {.passive.} =
  ## Echo everything until the peer closes. One flat coroutine; the await*
  ## templates inline their suspend loops here so all suspend points live in
  ## this coroutine.
  var buf = default(array[4096, char])
  while true:
    var n = 0
    r.awaitRead(fd, addr buf[0], 4096, n)
    if n <= 0:
      break
    var ok = false
    r.awaitWriteAll(fd, addr buf[0], n, ok)
    if not ok:
      break
  r.unregister(fd)
  closeTcp(fd)

proc acceptLoop(r: Reactor; listenFd: cint) {.passive.} =
  ## Accept connections forever, spawning an echoConn coroutine for each. When
  ## a spawned coroutine parks, `spawn`'s drive returns here to accept the next;
  ## when there is nothing to accept, this parks on the listener.
  while true:
    var fd = InvalidTcpHandle
    r.awaitAccept(listenFd, fd)
    if not isValidTcp(fd):
      break
    discard setTcpNonBlocking(fd)
    r.register(fd)
    r.spawn(delay(echoConn(r, fd)))   # launch as an independent coroutine

proc main() =
  var port = 8099
  if paramCount() >= 1:
    try: port = parseInt(paramStr(1))
    except: port = 8099
  let listenFd = listenTcp(port)
  if not isValidTcp(listenFd):
    echo "listen failed on port ", port
    quit(1)
  discard setTcpNonBlocking(listenFd)
  let r = newReactor()
  r.register(listenFd)
  echo "reactor echo server: one thread, epoll, port ", port
  r.spawn(delay(acceptLoop(r, listenFd)))  # start the acceptor coroutine
  r.run()                                  # drive epoll: the whole server, one thread

main()
