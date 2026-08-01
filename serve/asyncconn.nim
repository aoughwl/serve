## serve/asyncconn.nim — one connection type over plaintext OR TLS, so a
## reactor server needs a single coroutine rather than one per transport.
##
## `asyncio.nim` and `asynctls.nim` give the two transports' await primitives.
## Writing a server against either one directly means writing the whole
## connection coroutine twice — and since the primitives must be templates
## (they inline their own suspend points), there is no function to abstract
## over. `Conn` closes that gap the only way the coroutine transform allows: a
## runtime branch, with each arm inlining the primitive it needs.
##
## The dispatch costs a predictable branch per I/O; that is nothing next to the
## syscall it guards, and it buys one connection body instead of two.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp
import net
import tls
import ./reactor
import ./asyncio
import ./asynctls

type
  Conn* = object
    fd*: cint          ## the raw descriptor — what epoll and the timeouts use
    isTls*: bool
    tls*: TlsSocket    ## meaningful only when `isTls`

proc plainConn*(fd: cint): Conn =
  ## A cleartext connection over an accepted descriptor.
  Conn(fd: fd, isTls: false,
       tls: TlsSocket(socket: invalidSocket(), ssl: nil, handshakeDone: false))

proc tlsConn*(ctx: TlsContext; fd: cint): Conn =
  ## A TLS connection over an accepted descriptor. The descriptor must ALREADY
  ## be non-blocking: `wrapServer` starts the handshake, and on a blocking fd it
  ## would run all of it right here, on the reactor thread.
  Conn(fd: fd, isTls: true, tls: wrapServer(ctx, Socket(handle: fd)))

template awaitConnHandshake*(r: Reactor; c: var Conn; okOut: var bool) =
  ## Complete the TLS handshake, suspending as it asks. Trivially true for a
  ## cleartext connection.
  if c.isTls:
    r.awaitTlsHandshake(c.tls, c.fd, okOut)
  else:
    okOut = true

template awaitConnRead*(r: Reactor; c: var Conn; buf: pointer; n: int; got: var int) =
  ## Read up to `n` bytes: >0 bytes, 0 for a clean close, -1 on error.
  if c.isTls:
    r.awaitTlsRead(c.tls, c.fd, buf, n, got)
  else:
    r.awaitRead(c.fd, buf, n, got)

template awaitConnWriteAll*(r: Reactor; c: var Conn; buf: pointer; n: int; okOut: var bool) =
  ## Write all `n` bytes, suspending on backpressure.
  if c.isTls:
    r.awaitTlsWriteAll(c.tls, c.fd, buf, n, okOut)
  else:
    r.awaitWriteAll(c.fd, buf, n, okOut)

template closeConn*(r: Reactor; c: var Conn; buf: pointer; chunk: int; maxDrain: int) =
  ## Graceful teardown: close_notify (TLS), then FIN, then read away whatever
  ## the peer had already sent. A bare `close()` with unread bytes queued makes
  ## the kernel answer them with RST, which the peer sees instead of whatever
  ## final frame it was owed. `buf`/`chunk` is scratch space for the drain,
  ## bounded by `maxDrain` so a peer that keeps talking cannot pin the coroutine
  ## on its own data.
  if c.isTls:
    closeTls(c.tls, false)
  discard shutdownTcpWrite(c.fd)
  var drained = 0
  var draining = true
  while draining and drained < maxDrain:
    var got = 0
    r.awaitRead(c.fd, buf, chunk, got)   # raw bytes, discarded
    if got <= 0:
      draining = false
    else:
      drained = drained + got
  r.unregister(c.fd)
  closeTcp(c.fd)
