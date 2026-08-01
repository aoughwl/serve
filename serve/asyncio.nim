## serve/asyncio.nim — suspendable socket I/O over the reactor, as TEMPLATES.
##
## These are templates, not procs, on purpose. A passive proc that suspends and
## is called from inside another coroutine's loop triggers a coroutine-transform
## defect in the current compiler (the caller busy-loops or the frame is double
## freed). Templates instead inline their read/accept/write loop — with its
## `delay()`/`suspend()` — directly into the calling coroutine, which is the
## shape the transform handles correctly: one flat coroutine that owns its own
## suspend points. See reactor.nim for the scheduler these park against.
##
## Each template attempts a nonblocking syscall via the tcp layer and, on the
## EAGAIN/EWOULDBLOCK condition, parks the calling coroutine against the fd and
## `suspend()`s; the reactor resumes it when epoll reports readiness.

import tcp
import ./reactor
import tcp/epoll as ep

template awaitAccept*(r: Reactor; listenFd: cint; fdOut: var TcpHandle) =
  ## Accept one connection into `fdOut` (a `TcpHandle` var), suspending until
  ## the listener is readable. `fdOut` is `InvalidTcpHandle` on a hard error.
  var done = false
  while not done:
    fdOut = acceptTcp(listenFd)
    if isValidTcp(fdOut):
      done = true
    else:
      if not tcpErrorWouldRetry(lastTcpErrorCode()):
        fdOut = InvalidTcpHandle
        done = true
      else:
        let k = delay()
        r.park(listenFd, ep.EPOLLIN, k)
        suspend()

template awaitReadableFor*(r: Reactor; fd: cint; ms: int; timedOut: var bool) =
  ## Suspend until `fd` is readable, or until `ms` milliseconds pass — whichever
  ## comes first; `timedOut` says which. No I/O is attempted: this is the wait
  ## itself, for a protocol that has its own timers to service (QUIC's loss and
  ## idle timers, a heartbeat) and must be woken whether or not a packet came.
  ## `ms <= 0` waits indefinitely.
  timedOut = false
  let k = delay()
  r.park(fd, ep.EPOLLIN, k)
  r.setResumeDeadline(fd, ms)   # after park: park arms the idle deadline, same slot
  suspend()
  timedOut = r.takeExpired(fd)

template awaitRead*(r: Reactor; fd: cint; buf: pointer; n: int; got: var int) =
  ## Read up to `n` bytes into `buf`, suspending until readable. `got` is set to
  ## >0 (bytes), 0 (orderly EOF), or -1 (hard error).
  var done = false
  while not done:
    got = readTcp(fd, buf, n)
    if got != -1:
      done = true
    else:
      if not tcpErrorWouldRetry(lastTcpErrorCode()):
        done = true
      else:
        let k = delay()
        r.park(fd, ep.EPOLLIN, k)
        suspend()

template awaitWriteAll*(r: Reactor; fd: cint; buf: pointer; n: int; okOut: var bool) =
  ## Write all `n` bytes from `buf`, suspending on a full send buffer. `okOut` is
  ## false on a hard error or peer close.
  ##
  ## Loop exit is via a `failed` flag rather than `break`: a `break` living in
  ## the same branch as a `suspend` crashes the coroutine transform, so the loop
  ## condition carries the exit instead.
  var off = 0
  var failed = false
  okOut = true
  while off < n and not failed:
    let wrote = writeTcp(fd, cast[pointer](cast[uint](buf) + uint(off)), n - off)
    if wrote > 0:
      off = off + wrote
    else:
      if wrote == 0:
        failed = true
      else:
        if not tcpErrorWouldRetry(lastTcpErrorCode()):
          failed = true
        else:
          let k = delay()
          r.park(fd, ep.EPOLLOUT, k)
          suspend()
  if failed:
    okOut = false
