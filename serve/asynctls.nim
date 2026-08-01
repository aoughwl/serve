## serve/asynctls.nim — suspendable TLS I/O over the reactor, as TEMPLATES.
##
## The plaintext counterpart is `asyncio.nim`, and the same rule applies: these
## are templates so the `delay()`/`suspend()` pair is inlined into the calling
## coroutine rather than living in a passive proc the coroutine calls (see
## asyncio.nim / REACTOR.md for why that distinction is load-bearing).
##
## The TLS layer already speaks the language the reactor needs: on a
## non-blocking socket, `handshake` / `tlsReadInto` / `tlsWriteFrom` return
## `tlsWantRead` or `tlsWantWrite` instead of blocking, which maps exactly onto
## parking against EPOLLIN or EPOLLOUT. Note that the direction is the *TLS
## layer's* choice, not the operation's: a read can want writability (a TLS 1.3
## key update or a renegotiation mid-read) and a write can want readability, so
## each of these parks on whichever the status names — never on the direction
## you would guess from the call.

import tcp
import tls
import ./reactor
import tcp/epoll as ep

template awaitTlsHandshake*(r: Reactor; t: var TlsSocket; fd: cint; okOut: var bool) =
  ## Drive the TLS handshake to completion, suspending as it asks. `okOut` is
  ## false if the peer went away or the handshake failed.
  var done = false
  okOut = false
  while not done:
    let st = handshake(t)
    if st == tlsOk:
      okOut = true
      done = true
    elif st == tlsWantRead:
      let k = delay()
      r.park(fd, ep.EPOLLIN, k)
      suspend()
    elif st == tlsWantWrite:
      let k = delay()
      r.park(fd, ep.EPOLLOUT, k)
      suspend()
    else:
      done = true

template awaitTlsRead*(r: Reactor; t: var TlsSocket; fd: cint; buf: pointer;
                       n: int; got: var int) =
  ## Read up to `n` bytes of plaintext, suspending until TLS can make progress.
  ## `got` is >0 (bytes), 0 (clean close_notify / EOF) or -1 (error).
  var done = false
  got = 0
  while not done:
    var st = tlsOk
    let r0 = tlsReadInto(t, buf, n, st)
    if r0 > 0:
      got = r0
      done = true
    elif st == tlsWantRead:
      let k = delay()
      r.park(fd, ep.EPOLLIN, k)
      suspend()
    elif st == tlsWantWrite:
      let k = delay()
      r.park(fd, ep.EPOLLOUT, k)
      suspend()
    elif st == tlsClosed:
      got = 0
      done = true
    else:
      got = -1
      done = true

template awaitTlsWriteAll*(r: Reactor; t: var TlsSocket; fd: cint; buf: pointer;
                           n: int; okOut: var bool) =
  ## Write all `n` bytes, suspending as TLS asks. Loop exit is flag-based: a
  ## `break` in the same branch as a `suspend` breaks the coroutine transform.
  var off = 0
  var failed = false
  okOut = true
  while off < n and not failed:
    var st = tlsOk
    let p = cast[pointer](cast[uint](buf) + uint(off))
    let w = tlsWriteFrom(t, p, n - off, st)
    if w > 0:
      off = off + w
    elif st == tlsWantRead:
      let k = delay()
      r.park(fd, ep.EPOLLIN, k)
      suspend()
    elif st == tlsWantWrite:
      let k = delay()
      r.park(fd, ep.EPOLLOUT, k)
      suspend()
    else:
      failed = true
  if failed:
    okOut = false
