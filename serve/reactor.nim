## reactor — a single-threaded, epoll-driven cooperative scheduler for the
## aoughwl net stack, built on passive procs (the language's continuation
## magics) and our OWN epoll primitives. No nimony std async, no thread pool:
## one OS thread multiplexes thousands of connections.
##
## The seam with the language is minimal and entirely standard:
##   * a `{.passive.}` proc suspends by reifying its own continuation with
##     `delay()`, parking it against the fd it is waiting on, then `suspend()`.
##   * the reactor's `run` loop calls `epoll_wait`, and for each ready fd drives
##     the parked continuation with `complete()` — which retries the I/O and
##     either finishes or re-parks.
##
## Everything below the continuation magics (`delay`/`suspend`/`complete`/
## `Continuation`, all from the core language, not a stdlib module) rides on the
## epoll wrappers in `epoll_native`, which we own.

import std/[tables, hashes]
import tcp/epoll as ep

type
  Reactor* = ref object
    epfd: cint                       ## our epoll instance
    waiting: Table[cint, Continuation]  ## fd -> parked continuation awaiting readiness
    interest: Table[cint, uint32]    ## fd -> currently-armed epoll event mask
    live: int                        ## number of registered fds (loop runs while > 0)

proc newReactor*(): Reactor =
  Reactor(epfd: ep.epollCreate(), waiting: initTable[cint, Continuation](),
          interest: initTable[cint, uint32](), live: 0)

# ---------------------------------------------------------------------------
# fd registration
# ---------------------------------------------------------------------------

proc register*(r: Reactor; fd: cint) =
  ## Begin tracking `fd`. Registered level-triggered; the interest mask is set
  ## per-wait by the async primitives.
  if not r.interest.hasKey(fd):
    ep.epollAdd(r.epfd, fd, 0'u32)
    r.interest[fd] = 0'u32
    inc r.live

proc unregister*(r: Reactor; fd: cint) =
  ## Stop tracking `fd` (call on close). Drops any parked continuation.
  if r.interest.hasKey(fd):
    ep.epollDel(r.epfd, fd)
    r.interest.del(fd)
    dec r.live
  if r.waiting.hasKey(fd):
    r.waiting.del(fd)

proc arm(r: Reactor; fd: cint; mask: uint32) =
  ## Ensure epoll is watching `fd` for `mask` (EPOLLIN/EPOLLOUT).
  let cur = r.interest.getOrDefault(fd)
  if cur != mask:
    ep.epollMod(r.epfd, fd, mask)
    r.interest[fd] = mask

# ---------------------------------------------------------------------------
# the park primitive used by async I/O wrappers
# ---------------------------------------------------------------------------

proc spawn*(r: Reactor; k: Continuation) =
  ## Launch a coroutine reified with `delay(handlerCall)`, driving it until it
  ## first parks (registering itself against an fd via `park`) or finishes.
  ## This is how a passive proc must be started from a non-passive context —
  ## a direct call does not establish a suspendable coroutine and will busy-loop
  ## instead of parking.
  complete(k)

proc park*(r: Reactor; fd: cint; mask: uint32; k: Continuation) =
  ## Record that the continuation `k` is waiting for `fd` to become ready for
  ## `mask`. Called by an async primitive as `r.park(fd, EPOLLIN, delay())`
  ## immediately before `suspend()`.
  r.arm(fd, mask)
  r.waiting[fd] = k

# ---------------------------------------------------------------------------
# the run loop == the scheduler
# ---------------------------------------------------------------------------

proc run*(r: Reactor) =
  ## Drive all registered coroutines to completion. Returns when no fds remain
  ## registered (every connection has closed).
  var events = ep.newEventBuf(64)
  while r.live > 0:
    let n = ep.epollWait(r.epfd, events, -1.cint)  # block until something is ready
    var i = 0
    while i < n:
      let fd = ep.eventFd(events, i)
      inc i
      if not r.waiting.hasKey(fd):
        continue                     # readiness for an fd nobody is parked on
      let k = r.waiting.getOrDefault(fd)
      r.waiting.del(fd)
      # Drive the continuation: it retries its I/O and either finishes or
      # re-parks itself (re-populating r.waiting[fd] via park()).
      complete(k)
