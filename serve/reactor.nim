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
##
## Two things the loop owns besides connections: an idle deadline per parked fd
## (`setIdleTimeout`), and a stop signal (`requestStop`) delivered through an
## eventfd, which is what lets a blocked `epoll_wait` be interrupted from a
## signal handler. The server entry points install SIGINT/SIGTERM handlers that
## request a GRACEFUL stop: listeners close, in-flight connections finish, then
## `run()` returns — rather than a response dying mid-write.

import std/[tables, hashes]
import tcp
import tcp/epoll as ep

type
  Timespec = object
    tvSec: int64
    tvNsec: int64

proc clockGettime(clkId: cint; tp: pointer): cint {.cdecl,
  importc: "clock_gettime", header: "<time.h>".}
  ## `tp` is typed `pointer`, not `ptr Timespec`: our hand-laid struct is
  ## layout-compatible with the system's `struct timespec` but not the same C
  ## type, and declaring it as such makes the C compiler warn on every build.

proc eventfd(initval: cuint; flags: cint): cint {.cdecl,
  importc: "eventfd", header: "<sys/eventfd.h>".}
proc posixWrite(fd: cint; buf: pointer; n: csize_t): int {.cdecl,
  importc: "write", header: "<unistd.h>".}
proc posixRead(fd: cint; buf: pointer; n: csize_t): int {.cdecl,
  importc: "read", header: "<unistd.h>".}
type SigHandler = proc(sig: cint) {.cdecl.}
proc csignal(sig: cint; handler: SigHandler): nil pointer {.cdecl,
  importc: "signal", header: "<signal.h>".}

const
  EFD_CLOEXEC = 0x80000.cint
  EFD_NONBLOCK = 0x800.cint
  SIGINT = 2.cint
  SIGTERM = 15.cint

proc nowMs*(): int64 =
  ## Monotonic milliseconds — immune to wall-clock jumps, which is the only
  ## clock a timeout may be measured against.
  var ts = Timespec(tvSec: 0, tvNsec: 0)
  discard clockGettime(cint(1), cast[pointer](addr ts))   # CLOCK_MONOTONIC
  return ts.tvSec * 1000'i64 + ts.tvNsec div 1_000_000'i64

type
  Reactor* = ref object
    epfd: cint                       ## our epoll instance
    waiting: Table[cint, Continuation]  ## fd -> parked continuation awaiting readiness
    interest: Table[cint, uint32]    ## fd -> currently-armed epoll event mask
    idle: Table[cint, int]           ## fd -> configured idle timeout in ms
    deadline: Table[cint, int64]     ## fd -> monotonic ms at which that idle expires
    live: int                        ## number of registered fds (loop runs while > 0)
    wakeFd: cint                     ## eventfd the loop also watches, to be interrupted
    listeners: seq[cint]             ## listening fds, closed first on a graceful stop
    stopRequested: bool
    stopGraceful: bool

proc newReactor*(): Reactor =
  ## The reactor also owns an eventfd it watches alongside the connections: it
  ## is how `requestStop` interrupts a `epoll_wait` that would otherwise block
  ## until the next connection event, and writing to an fd is one of the few
  ## things a signal handler is allowed to do.
  let ef = eventfd(0.cuint, EFD_CLOEXEC or EFD_NONBLOCK)
  result = Reactor(epfd: ep.epollCreate(), waiting: initTable[cint, Continuation](),
                   interest: initTable[cint, uint32](), idle: initTable[cint, int](),
                   deadline: initTable[cint, int64](), live: 0, wakeFd: ef,
                   listeners: @[], stopRequested: false, stopGraceful: true)
  if ef >= 0.cint:
    # Deliberately NOT via `register`: the wake fd must not count towards `live`,
    # or the loop would never see "no connections left" and never return.
    ep.epollAdd(result.epfd, ef, ep.EPOLLIN)

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

proc registerListener*(r: Reactor; fd: cint) =
  ## Track `fd` AND remember it is a listener. A graceful stop closes listeners
  ## first: no new connections are accepted, while the ones already in flight
  ## are allowed to finish.
  r.register(fd)
  r.listeners.add fd

proc unregister*(r: Reactor; fd: cint) =
  ## Stop tracking `fd` (call on close). Drops any parked continuation.
  if r.interest.hasKey(fd):
    ep.epollDel(r.epfd, fd)
    r.interest.del(fd)
    dec r.live
  if r.waiting.hasKey(fd):
    r.waiting.del(fd)
  if r.idle.hasKey(fd):
    r.idle.del(fd)
  if r.deadline.hasKey(fd):
    r.deadline.del(fd)

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

proc setIdleTimeout*(r: Reactor; fd: cint; ms: int) =
  ## Give `fd` an idle timeout: if it ever stays un-ready for `ms` milliseconds
  ## while a coroutine is parked on it, the reactor shuts the socket down, which
  ## surfaces to that coroutine as an ordinary EOF — no new control flow in the
  ## servers, and no coroutine parked forever on a peer that stops talking.
  ## `ms <= 0` removes the timeout.
  ##
  ## The clock only runs while a coroutine is actually waiting (see `park`), so
  ## this measures idleness, not connection age.
  if ms <= 0:
    if r.idle.hasKey(fd): r.idle.del(fd)
    if r.deadline.hasKey(fd): r.deadline.del(fd)
  else:
    r.idle[fd] = ms

proc park*(r: Reactor; fd: cint; mask: uint32; k: Continuation) =
  ## Record that the continuation `k` is waiting for `fd` to become ready for
  ## `mask`. Called by an async primitive as `r.park(fd, EPOLLIN, delay())`
  ## immediately before `suspend()`.
  r.arm(fd, mask)
  r.waiting[fd] = k
  let ms = r.idle.getOrDefault(fd)
  if ms > 0:
    r.deadline[fd] = nowMs() + int64(ms)

proc requestStop*(r: Reactor; graceful = true) =
  ## Ask `run()` to finish. Safe to call from a coroutine, another thread, or a
  ## signal handler: it only sets two words and writes 8 bytes to the eventfd,
  ## which is what wakes a blocked `epoll_wait`.
  ##
  ## `graceful` (the default) closes the listeners and lets the connections
  ## already in flight run to completion — `run()` returns when the last one
  ## closes. Otherwise `run()` returns at the next turn of the loop, abandoning
  ## whatever was in flight.
  r.stopGraceful = graceful
  r.stopRequested = true
  if r.wakeFd >= 0.cint:
    var one = 1'u64
    discard posixWrite(r.wakeFd, cast[pointer](addr one), csize_t(8))

# A 0-or-1 element seq rather than a nilable global: nimony's flow analysis
# cannot prove a global `ref` non-nil at a use site, and a signal handler is the
# one place that must not carry a maybe-nil.
var gStopReactor: seq[Reactor] = @[]

proc onStopSignal(sig: cint) {.cdecl.} =
  if gStopReactor.len > 0:
    gStopReactor[0].requestStop(true)

proc stopOnSignals*(r: Reactor) =
  ## Make SIGINT and SIGTERM start a graceful stop. One reactor per process gets
  ## this (the handler needs a global to reach it), which matches the one-thread
  ## model. Without it, the only way to end a server is to kill it mid-response.
  gStopReactor = @[r]
  discard csignal(SIGINT, onStopSignal)
  discard csignal(SIGTERM, onStopSignal)

proc closeListeners(r: Reactor) =
  ## Stop accepting. Connections already open are untouched.
  let fds = r.listeners
  r.listeners = @[]
  for fd in fds:
    r.unregister(fd)
    closeTcp(fd)

proc nextTimeoutMs(r: Reactor): cint =
  ## How long `epoll_wait` may block: until the nearest deadline, or forever.
  ## Linear in the number of armed deadlines — fine at these connection counts;
  ## a heap is the upgrade if that stops being true.
  var best = -1'i64
  let t = nowMs()
  for fd, dl in pairs(r.deadline):
    let left = dl - t
    let clamped = if left < 0'i64: 0'i64 else: left
    if best < 0'i64 or clamped < best:
      best = clamped
  if best < 0'i64:
    return -1.cint
  return cint(best)

proc expire(r: Reactor) =
  ## Shut down every fd whose idle deadline has passed. The shutdown makes the
  ## socket readable-at-EOF, so epoll hands the parked coroutine back its normal
  ## end-of-connection path on the next turn.
  if r.deadline.len == 0:
    return
  let t = nowMs()
  var dead: seq[cint] = @[]
  for fd, dl in pairs(r.deadline):
    if dl <= t:
      dead.add fd
  for fd in dead:
    r.deadline.del(fd)
    discard shutdownTcpBoth(fd)

# ---------------------------------------------------------------------------
# the run loop == the scheduler
# ---------------------------------------------------------------------------

proc run*(r: Reactor) =
  ## Drive all registered coroutines to completion. Returns when no fds remain
  ## registered (every connection has closed), or when a stop is requested —
  ## immediately for a hard stop, once the last in-flight connection finishes
  ## for a graceful one.
  var events = ep.newEventBuf(64)
  var running = true
  while r.live > 0 and running:
    # Block until something is ready, or until the nearest idle deadline.
    let n = ep.epollWait(r.epfd, events, r.nextTimeoutMs())
    var i = 0
    while i < n:
      let fd = ep.eventFd(events, i)
      inc i
      if fd == r.wakeFd:
        var sink = 0'u64             # drain the eventfd so it stops firing
        discard posixRead(r.wakeFd, cast[pointer](addr sink), csize_t(8))
        continue
      if not r.waiting.hasKey(fd):
        continue                     # readiness for an fd nobody is parked on
      if r.deadline.hasKey(fd):
        r.deadline.del(fd)           # it spoke: the idle clock stops here
      let k = r.waiting.getOrDefault(fd)
      r.waiting.del(fd)
      # Drive the continuation: it retries its I/O and either finishes or
      # re-parks itself (re-populating r.waiting[fd] via park()).
      complete(k)
    r.expire()
    if r.stopRequested:
      if r.stopGraceful:
        # Close the listeners once; the loop then drains naturally as the
        # connections still in flight finish and unregister themselves.
        r.stopRequested = false
        r.closeListeners()
      else:
        running = false
