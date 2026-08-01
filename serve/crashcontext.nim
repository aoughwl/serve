## serve/crashcontext.nim — name the request that killed the server.
##
## A handler cannot raise: `Handler` carries no `.raises`, so nimony rejects a
## `raise` inside one at compile time. The whole "uncaught exception takes the
## process down" class is excluded by the type system, and no try/except in the
## serving loop would add anything.
##
## What a handler CAN do is commit a defect — an out-of-bounds index, a nil
## dereference, a failed assertion in a library it called. Those are not
## exceptions and are not catchable; the process aborts. That is defensible
## behaviour (fail fast, let a supervisor restart) with one problem: the message
## is the defect's own, e.g.
##
##     seqimpl.nim(167, 41): i < s.len and 0 <= i [AssertionDefect]
##
## which says nothing about WHICH request produced it. On a busy server that is
## the difference between a five-minute fix and an unreproducible ticket.
##
## This module keeps the in-flight request line in a preallocated buffer and
## prints it as the process leaves.
##
## The hook is **`atexit`**, not a signal handler, because that is how nimony
## actually terminates on a defect: `panic` in `std/system/panics.nim` writes
## its message and calls `exit(1)`. No SIGABRT is raised, so a `signal()` handler
## never runs — which is exactly what the first version of this module did, and
## it printed nothing. Signal handlers are still installed for the faults `exit`
## cannot cover (SIGSEGV, SIGBUS, SIGILL, SIGFPE); those paths use only
## `write(2)`, which is async-signal-safe.

when defined(nimony):
  {.feature: "lenientnils".}

const ContextBytes = 512

type SigHandler = proc(sig: cint) {.cdecl.}

proc csignal(sig: cint; handler: SigHandler): nil pointer {.cdecl,
  importc: "signal", header: "<signal.h>".}
proc craise(sig: cint): cint {.cdecl, importc: "raise", header: "<signal.h>".}
proc csignalReset(sig: cint; handler: pointer): nil pointer {.cdecl,
  importc: "signal", header: "<signal.h>".}
  ## The same `signal`, typed to take a bare pointer, so `SIG_DFL` (which is 0)
  ## can be passed without casting an integer to a proc type — nimony refuses
  ## that cast, and rightly.
proc cwrite(fd: cint; buf: pointer; n: csize_t): int {.cdecl,
  importc: "write", header: "<unistd.h>".}
proc catexit(f: proc() {.cdecl.}): cint {.cdecl,
  importc: "atexit", header: "<stdlib.h>".}
proc cfflush(f: pointer): cint {.cdecl,
  importc: "fflush", header: "<stdio.h>".}

const
  SIGILL = 4.cint
  SIGABRT = 6.cint
  SIGFPE = 8.cint
  SIGSEGV = 11.cint
  SIGBUS = 7.cint

var gContext = default(array[ContextBytes, char])
var gContextLen = 0
var gPrefix = default(array[64, char])
var gPrefixLen = 0

proc setPrefix(s: string) =
  gPrefixLen = 0
  var i = 0
  while i < s.len and i < 64:
    gPrefix[i] = s[i]
    inc i
  gPrefixLen = i

proc setCrashContext*(meth, path: string) =
  ## Record the request being served. Called on every request, so it does no
  ## allocation and no formatting — a bounded copy into a fixed buffer.
  var n = 0
  var i = 0
  while i < meth.len and n < ContextBytes - 2:
    gContext[n] = meth[i]
    inc n
    inc i
  if n < ContextBytes - 1:
    gContext[n] = ' '
    inc n
  i = 0
  while i < path.len and n < ContextBytes - 1:
    gContext[n] = path[i]
    inc n
    inc i
  gContext[n] = '\n'
  inc n
  gContextLen = n

proc clearCrashContext*() =
  ## No request in flight. A crash between requests then says so, rather than
  ## blaming the last one that completed successfully.
  gContextLen = 0

proc onFatalSignal(sig: cint) {.cdecl.} =
  if gPrefixLen > 0:
    discard cwrite(2.cint, cast[pointer](addr gPrefix[0]), csize_t(gPrefixLen))
  if gContextLen > 0:
    discard cwrite(2.cint, cast[pointer](addr gContext[0]), csize_t(gContextLen))
  else:
    const idle = "<no request in flight>\n"
    var buf = default(array[24, char])
    var i = 0
    while i < idle.len and i < 24:
      buf[i] = idle[i]
      inc i
    discard cwrite(2.cint, cast[pointer](addr buf[0]), csize_t(i))
  # Restore the default disposition and re-raise, so the exit status and core
  # dump are what they would have been without this handler.
  discard csignalReset(sig, cast[pointer](0))     # SIG_DFL
  discard craise(sig)

proc onExit() {.cdecl.} =
  ## Runs on any `exit`, including the one `panic` performs. Says nothing when
  ## no request is in flight, so an ordinary shutdown stays quiet.
  if gContextLen > 0:
    discard cfflush(cast[pointer](0))   # let the panic's own message land first
    if gPrefixLen > 0:
      discard cwrite(2.cint, cast[pointer](addr gPrefix[0]), csize_t(gPrefixLen))
    discard cwrite(2.cint, cast[pointer](addr gContext[0]), csize_t(gContextLen))

proc installCrashContext*(prefix = "serve: died while handling: ") =
  ## Print the in-flight request on a fatal signal. Covers the signals a defect
  ## actually produces: SIGABRT (a failed assertion, which is how nimony's
  ## bounds check reports), SIGSEGV, SIGBUS, SIGILL, SIGFPE.
  setPrefix(prefix)
  discard catexit(onExit)
  discard csignal(SIGABRT, onFatalSignal)
  discard csignal(SIGSEGV, onFatalSignal)
  discard csignal(SIGBUS, onFatalSignal)
  discard csignal(SIGILL, onFatalSignal)
  discard csignal(SIGFPE, onFatalSignal)
