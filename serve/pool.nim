## serve/pool.aowl — concurrent serving via a fixed worker pool.
##
## The single-connection `serve` loop handles one client at a time: a slow or
## keep-alive client blocks every other. `serveConcurrent` / `serveTlsConcurrent`
## fix that with a bounded pool of worker threads that all `accept()` on ONE
## shared listening socket. The kernel hands each incoming connection to one
## waiting worker, so up to `workers` connections are served simultaneously with
## no per-connection thread churn and no unbounded thread growth.
##
## The pool is process-global (one server per process). Configure it, spawn
## workers, and join them (workers loop forever, so a plain server never
## returns). Tests can drive the lower-level `configurePool` / `spawnWorker`
## directly to run workers without blocking on `join`.
##
## nimony notes: thread entry points are `{.nimcall.}` (not closures) and take a
## single `pointer`; per-connection state travels through the process-global
## config rather than a captured environment.

import std/syncio
import std/rawthreads
import tcp
import tls
import loop

const MaxWorkers* = 256

var gPoolListen = InvalidTcpHandle
var gPoolHandler: NimcallHandler
var gPoolUseTls = false
var gPoolCtx: TlsContext

proc configurePool*(listenFd: TcpHandle; handler: NimcallHandler; useTls: bool;
                    ctx: TlsContext) =
  ## Install the shared listening socket + handler that workers will serve.
  gPoolListen = listenFd
  gPoolHandler = handler
  gPoolUseTls = useTls
  gPoolCtx = ctx

proc poolWorker(arg: pointer) {.nimcall.} =
  ## One worker: accept a connection off the shared socket and serve it to
  ## completion. A transient accept failure is retried; a hard one — which is
  ## what `stopServing` produces, by shutting the shared listener down under
  ## every worker at once — ends the worker so `runPool`'s joins can return.
  ##
  ## Previously this was `while true` with a bare `continue` on a failed accept:
  ## a dead listener span every worker at 100% CPU, and nothing could ever end
  ## the pool.
  discard arg
  var running = true
  while running:
    let fd = acceptTcp(gPoolListen)
    if fd != InvalidTcpHandle:
      if gPoolUseTls:
        serveConnectionTlsNimcall(fd, gPoolCtx, gPoolHandler)
      else:
        serveConnectionNimcall(fd, gPoolHandler)
    elif serveStopRequested() or not tcpErrorWouldRetry(lastTcpErrorCode()):
      running = false

proc spawnWorker*(t: var RawThread) =
  ## Create one worker thread into caller-owned storage `t`. `t` MUST outlive the
  ## thread: nimony's `create` passes `addr t` to the OS and the worker reads its
  ## entry point back through that pointer, so a RawThread returned by value (its
  ## storage freed on return) would leave the thread dereferencing a dangling
  ## pointer. Keep `t` in a long-lived array/global.
  try:
    create(t, poolWorker, nil)
  except:
    discard

proc runPool(workers: int) =
  var threads = default(array[MaxWorkers, RawThread])
  var w = workers
  if w < 1: w = 1
  if w > MaxWorkers: w = MaxWorkers
  var i = 0
  while i < w:
    spawnWorker(threads[i])
    inc i
  i = 0
  while i < w:
    join(threads[i])
    inc i

proc serveConcurrent*(port: int; handler: NimcallHandler; workers = 4) =
  ## Concurrent plaintext HTTP server: `workers` threads share one listening
  ## socket. Loops forever (workers never return).
  initTcp()
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    shutdownTcp()
    return
  registerServeListener(l)
  configurePool(l, handler, false, TlsContext(handle: nil, mode: tlsServer))
  echo "serving on :", port, " with ", workers, " worker(s)"
  runPool(workers)
  closeTcp(l)
  shutdownTcp()

proc serveTlsConcurrent*(port: int; ctx0: TlsContext;
                         handler: NimcallHandler; workers = 4) =
  ## Concurrent HTTPS server: `workers` threads share one listening socket and a
  ## single TLS context — one YOU built and configured, so versions, ciphers,
  ## groups, ALPN and extra SNI certificates stay reachable. Returns when
  ## `stopServing` shuts the listener down.
  initTcp()
  var ctx = ctx0
  if not ctx.isValid:
    echo "invalid TLS context: ", lastTlsError()
    shutdownTcp()
    return
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    echo "failed to listen on :", port
    ctx.close()
    shutdownTcp()
    return
  registerServeListener(l)
  configurePool(l, handler, true, ctx)
  echo "serving TLS on :", port, " with ", workers, " worker(s)"
  runPool(workers)
  ctx.close()
  closeTcp(l)
  shutdownTcp()

proc serveTlsConcurrent*(port: int; certFile: string; keyFile: string;
                         handler: NimcallHandler; workers = 4) =
  ## As above, with a default context built from a PEM cert chain and key.
  serveTlsConcurrent(port, newTlsServerContext(certFile, keyFile), handler, workers)
