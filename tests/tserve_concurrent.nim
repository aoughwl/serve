## tserve_concurrent.nim — proves the worker pool serves connections in
## parallel, not serially.
##
## The handler is a barrier: every invocation bumps a shared atomic counter and
## then spins until the counter reaches the worker count. That can only happen
## if that many handler invocations are running *at the same time*. We fire that
## many concurrent clients against a pool with that many workers:
##   * a genuinely concurrent server releases the barrier and every client gets
##     200;
##   * a serial server can never get a second handler running while the first
##     spins, so the barrier never releases — the spin cap trips `gTimedOut` and
##     the test fails.

import std/syncio
import std/rawthreads
import std/atomics
import serve

const Workers = 4

var gArrived = 0
var gTimedOut = 0
var gSuccess = 0
var gPort = 0

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc writeAllRaw(fd: TcpHandle; s: string): bool =
  var chunk = default(array[4096, char])
  var i = 0
  while i < s.len:
    var n = 0
    while n < chunk.len and i < s.len:
      chunk[n] = s[i]
      inc n
      inc i
    if writeAllTcp(fd, addr chunk[0], n) != n:
      return false
  return true

proc readAllRaw(fd: TcpHandle): string =
  result = ""
  var buf = default(array[4096, char])
  while true:
    let n = readTcp(fd, addr buf[0], buf.len)
    if n <= 0:
      break
    var i = 0
    while i < n:
      result.add buf[i]
      inc i

proc statusOf(resp: string): int =
  var i = 0
  while i < resp.len and resp[i] != ' ':
    inc i
  while i < resp.len and resp[i] == ' ':
    inc i
  var code = 0
  var any = false
  while i < resp.len and resp[i] >= '0' and resp[i] <= '9':
    code = code * 10 + (ord(resp[i]) - ord('0'))
    any = true
    inc i
  if not any: return -1
  return code

proc barrierArrive() {.nimcall.} =
  ## Register this handler's arrival and spin until all `Workers` handlers have
  ## arrived — only possible if that many run concurrently. Sets `gTimedOut` if
  ## the barrier never releases. Kept as a top-level `{.nimcall.}` proc (not
  ## inlined into the handler closure) because nimony's lambda lifter cannot
  ## lift the inline atomic generics through a closure body.
  var one = 1
  discard atomicFetchAdd(gArrived, one)
  var spins = 0
  while atomicLoad(gArrived) < Workers and spins < 500000000:
    inc spins
  if atomicLoad(gArrived) < Workers:
    var t = 1
    atomicStore(gTimedOut, t)

proc barrierHandler(req: Request): Response {.nimcall.} =
  ## The pool's thread-safe handler: a plain function pointer (no closure).
  barrierArrive()
  return response(200, "text/plain", "ok\n")

proc clientThread(arg: pointer) {.nimcall.} =
  discard arg
  let fd = connectLocalhostTcp(gPort)
  if fd == InvalidTcpHandle:
    return
  discard writeAllRaw(fd, "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
  let resp = readAllRaw(fd)
  closeTcp(fd)
  if statusOf(resp) == 200:
    var one = 1
    discard atomicFetchAdd(gSuccess, one)

proc main =
  initTcp()
  let l = listenTcp(0)
  check(l != InvalidTcpHandle, "listen failed")
  gPort = localTcpEndpoint(l).port
  check(gPort > 0, "no ephemeral port")

  configurePool(l, barrierHandler, false, TlsContext(handle: nil, mode: tlsServer))

  # Spawn the worker pool into stable storage (`wt` lives until process exit;
  # the workers loop forever, so it is never joined).
  var wt = default(array[Workers, RawThread])
  var i = 0
  while i < Workers:
    spawnWorker(wt[i])
    inc i

  # Fire `Workers` concurrent clients.
  var ct = default(array[Workers, RawThread])
  try:
    i = 0
    while i < Workers:
      create(ct[i], clientThread, nil)
      inc i
    i = 0
    while i < Workers:
      join(ct[i])
      inc i
  except:
    echo "FAIL: client thread create/join raised"
    quit(1)

  check(atomicLoad(gSuccess) == Workers, "not all clients got 200 (got " & $atomicLoad(gSuccess) & ")")
  check(atomicLoad(gTimedOut) == 0, "barrier timed out — server did not serve concurrently")

  closeTcp(l)
  echo "tserve_concurrent: all checks passed (", Workers, " concurrent)"
  quit(0)

main()
