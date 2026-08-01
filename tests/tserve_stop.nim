## The blocking worker pool can now be stopped.
##
## Before this it could not: a failed `accept` was a bare `continue`, so a dead
## listener span every worker at 100% CPU, and `runPool` joined threads that had
## no exit at all. `stopServing` shuts the shared listener down under the
## workers, which is the only thing that can interrupt a blocking `accept`.
##
## The claim is "the joins return", so that is literally what is asserted: if
## the workers still had no exit, this test would hang rather than fail — which
## is the honest signal, since a hung server is exactly the old behaviour.

import std/[syncio, rawthreads]
import serve
import serve/pool

const Workers = 3

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "up" & req.path)

proc writeAllRaw(fd: TcpHandle; s: string): bool =
  if s.len == 0: return true
  var buf = newSeq[char](s.len)
  var i = 0
  while i < s.len:
    buf[i] = s[i]
    inc i
  writeAllTcp(fd, addr buf[0], buf.len) == buf.len

proc readAllRaw(fd: TcpHandle): string =
  result = ""
  var buf = default(array[4096, char])
  var got = readTcp(fd, addr buf[0], 4096)
  while got > 0:
    var k = 0
    while k < got:
      result.add buf[k]
      inc k
    got = readTcp(fd, addr buf[0], 4096)

proc contains(hay, needle: string): bool =
  if needle.len == 0: return true
  var i = 0
  while i + needle.len <= hay.len:
    var j = 0
    var ok = true
    while j < needle.len:
      if hay[i + j] != needle[j]:
        ok = false
        break
      inc j
    if ok: return true
    inc i
  false

var failures = 0
proc check(cond: bool; what: string) =
  if not cond:
    echo "FAIL: ", what
    inc failures

proc main =
  initTcp()
  let l = listenTcp(0)
  check(l != InvalidTcpHandle, "listen failed")
  let port = localTcpEndpoint(l).port
  check(port > 0, "no ephemeral port")

  registerServeListener(l)
  configurePool(l, handler, false, TlsContext(handle: nil, mode: tlsServer))

  var wt = default(array[Workers, RawThread])
  var i = 0
  while i < Workers:
    spawnWorker(wt[i])
    inc i

  # Alive before the stop.
  var raw = 0'u32
  check(resolveTcp4("127.0.0.1", raw), "resolve 127.0.0.1")
  let fd = connectTcp4Timeout(raw, port, 2000).handle
  check(isValidTcp(fd), "connect to the pool")
  if isValidTcp(fd):
    check(writeAllRaw(fd, "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"),
          "write request")
    let resp = readAllRaw(fd)
    check(contains(resp, "up/x"), "pool answered before the stop")
    closeTcp(fd)

  # The claim: this returns.
  stopServing()
  check(serveStopRequested(), "the stop flag is set")
  i = 0
  while i < Workers:
    join(wt[i])
    inc i
  check(true, "every worker left its accept loop")

  closeTcp(l)
  if failures == 0:
    echo "tserve_stop: all checks passed (", Workers, " workers stopped)"
    quit(0)
  else:
    echo "tserve_stop: ", failures, " failures"
    quit(1)

main()
