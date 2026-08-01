# The reactor — single-threaded async for the aoughwl net stack

`serve/reactor.nim` + `serve/asyncio.nim` add a single-threaded, epoll-driven
async model to the net stack, built on Nimony's **passive procs** (continuation
coroutines) and our own epoll primitive (`tcp/epoll.nim`). One OS thread
multiplexes thousands of connections — the alternative to the blocking
worker-pool model in `serve/loop.nim` + `serve/pool.nim`.

Verified: `tests/reactor_e2e.sh` serves **100 simultaneous connections × 3
rounds (300/300 echoes) on exactly one OS thread.**

## How it fits together

- **`tcp/epoll.nim`** — our own thin epoll(7) binding (the net stack owns no
  epoll otherwise, only `poll`). `epollCreate/Add/Mod/Del/Wait`, an `EventBuf`.
- **`serve/reactor.nim`** — the scheduler. A `Reactor` owns the epoll fd and a
  `Table[fd, Continuation]` of parked coroutines. `run()` calls `epoll_wait` and,
  for each ready fd, `complete()`s the parked continuation. `spawn(delay(call))`
  launches a coroutine and drives it to its first park.
- **`serve/asyncio.nim`** — `awaitAccept` / `awaitRead` / `awaitWriteAll`. Each
  tries a nonblocking syscall and, on EAGAIN, parks the calling coroutine against
  the fd and `suspend()`s. The reactor resumes it on readiness.

The seam with the language is standard: `delay()` reifies a coroutine's
continuation, `suspend()` parks it, `complete()` drives it. The language hands us
suspendable continuations; the reactor is the scheduler that epoll drives.

## Why the await primitives are templates, not procs

This is the load-bearing design decision, forced by two defects in the current
Nimony coroutine transform (`hexer/coro_transform.nim`). Both are worked around
here; both are worth filing against the fork.

**1. A caller looping over a suspending callee corrupts the coroutine frame.**
If `handler()` (a passive proc) loops calling `asyncRead()` (a passive proc that
suspends internally), the callee either busy-loops instead of parking or the
frame is double-freed (`mimalloc: double free detected`). A *single flat
coroutine* that owns its own suspend loop works correctly. So the await
primitives are **templates**: they inline their read/accept/write-and-suspend
loop into the calling coroutine, keeping every suspend point in one flat
coroutine. (This is the same class of bug hashi's CPS briefings describe.)

**2. `break`/`return` in the same branch as a `suspend` crashes the transform.**
An `if/elif/else` (or nested `if/else`) branch that does `break`/`return` and
also, in a sibling branch, `suspend()` crashes goto-lowering
(`[Bug] expected ')'` in `trGoto`). So the templates carry loop exit in a
`done`/`failed` flag on the `while` condition rather than `break`ing out of a
branch that suspends.

Both rules are mechanical and local; the resulting code is plain. When the
transform is fixed, the templates can become ordinary passive procs unchanged.

## Using it

```nim
proc echoConn(r: Reactor; fd: cint) {.passive.} =
  var buf = default(array[4096, char])
  while true:
    var n = 0
    r.awaitRead(fd, addr buf[0], 4096, n)
    if n <= 0: break
    var ok = false
    r.awaitWriteAll(fd, addr buf[0], n, ok)
    if not ok: break
  r.unregister(fd); closeTcp(fd)
```

See `examples/reactor_echo.nim` for the full accept loop and driver.

## Async servers built on the reactor

The reactor is the async backbone for real protocols, each one flat coroutine
per connection, all multiplexed on one OS thread:

- **`serve/reactorhttp.nim`** — async **HTTP/1.1**. `serveHttpReactor(port,
  handler)` where `handler` is a `{.nimcall.}` `proc(req: Request): Response`.
  Reads a full request (Content-Length or chunked), runs the handler, writes the
  response, loops for keep-alive. Reuses the `http` package's parse/serialize.
  *Verified: 60 simultaneous keep-alive conns × 5 requests (300/300) on one
  thread* (`tests/reactor_http_e2e.sh`).
- **`serve/reactorws.nim`** — async **WebSocket (RFC 6455)**.
  `serveWsReactor(port, handler)` where `handler` is `proc(msg: string;
  isBinary: bool): string`. Reads the Upgrade request, completes the handshake
  (`ws` package), then runs a frame loop with an incremental buffer-based
  decoder (`tryDecodeFrame`) — the `ws` package only ships a transport-coupled
  reader, so async needs its own — reassembling fragments and auto-answering
  ping/close. **Autobahn-grade conformance**: masked-frame enforcement, RSV /
  reserved-opcode / control-frame validation, a fragmentation state machine,
  incremental UTF-8 validation of text (Höhrmann DFA in `ws/protocol`, Close 1007
  on invalid), close-code validation + echo (Close 1002), and permessage-deflate.
  *Verified: 160/160 echo across 40 clients (`tests/reactor_ws_e2e.sh`) plus 19/19
  conformance cases (`tests/reactor_ws_conformance.sh`) on one thread.*
- **`serve/reactorh3.nim`** — async **HTTP/3 (QUIC)**.
  `serveH3Reactor(port, cert, key, handler)` where `handler` is `proc(meth, path,
  body: string): H3Response`. The QUIC transport, TLS 1.3 handshake, connection-ID
  routing, timers, and the HTTP/3 (QPACK) layer live in the `quic/quicglue.c`
  glue shim (compiled against system **ngtcp2 + nghttp3 + GnuTLS**; build with
  `quic/build.sh`), exposed to nimony through a small pull-based API
  (`quic/quic.nim`). The reactor owns only the epoll wait on the single UDP fd,
  feeding datagram readiness and QUIC timer expiries into the shim. GET + POST.
  *Verified: 20 independent QUIC clients (20/20) on one thread*
  (`tests/reactor_h3_e2e.sh`); the pure-C harness is ASan/LSan-clean.

- **WebTransport** (same shim, `AQ_WEBTRANSPORT` — needs vendored nghttp3 ≥ 1.x
  from `quic/build-nghttp3.sh`). A session is an HTTP/3 extended CONNECT with
  `:protocol=webtransport`, answered 200 with the CONNECT stream held open.
  Over it:
  - **datagrams** — `wtSendDatagram` / `takeDatagram`, carried as H3 datagrams
    (quarter-stream-id flow prefix) over RFC 9221 QUIC datagrams. *Verified:
    session + datagram round-trip* (`tests/reactor_wt_e2e.sh`).
  - **streams** — `wtOpenStream(uni)`, `wtStreamSend(…, fin)`, `wtTakeStream`,
    `wtStreamRecv`, `wtStreamFin`. These are ordinary QUIC streams carrying the
    `WEBTRANSPORT_STREAM` signal (`0x41` bidi / `0x54` uni) plus a session id, so
    the shim routes them itself and they never reach nghttp3; a stream that
    turns out to be plain HTTP/3 has its held opening bytes replayed into
    nghttp3 instead. *Verified: bidi echo + a uni stream in each direction on one
    thread* (`tests/reactor_wtstream_e2e.sh`), ASan-clean.

Both TCP servers use a module-global `{.nimcall.}` handler (the `pool.nim` pattern) rather
than a captured closure, which composes cleanly across the coroutine boundary,
and flag-based control flow throughout (no `break`/`return` beside a `suspend`).

The blocking worker-pool servers (`serve/loop.nim`, `serve/pool.nim`) remain for
callers that want thread-per-connection; the reactor variants are the
single-thread-multiplexing alternative for high connection counts.
