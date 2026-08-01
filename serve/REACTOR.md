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

## TLS on the reactor

`serve/asynctls.nim` is `asyncio.nim`'s TLS twin: `awaitTlsHandshake`,
`awaitTlsRead`, `awaitTlsWriteAll`. No new machinery was needed — the `tls`
package already returns `tlsWantRead` / `tlsWantWrite` on a non-blocking socket
instead of blocking, and those map straight onto parking against `EPOLLIN` /
`EPOLLOUT`.

Two things that are easy to get wrong:

- **Set the accepted fd non-blocking *before* `wrapServer`.** `wrapServer` starts
  the handshake; on a blocking fd it runs the whole thing right there, on the
  reactor thread, stalling every other connection.
- **The direction is TLS's choice, not the operation's.** A read can want
  writability (a TLS 1.3 key update) and a write can want readability, so each
  primitive parks on whichever the status names — never on the direction the
  call name suggests.

Teardown is `close_notify` → FIN → bounded drain, not a bare `close()`: closing
while the peer's last bytes sit unread makes the kernel answer them with RST.
That single detail was worth two h2spec cases.

Every TLS entry point comes in two forms: one taking a PEM cert/key pair, and
one taking a `TlsContext` **you** built and configured. The second exists
because a server that constructs its own context freezes every TLS knob out of
reach — protocol versions, cipher suites, key-exchange groups (post-quantum
included), extra SNI certificates, session resumption. `examples/reactor_tlsconf.nim`
is the shape: build the context, set what you need, hand it over.

`serve/asyncconn.nim` then removes the "write the coroutine twice" problem.
`Conn` is `{fd, isTls, tls}`, and `awaitConnHandshake` / `awaitConnRead` /
`awaitConnWriteAll` / `closeConn` dispatch on `isTls`, each arm inlining the
primitive it needs. A runtime branch is the only abstraction the coroutine
transform allows here — the primitives must be templates — and it costs a
predictable branch per I/O against a syscall. HTTP/1.1 and WebSocket each run
**one** connection body for both transports; only the accept loop differs
(`serveHttpsReactor`, `serveWssReactor`).

## Idle timeouts

`r.setIdleTimeout(fd, ms)` — set once per connection, right after `register` —
bounds how long a coroutine may sit parked on a socket that never becomes ready.
Without it a peer that completes a handshake and then says nothing holds its
coroutine (and, for HTTP/2, one of the fixed session slots) for the life of the
process.

The clock runs only while a coroutine is actually waiting: `park` arms the
deadline, readiness disarms it, so it measures idleness rather than connection
age. `epoll_wait` blocks until the nearest deadline instead of forever, and an
expiry **shuts the socket down** rather than resuming the continuation with an
error. That is the whole trick — the coroutine then reads 0, takes the ordinary
end-of-connection path it already has, and no server needs a line of new control
flow. `nowMs()` is `CLOCK_MONOTONIC`, so a wall-clock jump cannot move a
deadline. Deadline lookup is linear in the number of *parked* fds; a heap is the
upgrade when that stops being cheap.

Defaults: 60 s for HTTP/1.1 and HTTP/2, **off** for WebSocket (a silent
subscription is not a stalled one). All three take an `idleTimeoutMs` argument.
*Verified: `tests/reactor_idle_timeout.sh`.*

## Streaming a response

Every response path materialised the whole body first, which rules out three
things a server has to do: server-sent events (a body that is never finished),
downloads larger than memory, and any response whose first byte should reach the
client before the last is computed.

`serve/stream.nim` adds a **pull producer**:

```nim
proc next(st: var StreamState; chunk: var string): bool {.nimcall.}
```

called repeatedly by the connection coroutine until it returns false. Pull, not
push, because a handler cannot suspend and therefore cannot write — it can only
be asked for the next piece while the coroutine does the suspending write.
(nghttp2's data provider works the same way, which is a good sign it is the
right seam.) Returning `true` with an empty chunk means "nothing right now" and
is not treated as the end.

`setReactorStreamHandler(handler, wants)` installs it beside the ordinary
handler, with a predicate deciding which requests stream — so a server can
stream `/events` and serve everything else normally. Framing is added by the
transport: `Transfer-Encoding: chunked` for HTTP/1.1, and for anything older no
chunked framing at all plus `Connection: close`, since silently sending chunks
to an HTTP/1.0 client would corrupt the body. Built in: `fileStream` (with
offset/length, so it can back a byte range) and `sseEvent`/`sseStream`, which
also sets the `Cache-Control: no-cache` and `X-Accel-Buffering: no` an
EventSource needs to not be buffered into uselessness by an intermediary.

*Verified: `tests/reactor_stream_e2e.sh` — a 128 MiB file arrives byte-exact
while the server's PEAK RSS stays at ~7 MB. Materialising the body would put the
whole file in that number, so the memory figure is the assertion; the checksum
is only the sanity check.*

One limit worth stating: a producer runs on the reactor thread, so it must not
block. A feed that has nothing to send yet should return an empty chunk, not
sleep.

## Calling out: the async client

The stack could *serve* asynchronously and could only *call* synchronously —
`net`, `tls` and `requests` all block the calling thread. On a single-threaded
server that is fatal: one upstream call stops every other connection, so a
server could not proxy, fire a webhook, or read an upstream API without giving
up the model.

`serve/asyncclient.nim` adds `awaitConnect` and `awaitFetch`: connect, TLS
handshake, request, response — every step suspending, all inside the calling
coroutine. `http`'s new `parseResponse` does the parsing (it could build a
response but not read one, which is exactly the server-shaped gap).

Scope is stated, not implied: HTTP/1.1, one request per connection
(`Connection: close`), no pooling and no redirect following — those are policy
and belong above this. **DNS resolution blocks**: `getaddrinfo` has no
non-blocking form worth the name, so a hostname costs the reactor thread the
lookup and an IP literal costs nothing.

Every step is bounded by `timeoutMs` (default 30 s), armed **before** the
connect rather than after it — a host that drops the SYN never makes the socket
writable, so the connect is the step most able to park a coroutine forever.

*Verified: `tests/reactor_proxy_e2e.sh` — 12 concurrent requests proxied
through a deliberately 0.5s upstream finish in ~0.5s, not the ~6s a blocking
fetch would take (the number IS the assertion); and an upstream that accepts
then says nothing is answered 502 after the configured 1s, with the proxy still
serving afterwards.*

## Timers that resume, not just timers that kill

The idle timeout above ends a connection. A protocol with timers of its OWN —
QUIC's loss, idle and PTO timers, a heartbeat, a retry backoff — needs the
opposite: to be woken *without* anything being torn down.

`awaitReadableFor(fd, ms, timedOut)` is that wait: it returns when the fd is
readable **or** when `ms` elapses, and says which. Underneath, a
`setResumeDeadline` marks the deadline as one that resumes the parked
continuation instead of shutting the socket down. The two share one deadline
slot per fd, which is why the primitive arms it *after* `park`.

This is what let HTTP/3 stop running a private epoll loop and join the shared
reactor — and therefore what makes one thread able to serve TCP and QUIC at
once.

## Stopping

`run()` used to loop until the process was killed, so the only way to end a
server was to cut a response in half.

`requestStop(r, graceful = true)` ends it properly. It sets two words and writes
8 bytes to an eventfd the loop also watches — the only work a signal handler is
allowed to do, and what lets a blocked `epoll_wait` be interrupted at all. A
graceful stop closes the **listeners** (`registerListener` is how the reactor
knows which fds those are), so nothing new is accepted while the connections
already in flight run to completion; `run()` returns when the last one closes.
A non-graceful stop returns at the next turn of the loop.

The server entry points install SIGINT/SIGTERM handlers for a graceful stop, so
Ctrl-C on a server drains rather than kills. *Verified:
`tests/reactor_shutdown.sh` — a keep-alive connection held across the signal
still gets a complete response, a new connection is refused, and the process
exits on its own.*

## Async servers built on the reactor

The reactor is the async backbone for real protocols, each one flat coroutine
per connection, all multiplexed on one OS thread:

- **`serve/reactorhttp.nim`** — async **HTTP/1.1**. `serveHttpReactor(port,
  handler)` where `handler` is a `{.nimcall.}` `proc(req: Request): Response`.
  Reads a full request (Content-Length or chunked), runs the handler, writes the
  response, loops for keep-alive. Reuses the `http` package's parse/serialize.
  `serveHttpsReactor(port, cert, key, handler)` is the same body over TLS.
  *Verified: 60 simultaneous keep-alive conns × 5 requests (300/300) on one
  thread* (`tests/reactor_http_e2e.sh`), *plus 30 simultaneous TLS conns × 5
  (150/150)* (`tests/reactor_https_e2e.sh`).
- **`serve/reactorh2.nim`** — async **HTTP/2 (h2c)**. `serveHttp2Reactor(port,
  handler)`, same `proc(req: Request): Response` handler shape as HTTP/1.1. The
  protocol work stays in libnghttp2, which is a pure codec — it never touches a
  socket — so the coroutine only drains what the session has queued
  (`h2NextOut`) and feeds it what it reads (`h2Feed`). Sessions live in a fixed
  global table (`MaxH2Conns`, overflow counted by `h2RejectedConns()`) because
  the `user_data` pointer handed to nghttp2 must stay address-stable, which a
  coroutine local is not. Connection teardown is a FIN plus a bounded drain, not
  a bare `close()`, so the peer's last frames do not turn into an RST.
  `serveHttp2TlsReactor(port, cert, key, handler)` is the same server over TLS
  with ALPN `h2` — the path browsers actually take — with the handshake itself
  pumped on the reactor (see below), so a peer that stalls mid-handshake stalls
  only itself. **`serveHttpsAlpnReactor(port, cert, key, handler)`** is what a
  real HTTPS port does: advertise `h2` *and* `http/1.1`, then serve each
  connection with whichever the client chose, from one handler. A short
  dispatcher coroutine owns the handshake (so the accept loop never suspends on
  one peer's) and then `spawn`s the protocol body — spawned, not called, because
  a coroutine that calls another suspending coroutine corrupts its frame.
  *Verified: interleaved h2 and http/1.1 clients on one port, plus h2spec
  146/146 against that same port* (`tests/reactor_alpn_e2e.sh`).
  *Verified: **h2spec 146/146 over both h2c and TLS** (`tests/h2spec.sh`) — was
  95/146 against the blocking server, which serves one connection at a time and
  so wedged on any connection left open — plus 20 concurrent requests with an
  idle connection parked (`tests/reactor_h2_e2e.sh`).*
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
  `serveWssReactor(port, cert, key, handler)` serves **wss://** from the same
  body. *Verified: 160/160 echo across 40 clients (`tests/reactor_ws_e2e.sh`)
  plus 19/19 conformance cases (`tests/reactor_ws_conformance.sh`) and 80/80
  across 20 simultaneous TLS clients (`tests/reactor_wss_e2e.sh`), on one
  thread.*
- **`serve/reactorall.nim`** — **HTTP/1.1 + HTTP/2 + HTTP/3 from one handler**,
  on one reactor, on one thread. `serveAllReactor(port, cert, key, handler)`
  serves TLS/TCP on `port` with ALPN dispatch and QUIC/UDP on the same port
  number, and stamps `Alt-Svc: h3=":<port>"` on every TCP response — without
  which a browser never tries HTTP/3 at all. HTTP/3's `(method, path, body)` is
  adapted to the `Request`/`Response` shape here, so callers write one handler.
  *Verified: all three protocols answering on one port, the HTTP/3 leg driven by
  third-party **aioquic**, one OS thread* (`tests/reactor_all_e2e.sh`).
- **`serve/reactorh3.nim`** — async **HTTP/3 (QUIC)**.
  `serveH3Reactor(port, cert, key, handler)` where `handler` is `proc(meth, path,
  body: string): H3Response`. The QUIC transport, TLS 1.3 handshake, connection-ID
  routing, timers, and the HTTP/3 (QPACK) layer live in the `quic/quicglue.c`
  glue shim (compiled against system **ngtcp2 + nghttp3 + GnuTLS**; build with
  `quic/build.sh`), exposed to nimony through a small pull-based API
  (`quic/quic.nim`). The reactor owns only the epoll wait on the single UDP fd,
  feeding datagram readiness and QUIC timer expiries into the shim. GET + POST.
  `spawnH3(r, srv, handler)` attaches it to a reactor someone else owns, which
  is how it shares a thread with the TCP servers. *Verified: 20 independent
  QUIC clients (20/20) on one thread* (`tests/reactor_h3_e2e.sh`); the pure-C
  harness is ASan/LSan-clean.

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

All three TCP servers use a module-global `{.nimcall.}` handler (the `pool.nim` pattern) rather
than a captured closure, which composes cleanly across the coroutine boundary,
and flag-based control flow throughout (no `break`/`return` beside a `suspend`).

The blocking worker-pool servers (`serve/loop.nim`, `serve/pool.nim`) remain for
callers that want thread-per-connection; the reactor variants are the
single-thread-multiplexing alternative for high connection counts.
