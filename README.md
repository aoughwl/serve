# serve

A high-level, programmable HTTP server for
[Nimony](https://github.com/nim-lang/nimony) — the top of the `tcp → net → serve`
stack. Pairs the transport-free `http` helpers with the native `tcp` transport
(both re-exported). Pass a handler, return any `Response`; or drop in the built-in
static-file handler. Status-based, no framework runtime.

**📖 Full docs → [aoughwl.github.io/docs/net-stack](https://aoughwl.github.io/docs/net-stack)**

```nim
import serve

serve(8080, proc(req: Request): Response {.closure.} =
  ok("hello"))
```

Keep-alive, request-size cap (`413`), streamed responses (no truncation), slowloris
guard, path-traversal safety, and `staticHandler(root)` for static serving.

## HTTP/1.1, HTTP/2 and HTTP/3, on one thread

`serve/reactor.nim` is a single-threaded epoll scheduler built on Nimony's
passive procs; the async servers ride on it, one coroutine per connection.

```nim
import serve, serve/reactorall

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

serveAllReactor(8443, "cert.pem", "key.pem", handler)
```

That serves TLS/TCP with ALPN dispatch (`h2` or `http/1.1`) **and** QUIC/UDP on
the same port number, from one handler, on one OS thread — with
`Alt-Svc: h3=":8443"` on every TCP response so browsers find the HTTP/3 side.
Individually: `serveHttpReactor` / `serveHttpsReactor` (HTTP/1.1),
`serveHttp2Reactor` / `serveHttp2TlsReactor` / `serveHttpsAlpnReactor` (HTTP/2),
`serveWsReactor` / `serveWssReactor` (WebSocket), `serveH3Reactor` (HTTP/3, plus
WebTransport). Idle timeouts and graceful SIGINT/SIGTERM shutdown come with the
reactor; the TLS entry points take a `TlsContext` you built, so cipher suites,
protocol versions, post-quantum groups and SNI certificates stay reachable.

Verified by the gates in `tests/`: **h2spec 146/146** over both h2c and TLS,
Autobahn-grade WebSocket conformance, third-party (aioquic) HTTP/3 interop, and
the concurrency and shutdown properties asserted directly rather than by proxy.
