# serve

A high-level HTTP/1.1 server for [Nimony](https://github.com/nim-lang/nimony) —
the top of the `tcp → net → serve` stack. It pairs the transport-free
`http` helpers (which it consumes and re-exports) with the
native `tcp` transport (also re-exported) to run a real
**programmable** server: pass a handler and return whatever `Response` you like,
or drop in the built-in static-file handler. No framework runtime; nimony-native
throughout; a caller-owned handler closure decides every response; failures are
status codes, not exceptions.

## Contents

- [Motivation](#motivation)
- [Capabilities](#capabilities)
- [API](#api)
- [Layout](#layout)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Testing](#testing)
- [Requirements](#requirements)
- [License](#license)

## Motivation

Nim 2's `std/asynchttpserver` is the stdlib comparison, but it is built on the
async runtime, exceptions, and closures Nimony does not yet want to depend on.
`serve` provides the same "hand me a request, take a response" shape on a
blocking `tcp` transport with an explicit, exception-free contract:

| Problem with the Nim2 stdlib path | `serve`'s approach |
|-----------------------------------|--------------------|
| `asynchttpserver` requires the `async`/`Future` runtime and `{.async.}` callbacks | `serve(port, handler)` runs a plain blocking accept loop; the handler is a `proc(req: Request): Response {.closure.}`. |
| Request bodies arrive through async reads with framework-managed limits | The loop reads a **complete** request (headers, then the `Content-Length` body) with an explicit `MaxRequestBytes` cap → `413`. |
| Responses go out through the async writer | Responses are **streamed** through `writeAllTcp` in chunks with **no size cap**; `Content-Length` always matches the bytes written. |
| Errors surface as raised exceptions across the async boundary | Everything is status-based; the loop never raises across the handler. |

## Capabilities

Everything below is exercised by the end-to-end test against the real accept
loop; ✅ marks the current behavior.

| Capability | Behavior | |
|------------|----------|---|
| Programmable handler | `serve(port, handler)` — the handler's `Response` is returned verbatim | ✅ |
| Static-file serving | `staticHandler(root)` / `serve(root, port)`: `GET`/`HEAD`/`OPTIONS`, `/`→`/index.html`, MIME by extension | ✅ |
| Full-request reads | accumulate to the header terminator, then read the `Content-Length` body | ✅ |
| Request size cap | requests over `MaxRequestBytes` (8 MB) get `413 Payload Too Large` | ✅ |
| Streamed responses | header then body streamed via `writeAllTcp`, **no truncation**, any size | ✅ |
| HTTP/1.1 keep-alive | multiple requests per socket (up to `MaxKeepAliveRequests`), correct `Connection` headers | ✅ |
| Slowloris guard | per-socket `ReadTimeoutMillis` (15 s) blocking read timeout | ✅ |
| Path safety | percent-decode, strip query/fragment, reject `..` segments → `403` | ✅ |
| Bounded runs | `maxRequests` arg serves N connections then returns (handy for tests) | ✅ |

## API

Everything is available from `import serve`, which re-exports the `http` and
`tcp` layers alongside its own symbols.

### The server (`serve/loop`)

| Symbol | Role | |
|--------|------|---|
| `serve(port, handler, maxRequests = 0)` | programmable request/response loop | ✅ |
| `serve(root, port, maxRequests = 0)` | static-file loop (built on `staticHandler`) | ✅ |
| `Handler` | `proc(req: Request): Response {.closure.}` handler type | ✅ |
| `serveConnection` | drive one already-accepted connection (the loop's core) | ✅ |
| `staticHandler`, `staticRoute` | build a static-file handler / route a request to a file | ✅ |
| `MaxRequestBytes`, `MaxKeepAliveRequests`, `ReadTimeoutMillis` | tunable limits (413 cap / keep-alive count / read timeout) | ✅ |

### Static routing (`serve/static`)

| Symbol | Role | |
|--------|------|---|
| `contentTypeFor` | MIME type for a path's extension | ✅ |
| `normalizeUrlPath`, `relativePath` | strip query/fragment + percent-decode; map URL path → filesystem path | ✅ |
| `serveFile`, `staticResponse`, `staticResponseObj` | read a file into a response (string / `Response`) | ✅ |

### Re-exported layers

| From | Symbols |
|------|---------|
| `http` | `Header`, `Request`, `Response`, `parseRequest`, `response`, `httpResponse`, `HttpMethod`, `HttpCode`, URL/query/form helpers, chunked codec |
| `tcp` | `TcpHandle`, `listenTcp`, `acceptTcp`, `readTcp`, `writeTcp`, `writeAllTcp`, `closeTcp`, … |

```nim
import serve

# Programmable: your closure decides every response. Nimony requires the
# `.closure` pragma — a plain `.nimcall` proc will NOT convert to `Handler`.
proc handler(req: Request): Response {.closure.} =
  if req.path == "/health":
    return response(200, "text/plain", "ok\n")
  response(404, "text/plain", "not found\n")

serve(8080, handler)               # loop forever
serve(8080, handler, 3)            # serve 3 connections then return (tests)

# Static-file server — the same loop with the built-in handler:
serve("/var/www", 8080)            # serve forever
serve(8080, staticHandler("/var/www"))   # equivalent
```

## Layout

```
serve/
├── serve.nim           umbrella: re-exports http, tcp, serve/static, serve/loop
├── serve/
│   ├── http.nim        compatibility umbrella re-exporting the generic http layer
│   ├── loop.nim        accept loop, serveConnection, keep-alive, request/413 caps,
│   │                   streamed responses, the serve() overloads + staticHandler
│   └── static.nim      URL→file routing, content types, path-safety, file reads
├── tests/
│   ├── tserve_api.nim  compile-time API smoke (both serve overloads + Handler)
│   └── tserve_e2e.nim  real end-to-end test against the live accept loop
├── serve.nimble        requires "http", "tcp"
└── README.md
```

## Design notes

- **Programmable first.** The core is the handler loop; static serving is just
  `serve(port, staticHandler(root))`. Handlers are `{.closure.}` procs (nimony
  requires the pragma to convert to `Handler`, and closures may capture config
  such as a root directory).
- **Clean layer boundaries.** Generic HTTP lives in `http`;
  the socket transport lives in `tcp`; this package only owns
  the accept loop (`serve/loop`) and static file routing (`serve/static`).
- **Caller-owned, no runtime.** The loop reads into fixed buffers and streams
  responses through `tcp`'s `writeAllTcp`; there is no async runtime and no
  framework dependency.
- **Streamed, uncapped responses.** The response header is written, then the body
  is streamed in chunks with no truncation — the old fixed 1 MB response buffer
  (which truncated larger bodies while `Content-Length` still reported the full
  size) is gone, so `Content-Length` now always matches the bytes written.
- **Char-walk parsing, status-based errors.** Request handling walks characters
  rather than slicing (nimony string slices are `.raises`) and reports failure as
  responses/status, never exceptions.

## Limitations

Single-connection and plaintext today; the roadmap to fully exceed
`asynchttpserver`:

- **Single connection at a time** — a blocking accept loop, no concurrency
  (suitable for local/dev/showcase serving, not open-internet hardening).
- **No HTTP pipelining** — one request per read cycle; extra bytes past a single
  request on a kept-alive socket are not buffered for the next iteration.
- **No TLS/SSL** — plaintext HTTP only.
- **IPv4 only** — inherited from the `tcp` transport (no IPv6).
- HTTP/1.x only — no HTTP/2 or HTTP/3.

## Testing

Two tests. `tserve_api.nim` is a compile-time smoke confirming both `serve`
overloads resolve and the handler API is wired. `tserve_e2e.nim` runs the
**actual** server (`serveConnection`, the same code path `serve` uses) on a
background thread bound to an ephemeral port and drives a blocking loopback
client: a custom handler's 200 body returns verbatim, a >1 MB body round-trips
intact (proving the removed response cap), a static root returns file bytes, a
`..` path is rejected (`403`), and an unknown path `404`s.

```bash
cd /home/savant/aoughwl-serve
nimony c -r --path:/home/savant/aoughwl-serve --path:/home/savant/aoughwl-http --path:/home/savant/aoughwl-tcp tests/tserve_e2e.nim   # prints: tserve_e2e: all checks passed
nimony c -r --path:/home/savant/aoughwl-serve --path:/home/savant/aoughwl-http --path:/home/savant/aoughwl-tcp tests/tserve_api.nim   # compiles clean
```

## Requirements

A built [Nimony](https://github.com/nim-lang/nimony) toolchain providing the
`nimony` compiler on `PATH`, and the sibling `http` and
`tcp` packages on the module path (`--path`). No third-party
dependencies.

## License

MIT.
