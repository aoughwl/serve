# serve

A pure-nimony **programmable HTTP/1.1 server** with a small TCP transport
abstraction. Bring your own request handler, or use the built-in static-file
handler.

Generic HTTP helpers live in the separate `http` package: headers, URL/query/form
helpers, request parsing, status metadata, and response building. `serve`
consumes and re-exports that package, but keeps sockets and routing in this
package.

Native TCP primitives live in the separate `tcp` package and are re-exported by
`serve`.

No framework dependency.

## Programmable server (handler API)

Pass a handler and return whatever `Response` you like. Handlers are
`proc(req: Request): Response {.closure.}` — nimony requires the `.closure`
pragma (a plain `.nimcall` proc will **not** convert to the handler type), and
closures may capture state such as a config value or a root directory.

```nim
import serve

proc handler(req: Request): Response {.closure.} =
  if req.path == "/health":
    return response(200, "text/plain", "ok\n")
  response(404, "text/plain", "not found\n")

serve(8080, handler)           # loop forever
serve(8080, handler, 3)        # serve 3 connections then return (handy for tests)
```

The connection loop reads a **complete** request (all headers, then the body per
`Content-Length`), calls the handler, and **streams** the response back with no
fixed size cap. HTTP/1.1 **keep-alive** is honored: multiple requests are served
on one socket until the client closes, sends `Connection: close`, or an error
occurs (`Connection: keep-alive` opts an HTTP/1.0 client in).

## Static-file server

The classic static server is just the handler API with `staticHandler`:

```nim
import serve

serve("/var/www", 8080)        # serve forever
serve("/var/www", 8080, 3)     # serve 3 connections then return

# equivalently:
serve(8080, staticHandler("/var/www"))
```

## API

| symbol | from | role |
|--------|------|------|
| `serve(port, handler, maxRequests = 0)` | `serve/loop` | programmable request/response loop |
| `serve(root, port, maxRequests = 0)` | `serve/loop` | static-file loop (built on `staticHandler`) |
| `Handler`, `serveConnection`, `staticHandler`, `staticRoute` | `serve/loop` | handler API + one-connection driver |
| `Header`, `Request`, `Response`, `parseRequest`, `response`, `httpResponse`, URL helpers | `http` | re-exported generic HTTP layer |
| `TcpHandle`, `listenTcp`, `acceptTcp`, `readTcp`, `writeTcp`, `closeTcp` | `tcp` | native TCP abstraction |
| `contentTypeFor`, `normalizeUrlPath`, `relativePath`, `staticResponse`, `staticResponseObj`, `serveFile` | `serve/static` | URL → file routing + content-type |

`serve/http` is a compatibility umbrella that re-exports the generic `http`
helpers:

```nim
import serve/http

let req = parseRequest("GET /search?q=nimony HTTP/1.1\r\nHost: example\r\n\r\n")
assert req.isMethod("GET")
assert queryParam(req.path, "q") == "nimony"
```

## Notes

* **Transport boundary** — `serve/loop` uses the standalone `tcp` package.
* **Clean module boundaries** — generic HTTP code lives in `http`; static file
  handling lives in `serve/static`; the socket loop lives in `serve/loop`.
* **Nimony-friendly** — parsing char-walks rather than slicing where practical
  because nimony string slices are `.raises`; handlers are `.closure` procs.
* **Static serving behavior** — supports `GET`, `HEAD`, and `OPTIONS`, strips
  query/fragment, percent-decodes paths, rejects `..` path segments, maps `/`
  to `/index.html`, and emits MIME types for common web assets.
* **Full-request reads** — the loop accumulates until the header terminator,
  then reads the `Content-Length` body; requests over 8 MB get `413`, and a
  15 s read timeout guards against slowloris-style stalls.
* **Streamed responses (no cap)** — the response header is written, then the
  body is streamed through `writeAllTcp` in chunks with **no truncation**. The
  old fixed 1 MB response buffer (which silently truncated larger bodies while
  `Content-Length` still reported the full size) is gone; `Content-Length` now
  always matches the bytes actually written.
* **Keep-alive** — HTTP/1.1 connections are reused (up to
  `MaxKeepAliveRequests`) with correct `Connection` headers.
* **Scope** — single connection at a time (blocking accept loop), suitable for
  local/dev/showcase serving, not open-internet hardening. HTTP pipelining is
  not handled (one request per read cycle).

## License

MIT.
