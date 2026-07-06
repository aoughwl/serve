# serve

A pure-nimony **HTTP/1.1 static-file server** built on `std/ioring`
(io_uring-style async TCP; Linux-only).

Generic HTTP helpers live in the separate [`aoughwl/http`](../http) pack:
headers, URL/query/form helpers, request parsing, status metadata, and response
building. `serve` consumes and re-exports that package, but keeps sockets and
static-file routing in this package.

No aoughwl substrate, ui, web, html, or css pack dependency.

```nim
import serve

serve("/var/www", 8080)        # serve forever
serve("/var/www", 8080, 3)     # serve 3 requests then return (handy for tests)

var opts = defaultServeOptions()
opts.maxConnections = 32
opts.maxRequestBytes = 8192
opts.maxResponseBytes = 512 * 1024
serveWithOptions("/var/www", 8080, opts)
```

## API

| symbol | from | role |
|--------|------|------|
| `serve(root, port, maxRequests = 0)` | `serve/loop` | the accept/serve loop over io_uring |
| `ServeOptions`, `defaultServeOptions`, `serveWithOptions` | `serve/loop` | configured server limits |
| `Header`, `Request`, `Response`, `parseRequest`, `httpResponse`, URL helpers | `http` | re-exported generic HTTP layer |
| `contentTypeFor`, `normalizeUrlPath`, `relativePath`, `staticResponse`, `serveFile` | `serve/static` | URL → file routing + content-type |

`serve/http` is a compatibility umbrella that re-exports `aoughwl/http`:

```nim
import serve/http

let req = parseRequest("GET /search?q=nimony HTTP/1.1\r\nHost: example\r\n\r\n")
assert req.isMethod("GET")
assert queryParam(req.path, "q") == "nimony"
```

## Notes

* **Linux-only** — it uses io_uring via `std/ioring`. Showcase-grade, not
  hardened for the open internet.
* **Clean module boundaries** — generic HTTP code lives in `aoughwl/http`;
  static file handling lives in `serve/static`; sockets live in `serve/loop`.
* **Nimony-friendly** — parsing char-walks rather than slicing where practical
  because nimony string slices are `.raises`.
* **Static serving behavior** — supports `GET`, `HEAD`, and `OPTIONS`, strips
  query/fragment, percent-decodes paths, rejects `..` path segments, maps `/`
  to `/index.html`, and emits MIME types for common web assets.
* **Per-connection buffers** — each accepted connection owns its read/write
  buffers, so in-flight responses do not overwrite each other.
* **Fixed implementation caps** — `serveWithOptions` can lower limits at
  runtime, but this ioring implementation is capped at 64 connections, 16 KiB
  request reads, and 1 MiB response staging.
* **Partial writes handled** — if the OS writes only part of a response, `serve`
  submits the remaining bytes before closing the connection.

## Provenance

This `.nim` package is a generated mirror of the `.aowl` sources authored in the
[aoughwl](https://github.com/aoughwl) monorepo (`packs/aoughwl/serve/`). Same
code, published under the extension the wider nim/nimony world recognises.

## License

MIT.
