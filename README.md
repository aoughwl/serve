# serve

A pure-nimony **HTTP/1.1 static-file server** built on `std/ioring`
(io_uring-style async TCP; Linux-only).

Generic HTTP helpers live in the separate `http` package: headers, URL/query/form
helpers, request parsing, status metadata, and response building. `serve`
consumes and re-exports that package, but keeps sockets and static-file routing
in this package.

No framework dependency.

```nim
import serve

serve("/var/www", 8080)        # serve forever
serve("/var/www", 8080, 3)     # serve 3 requests then return (handy for tests)
```

## API

| symbol | from | role |
|--------|------|------|
| `serve(root, port, maxRequests = 0)` | `serve/loop` | the accept/serve loop over io_uring |
| `Header`, `Request`, `Response`, `parseRequest`, `httpResponse`, URL helpers | `http` | re-exported generic HTTP layer |
| `contentTypeFor`, `normalizeUrlPath`, `relativePath`, `staticResponse`, `serveFile` | `serve/static` | URL → file routing + content-type |

`serve/http` is a compatibility umbrella that re-exports the generic `http`
helpers:

```nim
import serve/http

let req = parseRequest("GET /search?q=nimony HTTP/1.1\r\nHost: example\r\n\r\n")
assert req.isMethod("GET")
assert queryParam(req.path, "q") == "nimony"
```

## Notes

* **Linux-only** — it uses io_uring via `std/ioring`. Showcase-grade, not
  hardened for the open internet.
* **Clean module boundaries** — generic HTTP code lives in `http`; static file
  handling lives in `serve/static`; sockets live in `serve/loop`.
* **Nimony-friendly** — parsing char-walks rather than slicing where practical
  because nimony string slices are `.raises`.
* **Static serving behavior** — supports `GET`, `HEAD`, and `OPTIONS`, strips
  query/fragment, percent-decodes paths, rejects `..` path segments, maps `/`
  to `/index.html`, and emits MIME types for common web assets.
* **Simple transport** — one read, one write, then close. The current loop uses
  fixed module-level buffers and is suitable for local/dev/showcase serving,
  not open-internet hardening.

## License

MIT.
