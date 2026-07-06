# serve

A minimal, pure-nimony **HTTP/1.1 static-file server** built on `std/ioring`
(io_uring-style async TCP; Linux-only). **Standard-library only** — it does not
depend on the aoughwl substrate or the ui/web/html/css packs, so it stays a
clean, independently reusable HTTP lib.

```nim
import serve

serve("/var/www", 8080)        # serve forever
serve("/var/www", 8080, 3)     # serve 3 requests then return (handy for tests)
```

## API

| symbol | from | role |
|--------|------|------|
| `serve(root, port, maxRequests = 0)` | `serve/loop` | the accept/serve loop over io_uring |
| `Request`, `parseRequest` | `serve/http` | tolerant HTTP/1.1 request-line parsing |
| `httpResponse(status, contentType, body)`, `reasonPhrase` | `serve/http` | response building |
| `serveFile(root, urlPath)` | `serve/static` | URL → file routing + content-type |

## Notes

* **Linux-only** — it uses io_uring via `std/ioring`. Showcase-grade, not
  hardened for the open internet.
* **Non-raising / allocation-frugal** — request parsing char-walks rather than
  slicing (nimony string slices are `.raises`), and file I/O is wrapped so the
  public procs stay `.raises`-clean.

## Provenance

This `.nim` package is a generated mirror of the `.aowl` sources authored in the
[aoughwl](https://github.com/aoughwl) monorepo (`packs/aoughwl/serve/`). Same
code, published under the extension the wider nim/nimony world recognises.

## License

MIT.
