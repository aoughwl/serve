## tserve_api.aowl — public API smoke test for serve.

import serve

var fd = InvalidTcpHandle
discard fd

discard contentTypeFor("/tmp/index.html")
discard normalizeUrlPath("/x?q=1")
discard httpResponse(200, "text/plain", "ok")

# Compile-only: confirm both `serve` overloads resolve and the handler API is
# wired up. Guarded by `false` so the accept loop never actually runs here.
let h: Handler = staticHandler("/tmp/www")
discard h
if false:
  serve("/tmp/www", 8080, 1)          # static-file overload (root: string)
  serve(8080, staticHandler("/x"), 1) # programmable overload (port: int, handler)
