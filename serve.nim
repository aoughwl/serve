## serve — a minimal, pure-nimony HTTP/1.1 static-file server on `std/ioring`
## (io_uring-style TCP; Linux-only). Standard-library only — it does NOT depend
## on the aoughwl substrate or the ui/web/html/css packs, so it stays a clean,
## independently reusable HTTP lib.
##
##   import aoughwl/serve/serve
##
##   serve("/var/www", 8080)          # loop forever
##   serve("/var/www", 8080, 3)       # serve 3 requests then return (tests)
##
## API surface:
##   * `serve(root, port, maxRequests = 0)`  — the accept/serve loop (loop.aowl)
##   * `Request`, `parseRequest`, `httpResponse`, `reasonPhrase`  (http.aowl)
##   * `serveFile(root, urlPath)`            — URL->file routing (static.aowl)

import serve/http
import serve/static
import serve/loop
export http, static, loop
