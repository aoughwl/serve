## serve — an HTTP/1.1 static-file server on `std/ioring` (io_uring-style TCP;
## Linux-only). It depends on the generic `aoughwl/http` helper pack but does
## NOT depend on the aoughwl substrate or ui/web/html/css packs.
##
##   import aoughwl/serve/serve
##
##   serve("/var/www", 8080)          # loop forever
##   serve("/var/www", 8080, 3)       # serve 3 requests then return (tests)
##
## API surface:
##   * `serve(root, port, maxRequests = 0)`  — the accept/serve loop (loop.aowl)
##   * generic HTTP helpers                  — re-exported from `aoughwl/http`
##   * `serveFile`, `staticResponse`         — URL->file routing (static.aowl)

import http/headers
import http/url
import http/request
import http/response
import serve/static
import serve/loop
export headers, url, request, response, static, loop
