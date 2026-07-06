## serve — an HTTP/1.1 static-file server on `std/ioring` (io_uring-style TCP;
## Linux-only). It depends on the generic `http` helper package and has no
## framework dependency.
##
##   import serve
##
##   serve("/var/www", 8080)          # loop forever
##   serve("/var/www", 8080, 3)       # serve 3 requests then return (tests)
##
## API surface:
##   * `serve(root, port, maxRequests = 0)`  — the accept/serve loop
##   * generic HTTP helpers                  — re-exported from `http`
##   * `serveFile`, `staticResponse`         — URL->file routing (static.aowl)

import http/headers
import http/url
import http/request
import http/response
import serve/static
import serve/loop
export headers, url, request, response, static, loop
