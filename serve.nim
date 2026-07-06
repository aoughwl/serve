## serve — an HTTP/1.1 static-file server. It depends on the generic `http`
## helper package and has no framework dependency.
##
##   import serve
##
##   serve("/var/www", 8080)          # loop forever
##   serve("/var/www", 8080, 3)       # serve 3 requests then return (tests)
##
## API surface:
##   * `serve(root, port, maxRequests = 0)`  — the accept/serve loop
##   * generic HTTP helpers                  — re-exported from `http`
##   * `TcpCompletion`, TCP primitives       — transport abstraction
##   * `serveFile`, `staticResponse`         — URL->file routing (static.aowl)

import http/headers
import http/url
import http/request
import http/response
import serve/static
import serve/tcp
import serve/loop
export headers, url, request, response, static, tcp, loop
