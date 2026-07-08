## serve — a programmable HTTP/1.1 server. It depends on the generic `http`
## helper package and has no framework dependency.
##
##   import serve
##
##   # Programmable: your handler decides every response. Handlers are
##   # `{.closure.}` (nimony requires the pragma; they may capture state).
##   proc hello(req: Request): Response {.closure.} =
##     response(200, "text/plain", "hi " & req.path & "\n")
##   serve(8080, hello)               # loop forever
##
##   # Static-file server (built on the same handler loop).
##   serve("/var/www", 8080)          # loop forever
##   serve("/var/www", 8080, 3)       # serve 3 connections then return (tests)
##
## API surface:
##   * `serve(port, handler, maxRequests = 0)` — programmable request/response loop
##   * `serve(root, port, maxRequests = 0)`    — static-file loop (uses `staticHandler`)
##   * `Handler`, `serveConnection`, `staticHandler`, `staticRoute` — handler API
##   * generic HTTP helpers                    — re-exported from `http`
##   * `TcpHandle`, TCP primitives             — re-exported from `tcp`
##   * `serveFile`, `staticResponse`           — URL->file routing (static.aowl)

import http/headers
import http/url
import http/request
import http/response
import tcp
import tls
import serve/static
import serve/loop
import serve/pool
import serve/encoding
export headers, url, request, response, static, tcp, loop, pool
export tls, encoding
