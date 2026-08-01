## The router, served asynchronously — routes, path parameters, middleware and
## a custom 404, over HTTP/1.1 + HTTP/2 + HTTP/3 on one thread.
##
##   bin/reactor_router 8443 cert.pem key.pem &
##   curl -k --http2 https://127.0.0.1:8443/users/42
##
## `toHandler` hands back the `{.nimcall.}` entry point, which is the same shape
## every reactor server takes — so the router composes with the async stack the
## same way it does with the blocking one, and the request-scoped state
## (`param`, `wildcard`) keeps working because dispatch is a plain call inside
## the connection coroutine.

import std/[cmdline, strutils]
import serve
import serve/router
import serve/reactorall

proc showUser(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "user " & param(req, "id") & "\n")

proc listUsers(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "all users\n")

proc createUser(req: Request): Response {.nimcall.} =
  response(201, "text/plain", "created: " & req.body & "\n")

proc missing(req: Request): Response {.nimcall.} =
  response(404, "text/plain", "no route for " & req.path & "\n")

var port = 8443
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"

let r = newRouter()
r.get("/users", listUsers)
r.get("/users/:id", showUser)
r.post("/users", createUser)
r.notFound(missing)

serveAllReactor(port, certFile, keyFile, r.toHandler())
