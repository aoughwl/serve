## serve/router.aowl — an opt-in routing + middleware layer over `serve`.
##
##   import serve
##   import serve/router
##
##   proc getUser(req: Request): Response {.nimcall.} =
##     response(200, "text/plain", "user " & param(req, "id") & "\n")
##
##   proc logging(req: Request; nxt: Chain): Response {.nimcall.} =
##     let resp = proceed(nxt, req)          # run the rest of the chain + handler
##     echo req.meth, " ", req.path, " -> ", resp.status
##     return resp
##
##   var r = newRouter()
##   r.use(logging)                          # middleware, runs in registration order
##   r.get("/users/:id", getUser)            # method + path, `:id` is a path param
##   r.get("/static/*", serveAsset)          # trailing `*` captures the rest of the path
##   r.post("/users", createUser)
##   r.notFound(myNotFound)                  # optional custom 404
##   serveRouter(8080, r)                     # run the loop, or:
##   serveConnectionNimcall(fd, r.toHandler)  # drive a single connection yourself
##
## Matching is on METHOD + PATH:
##   * no path matches                     -> 404 (or the `notFound` handler);
##   * a path matches but not the method   -> 405 with an `Allow` header;
##   * `HEAD` falls back to a `GET` route  (the loop omits the body for HEAD).
##
## Path parameters and the trailing wildcard are captured INTO the request and
## read back with `param(req, "id")` / `wildcard(req)`. They ride as reserved
## pseudo-headers under a control-character prefix that a conforming HTTP client
## cannot inject (and any spoofed copies are stripped before dispatch), so
## `param` only ever returns router-populated values.
##
## nimony design note: handlers and middleware are `{.nimcall.}` function
## pointers, NOT closures. This is a hard requirement, not a style choice — the
## current nimony C backend miscompiles a closure stored inside a `seq`/object
## field (and cannot pass a closure as a parameter of another closure, which the
## classic `next: Handler` middleware shape needs). Storing plain function
## pointers sidesteps both. The bonus: because the whole router is `{.nimcall.}`,
## it is also compatible with the threaded worker pool (`serveConnectionTls`-
## Nimcall etc.), not just the single-threaded path. State that a handler would
## have captured must come from globals; per-request data travels on the request.
##
## The middleware continuation is passed as a plain `Chain` value (an index into
## the chain), advanced with `proceed(nxt, req)` — the nimony-idiomatic stand-in
## for calling `next(req)`.

import http/headers
import http/request
import http/response
import tcp
import loop

const ParamPrefix = "\x1f\x1fserve-param-"
  ## Reserved header-name prefix for captured params. Starts with control bytes
  ## (0x1F "unit separator"), which are illegal in an HTTP header name, so a
  ## conforming client cannot forge one; incoming headers with this prefix are
  ## stripped before dispatch regardless.

type
  RouteHandler* = proc(req: Request): Response {.nimcall.}
    ## A route handler — the same shape as `serve`'s `NimcallHandler`. Reads the
    ## request (including captured params via `param`) and returns the response.

  Chain* = object
    ## Opaque continuation handed to a middleware: it identifies the router and
    ## the next position in the chain. Advance it with `proceed(nxt, req)`.
    rid*: int
    idx*: int

  Middleware* = proc(req: Request; nxt: Chain): Response {.nimcall.}
    ## Wraps the downstream chain: run logic before/after `proceed(nxt, req)`,
    ## short-circuit by never calling it, or rewrite the returned response.
    ## Middlewares compose in registration order — the first `use`d is outermost.

  Route = object
    meth: string          ## upper-case HTTP method
    segs: seq[string]     ## pattern split on '/'; ":name" = param, "*" = wildcard
    handler: RouteHandler

  RouterData = object
    routes: seq[Route]
    mws: seq[Middleware]
    notFoundH: RouteHandler
    hasNotFound: bool

  Router* = object
    ## A handle to a registered router. The route/middleware tables live in a
    ## module-global registry (function pointers cannot be captured), and this
    ## object is just the small integer id into it.
    id*: int

var gReg: seq[RouterData] = @[]
  ## Registry of all routers. Indexed by `Router.id`.
var gActive = 0
  ## The router id the `{.nimcall.}` dispatcher serves. Set by `toHandler` /
  ## `serveRouter`. A `{.nimcall.}` proc carries no state, so one router is the
  ## active dispatcher at a time (the most recently installed) — fine for the
  ## usual single-server process.

proc newRouter*(): Router =
  ## Create an empty router (no routes, no middleware, default 404) and return a
  ## handle to it.
  gReg.add RouterData(routes: @[], mws: @[], hasNotFound: false)
  Router(id: gReg.len - 1)

# ---------------------------------------------------------------------------
# small string helpers (nimony string slices are `.raises`, so we char-walk)
# ---------------------------------------------------------------------------

proc asciiUpperCh(c: char): char =
  if c >= 'a' and c <= 'z': chr(ord(c) - 32) else: c

proc upperAscii(s: string): string =
  result = ""
  var i = 0
  while i < s.len:
    result.add asciiUpperCh(s[i])
    inc i

proc startsWith(s, prefix: string): bool =
  if prefix.len > s.len: return false
  var i = 0
  while i < prefix.len:
    if s[i] != prefix[i]: return false
    inc i
  return true

proc dropLeading(s: string; c: char): string =
  ## Return `s` with a single leading `c` removed (drops the ':' on a param).
  result = ""
  var i = 0
  if s.len > 0 and s[0] == c:
    i = 1
  while i < s.len:
    result.add s[i]
    inc i

proc splitPath(p: string): seq[string] =
  ## Split a request-target path on '/', dropping the query/fragment and empty
  ## segments (so "/", "/a/", "//a" all normalize sensibly).
  result = @[]
  var cur = ""
  var i = 0
  while i < p.len and p[i] != '?' and p[i] != '#':
    if p[i] == '/':
      if cur.len > 0:
        result.add cur
        cur = ""
    else:
      cur.add p[i]
    inc i
  if cur.len > 0:
    result.add cur

# ---------------------------------------------------------------------------
# param capture / read-back
# ---------------------------------------------------------------------------

proc withParams(req: Request; keys, vals: seq[string]): Request =
  ## Copy `req`, strip any client-supplied headers under the reserved prefix,
  ## then inject the captured params as reserved pseudo-headers.
  result = req
  var clean: seq[Header] = @[]
  var i = 0
  while i < result.headers.len:
    if not startsWith(lowerAscii(result.headers[i].name), ParamPrefix):
      clean.add result.headers[i]
    inc i
  result.headers = clean
  var j = 0
  while j < keys.len:
    result.headers.add Header(name: ParamPrefix & keys[j], value: vals[j])
    inc j

proc param*(req: Request; name: string): string =
  ## The captured value of path parameter `name` (e.g. `:id`), or "" if absent.
  headerValue(req.headers, ParamPrefix & name)

proc hasParam*(req: Request; name: string): bool =
  ## Whether path parameter `name` was captured (distinguishes an empty value
  ## from an absent one).
  var i = 0
  let key = ParamPrefix & name
  while i < req.headers.len:
    if eqIgnoreCase(req.headers[i].name, key):
      return true
    inc i
  return false

proc wildcard*(req: Request): string =
  ## The remainder captured by a trailing `*` in the route pattern (e.g. for
  ## pattern `/static/*` and path `/static/js/app.js`, this is "js/app.js").
  param(req, "*")

# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------

proc tryMatch(route: Route; segs: seq[string]; keys, vals: var seq[string]): bool =
  ## Match `route.segs` against the request path segments, capturing params and
  ## the wildcard into `keys`/`vals`. A `*` segment matches all remaining
  ## segments (joined by '/') and is terminal.
  var ri = 0
  var si = 0
  while ri < route.segs.len:
    let rs = route.segs[ri]
    if rs == "*":
      var rest = ""
      while si < segs.len:
        if rest.len > 0: rest.add "/"
        rest.add segs[si]
        inc si
      keys.add "*"
      vals.add rest
      return true
    if si >= segs.len:
      return false
    if rs.len > 0 and rs[0] == ':':
      keys.add dropLeading(rs, ':')
      vals.add segs[si]
    else:
      if rs != segs[si]:
        return false
    inc ri
    inc si
  return si == segs.len

proc methodMatches(routeMeth, reqMeth: string): bool =
  ## Exact (case-insensitive) method match, with HEAD falling back to GET.
  if eqIgnoreCase(routeMeth, reqMeth):
    return true
  return eqIgnoreCase(reqMeth, "HEAD") and eqIgnoreCase(routeMeth, "GET")

proc addAllow(allowed: var seq[string]; meth: string) =
  ## Accumulate a unique method into the Allow set; a GET route also allows HEAD.
  var i = 0
  while i < allowed.len:
    if eqIgnoreCase(allowed[i], meth): return
    inc i
  allowed.add upperAscii(meth)
  if eqIgnoreCase(meth, "GET"):
    addAllow(allowed, "HEAD")

proc joinComma(parts: seq[string]): string =
  result = ""
  var i = 0
  while i < parts.len:
    if i > 0: result.add ", "
    result.add parts[i]
    inc i

proc dispatchCore(rid: int; req: Request): Response =
  ## Route one request against router `rid`: run the method+path match's handler,
  ## else 405 (path matched, wrong method) or 404 (no path match).
  let segs = splitPath(req.path)
  var allowed: seq[string] = @[]
  var pathMatched = false
  var i = 0
  while i < gReg[rid].routes.len:
    var keys: seq[string] = @[]
    var vals: seq[string] = @[]
    if tryMatch(gReg[rid].routes[i], segs, keys, vals):
      pathMatched = true
      if methodMatches(gReg[rid].routes[i].meth, req.meth):
        let req2 = withParams(req, keys, vals)
        let h = gReg[rid].routes[i].handler
        return h(req2)
      addAllow(allowed, gReg[rid].routes[i].meth)
    inc i
  if pathMatched:
    var resp = response(405, "text/plain", "Method Not Allowed\n")
    resp.withHeader("Allow", joinComma(allowed))
    return resp
  if gReg[rid].hasNotFound:
    let nf = gReg[rid].notFoundH
    return nf(req)
  return response(404, "text/plain", "Not Found\n")

proc runFrom(rid: int; idx: int; req: Request): Response =
  ## Run the middleware chain of router `rid` starting at `idx`, then routing.
  if idx < gReg[rid].mws.len:
    let m = gReg[rid].mws[idx]
    return m(req, Chain(rid: rid, idx: idx + 1))
  return dispatchCore(rid, req)

proc proceed*(nxt: Chain; req: Request): Response =
  ## From inside a middleware, run the rest of the chain and the matched handler.
  ## The idiomatic stand-in for calling `next(req)`.
  runFrom(nxt.rid, nxt.idx, req)

proc dispatch*(r: Router; req: Request): Response =
  ## Route a single request through router `r` directly (middleware included),
  ## without going through the `serve` loop — handy for unit tests.
  runFrom(r.id, 0, req)

# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

proc addRoute(r: Router; meth, pattern: string; h: RouteHandler) =
  gReg[r.id].routes.add Route(meth: upperAscii(meth), segs: splitPath(pattern), handler: h)

proc get*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `GET pattern`.
  addRoute(r, "GET", pattern, h)

proc post*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `POST pattern`.
  addRoute(r, "POST", pattern, h)

proc put*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `PUT pattern`.
  addRoute(r, "PUT", pattern, h)

proc patch*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `PATCH pattern`.
  addRoute(r, "PATCH", pattern, h)

proc delete*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `DELETE pattern`.
  addRoute(r, "DELETE", pattern, h)

proc head*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `HEAD pattern` (otherwise HEAD falls back to GET).
  addRoute(r, "HEAD", pattern, h)

proc options*(r: Router; pattern: string; h: RouteHandler) =
  ## Register a handler for `OPTIONS pattern`.
  addRoute(r, "OPTIONS", pattern, h)

proc use*(r: Router; mw: Middleware) =
  ## Append a middleware to the chain (runs in registration order; first is
  ## outermost).
  gReg[r.id].mws.add mw

proc notFound*(r: Router; h: RouteHandler) =
  ## Set a custom handler for unmatched paths (replaces the default 404).
  gReg[r.id].notFoundH = h
  gReg[r.id].hasNotFound = true

# ---------------------------------------------------------------------------
# turn into a serve handler
# ---------------------------------------------------------------------------

proc routerDispatch(req: Request): Response {.nimcall.} =
  ## The `{.nimcall.}` entry the `serve` loop calls; dispatches the active router.
  runFrom(gActive, 0, req)

proc toHandler*(r: Router): NimcallHandler =
  ## Install `r` as the active router and return the `{.nimcall.}` handler that
  ## `serve` (single-thread) and the worker pool both accept. Because the handler
  ## is stateless, the most recently installed router is the one served.
  gActive = r.id
  return routerDispatch

proc serveRouter*(port: int; r: Router; maxRequests = 0) =
  ## Run router `r` on `port` over the single-threaded plaintext loop. Loops
  ## forever unless `maxRequests > 0`, in which case it returns after that many
  ## connections.
  gActive = r.id
  initTcp()
  let l = listenTcp(port)
  if l == InvalidTcpHandle:
    shutdownTcp()
    return
  var served = 0
  while maxRequests == 0 or served < maxRequests:
    let clientFd = acceptTcp(l)
    if clientFd != InvalidTcpHandle:
      serveConnectionNimcall(clientFd, routerDispatch)
      inc served
  closeTcp(l)
  shutdownTcp()
