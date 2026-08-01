## serve/applyconfig.nim — the one place a ServerConfig takes effect.
##
## Kept separate from `serverconfig` so the record itself stays pure data that
## anything can depend on, while the code that reaches into `loop`,
## `reactorhttp` and `static` lives in a module you only import when you mean
## to apply it.
##
## Each setting still lands in the process-global it always did. That is not
## the end state — a per-server instance is — but it is the honest one while
## the connection bodies are `{.nimcall.}` procs reading module globals. What
## changes here is that there is one call instead of six, one vocabulary
## instead of four, and nothing silently keeps a default the caller thought it
## had replaced.

import std/syncio
import tcp
import tls
import http/request
import http/response
import ./serverconfig
import ./listener
import ./loop
import ./reactorhttp
import ./static

export serverconfig

proc applyServerConfig*(cfg: ServerConfig) =
  ## Apply every set scalar of `cfg` to the blocking and reactor servers and to
  ## the static file path. Unset fields are left alone, so applying
  ## `noServerConfig()` is a no-op.
  ##
  ## The listener policy is handed to `listener`, which the servers consult
  ## when they create their listening socket. The TLS and parser sub-records
  ## are *not* applied here: they take effect where the thing they configure is
  ## created — an `SSL_CTX` at context construction, a parser at connection
  ## start — and applying them to a global would be applying them to nothing.
  ## `serveTls(port, handler, cfg)` below is what consumes the TLS half.
  if not isEmpty(cfg.listener) or cfg.listener.backlog != TcpUnset:
    setServeListenerOpts(cfg.listener)
  # Both setters take both values, so read the current pair and replace only
  # the half that was actually set. Passing a default for the other half is how
  # "I raised the request cap" silently resets the keep-alive count.
  if cfg.maxRequestBytes != ServeUnset or cfg.maxKeepAlive != ServeUnset:
    let serveNow = serveLimits()
    setServeLimits(
      resolve(cfg.maxRequestBytes, serveNow.maxRequestBytes),
      resolve(cfg.maxKeepAlive, serveNow.maxKeepAlive))

  # The reactor reads its OWN keep-alive field. Feeding it `maxKeepAlive` would
  # impose the blocking server's count on a model that costs a coroutine per
  # connection rather than a thread.
  if cfg.maxRequestBytes != ServeUnset or cfg.reactorMaxKeepAlive != ServeUnset:
    let reactorNow = reactorLimits()
    setReactorLimits(
      resolve(cfg.maxRequestBytes, reactorNow.maxRequestBytes),
      resolve(cfg.reactorMaxKeepAlive, reactorNow.maxKeepAlive))

  if cfg.readTimeoutMs != ServeUnset:
    setServeReadTimeout(cfg.readTimeoutMs)

  if cfg.idleTimeoutMs != ServeUnset:
    setReactorIdleTimeout(cfg.idleTimeoutMs)

  if cfg.maxStaticBytes != ServeUnset:
    setStaticFileLimit(cfg.maxStaticBytes)

proc currentServerConfig*(): ServerConfig =
  ## What is in force right now, as a record. Readable, so "the current policy
  ## with one change" is a merge rather than a guess at what the other five
  ## settings were.
  result = defaultServerConfig()
  let serveNow = serveLimits()
  result.maxRequestBytes = serveNow.maxRequestBytes
  result.maxKeepAlive = serveNow.maxKeepAlive
  result.reactorMaxKeepAlive = reactorLimits().maxKeepAlive
  result.readTimeoutMs = serveReadTimeout()
  result.idleTimeoutMs = reactorIdleTimeout()
  result.listener = serveListenerOpts()

proc serve*(port: int; handler: Handler; cfg: ServerConfig; maxRequests = 0) =
  ## A plaintext server under an explicit policy: bounds, timeouts and the
  ## listening socket's options all come from one value instead of four setter
  ## calls the caller had to remember to make first.
  applyServerConfig(cfg)
  serve(port, handler, maxRequests)

proc serveTls*(port: int; handler: Handler; cfg: ServerConfig;
               maxRequests = 0) =
  ## An HTTPS server whose TLS is described rather than assumed. The old
  ## `serveTls(port, cert, key, handler)` built its own context and kept it, so
  ## protocol versions, cipher suites, groups, ALPN and extra SNI certificates
  ## were all unreachable from a server; the `TlsContext` overload opened that
  ## by handing ownership back to the caller, and this closes it by letting the
  ## caller describe the context instead of having to build one.
  applyServerConfig(cfg)
  if not usesTls(cfg):
    echo "serveTls: the config carries no certificate pair"
    return
  var report = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  let ctx = newTlsServerContext(cfg.tls, report)
  if not ctx.isValid:
    echo "serveTls: TLS context rejected the config: ", report.firstFailure
    return
  if not ok(report):
    # The context is usable but something in the policy did not take. Say so
    # rather than serving with a quietly different configuration than asked for.
    echo "serveTls: warning, setting not applied: ", report.firstFailure
  serveTls(port, ctx, handler, maxRequests)
