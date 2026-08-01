## serve/serverconfig.nim — one value describing a server.
##
## Everything a server here can be told is currently told to it by a different
## mechanism: `setServeLimits` and `setReactorLimits` (two separate globals for
## the same two ideas, because the blocking and reactor models keep different
## defaults), `setServeReadTimeout`, `setStaticFileLimit`, the idle timeout as a
## parameter on one entry point, and — for the transport underneath — nothing at
## all, because `serveTls` constructed its own `TlsContext` and the listeners
## took no socket options.
##
## `ServerConfig` collects them. It nests the records the layers below already
## define rather than restating their fields, which is the whole reason those
## records went in first: a server's TLS policy *is* a `TlsConfig`, its listener
## policy *is* a `TcpOpts`, and its parser bounds *are* `ParserLimits`. Nothing
## here re-spells them, so there is one place per concept and one merge rule.
##
## Not included, deliberately: `WsConfig` and `H2Settings`. `ws` is not a
## dependency of this package (only `serve/reactorws` uses it, by path), and
## HTTP/2 is an opt-in import. Folding either in would make an optional
## dependency mandatory for everyone who wants to set a read timeout. They are
## their own records and are applied directly.
##
## On the globals: the values below are still applied to process-wide `var`s
## rather than being carried per-server, because the handler and connection
## bodies are `{.nimcall.}` reading module globals — a design forced by the
## compiler's closure-return codegen bug, not chosen. When that is fixed this
## record is what a per-server instance would hold; until then it is at least
## one vocabulary and one application point instead of six.

import tcp
import tls
import http/stream

const
  ServeUnset* = -1
    ## Inherit this field. 0 is a real value for several of these — an unbounded
    ## request size, a disabled timeout — so it cannot double as "unset".

  DefaultMaxRequestBytes* = 8 * 1024 * 1024
    ## Whole-request cap; over it the server answers 413.
  DefaultServeKeepAlive* = 100
    ## Requests per kept-alive connection, blocking servers.
  DefaultReactorKeepAlive* = 1000
    ## Requests per kept-alive connection, reactor servers. Higher on purpose:
    ## a kept-alive connection costs a thread in one model and a coroutine in
    ## the other, so the same number would be the wrong trade in both.
  DefaultReadTimeoutMs* = 15000
    ## Per-socket blocking read timeout — the slowloris guard.
  DefaultIdleTimeoutMs* = 60000
    ## Reactor keep-alive idle limit.
  DefaultMaxStaticBytes* = 64 * 1024 * 1024
    ## Cap for the in-memory static path.

type
  ServerConfig* = object
    ## What a server accepts, how long it waits, and what its transport looks
    ## like. Sub-records are the ones their own libraries define.
    listener*: TcpOpts          ## socket policy for the listening socket
    tls*: TlsConfig             ## TLS policy; `hasCertificate` decides if it is usable
    parser*: ParserLimits       ## HTTP parser bounds
    maxRequestBytes*: int       ## whole request; 0 = unbounded
    maxKeepAlive*: int          ## requests per connection, blocking servers
    reactorMaxKeepAlive*: int   ## requests per connection, reactor servers
      ## Two fields rather than one, because the two models genuinely disagree
      ## and a single field cannot hold both. Collapsing them meant applying a
      ## config built for one model silently imposed its keep-alive count on
      ## the other — which is how the blocking server's 100 replaced the
      ## reactor's 1000 the first time this was written.
    readTimeoutMs*: int         ## blocking read timeout; 0 = off
    idleTimeoutMs*: int         ## reactor idle timeout; 0 = off
    maxStaticBytes*: int        ## in-memory static file cap; 0 = uncapped

proc defaultServerConfig*(): ServerConfig =
  ## The blocking servers' shipped behaviour, written out. Applying this
  ## changes nothing about how they run today.
  ServerConfig(
    listener: defaultListenerOpts(),
    tls: defaultTlsConfig(),
    parser: defaultParserLimits(),
    maxRequestBytes: DefaultMaxRequestBytes,
    maxKeepAlive: DefaultServeKeepAlive,
    reactorMaxKeepAlive: DefaultReactorKeepAlive,
    readTimeoutMs: DefaultReadTimeoutMs,
    idleTimeoutMs: DefaultIdleTimeoutMs,
    maxStaticBytes: DefaultMaxStaticBytes)

proc noServerConfig*(): ServerConfig =
  ## The empty override: every scalar inherits, and every sub-record is its own
  ## empty override too.
  ServerConfig(
    listener: defaultTcpOpts(),
    tls: defaultTlsConfig(),
    parser: noParserLimits(),
    maxRequestBytes: ServeUnset,
    maxKeepAlive: ServeUnset,
    reactorMaxKeepAlive: ServeUnset,
    readTimeoutMs: ServeUnset,
    idleTimeoutMs: ServeUnset,
    maxStaticBytes: ServeUnset)

proc withTls*(cfg: ServerConfig; certChainFile: string;
              keyFile: string): ServerConfig =
  ## Attach a certificate pair. This is what `serveTls(port, cert, key, ...)`
  ## used to be able to say and nothing more — every other TLS setting was
  ## unreachable because the entry point owned the context. Now the pair is one
  ## field of a policy that can carry the rest.
  result = cfg
  result.tls.certChainFile = certChainFile
  result.tls.keyFile = keyFile

proc merge*(base: ServerConfig; over: ServerConfig): ServerConfig =
  ## The scope ladder, recursing into each sub-record's own merge rule.
  result = base
  result.listener = merge(base.listener, over.listener)
  result.tls = merge(base.tls, over.tls)
  result.parser = merge(base.parser, over.parser)
  if over.maxRequestBytes != ServeUnset: result.maxRequestBytes = over.maxRequestBytes
  if over.maxKeepAlive != ServeUnset: result.maxKeepAlive = over.maxKeepAlive
  if over.reactorMaxKeepAlive != ServeUnset:
    result.reactorMaxKeepAlive = over.reactorMaxKeepAlive
  if over.readTimeoutMs != ServeUnset: result.readTimeoutMs = over.readTimeoutMs
  if over.idleTimeoutMs != ServeUnset: result.idleTimeoutMs = over.idleTimeoutMs
  if over.maxStaticBytes != ServeUnset: result.maxStaticBytes = over.maxStaticBytes

proc usesTls*(cfg: ServerConfig): bool =
  ## Whether this config describes a server that can terminate TLS.
  hasCertificate(cfg.tls)

proc resolve*(value: int; fallback: int): int =
  ## Resolve one possibly-unset scalar. Kept here so every consumer interprets
  ## `ServeUnset` the same way.
  if value == ServeUnset: fallback else: value
