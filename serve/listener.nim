## serve/listener.nim — every server's listening socket, under one policy.
##
## Each server in this package called `listenTcp(port)` directly, which meant
## the listener's socket options were whatever `tcp` hardcoded: SO_REUSEADDR
## forced on with no opt-out, backlog 128, no buffer sizing, no SO_BINDTODEVICE,
## no way to decline any of it. `TcpOpts` made that expressible; this is where
## a server picks it up.
##
## The policy is a process global for the same reason the rest of this
## package's knobs are: the connection bodies are `{.nimcall.}` procs reading
## module globals, so there is no per-server instance to hang it on yet.
##
## Scope, stated rather than implied: `loop`, `pool` and `reactorhttp` route
## through here. `http2`, `reactorh2`, `reactorws`, `reactorall` and `router`
## still call `listenTcp` directly and are on the Phase 2 sweep.

import tcp

var gListenerOpts = defaultListenerOpts()
var gLastReport = TcpOptsReport(applied: 0, failed: 0, firstFailure: "")

proc setServeListenerOpts*(opts: TcpOpts) =
  ## Socket policy for subsequently created listeners.
  gListenerOpts = opts

proc serveListenerOpts*(): TcpOpts =
  ## The policy in force. Readable, so "the current policy with a bigger
  ## backlog" is a merge rather than a guess.
  gListenerOpts

proc lastListenReport*(): TcpOptsReport =
  ## What the platform accepted for the most recent listener. An option the
  ## kernel refused is worth knowing about before the server takes traffic.
  gLastReport

proc serveListen*(port: int): TcpHandle =
  ## Listen on the wildcard address under the configured policy.
  result = listenTcpOpts(0'u32, port, gListenerOpts, gLastReport)
