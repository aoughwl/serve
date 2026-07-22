## An async WebSocket echo server on the reactor: one thread, epoll-multiplexed.
## Build: nimony c (net-stack + ws --path set)   Run: bin/reactor_ws [port]

import std/[cmdline, strutils]
import serve/reactorws

proc echoWs(msg: string; isBinary: bool): string {.nimcall.} =
  msg   # echo every message back

var port = 8150
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8150

serveWsReactor(port, echoWs)
