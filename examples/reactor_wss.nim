## An async **wss://** echo server on the reactor: one thread, epoll
## multiplexed, TLS handshakes pumped as ordinary async I/O.
## Run: bin/reactor_wss [port] [cert.pem] [key.pem]

import std/[cmdline, strutils]
import serve/reactorws

proc echoWs(msg: string; isBinary: bool): string {.nimcall.} =
  msg   # echo every message back

var port = 8451
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8451
let certFile = if paramCount() >= 2: paramStr(2) else: "cert.pem"
let keyFile = if paramCount() >= 3: paramStr(3) else: "key.pem"

serveWssReactor(port, certFile, keyFile, echoWs)
