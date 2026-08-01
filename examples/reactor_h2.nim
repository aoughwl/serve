## An async h2c (prior-knowledge HTTP/2) server on the reactor — the concurrent
## counterpart to `h2_server.nim`, and what the h2spec gate drives.
##
##   bin/reactor_h2 8090 &
##   h2spec -h 127.0.0.1 -p 8090
##
## Unlike the blocking `serveHttp2`, one connection sitting idle does not stop
## the next from being accepted: all of them are multiplexed on this one thread.

import std/[cmdline, strutils]
import serve
import serve/reactorh2
import serve/http2

proc handler(req: Request): Response {.nimcall.} =
  response(200, "text/plain", "ok " & req.path & "\n")

var port = 8090
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8090

# Optional second argument: the idle timeout in ms, so a test can watch a silent
# connection actually get dropped without waiting the default minute.
var idleMs = 60_000
if paramCount() >= 2:
  try: idleMs = parseInt(paramStr(2))
  except: idleMs = 60_000

# The SETTINGS a deployment actually wants to state, rather than nghttp2's
# defaults plus one hardcoded entry. A 5th argument overrides the announced
# per-stream window, which is the knob that decides how much memory one peer
# can make this server hold.
var st = defaultH2Settings()
if paramCount() >= 3:
  try: st.initialWindowSize = uint32(parseInt(paramStr(3)))
  except: discard
st.maxHeaderListSize = 32 * 1024'u32     # unbounded by default; bound it
setH2Settings(st)

serveHttp2Reactor(port, handler, idleMs)
