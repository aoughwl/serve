## Streamed responses on the reactor: server-sent events and a file download
## that is never held in memory.
##
##   bin/reactor_stream 8190 [file-to-serve] &
##   curl -N http://127.0.0.1:8190/events     # events arrive one at a time
##   curl -s http://127.0.0.1:8190/file | wc -c
##   curl -s http://127.0.0.1:8190/hello      # ordinary responses still work
##
## The producers are `{.nimcall.}` procs that cannot capture and cannot suspend;
## they are asked for the next piece and the connection coroutine writes it.

import std/[cmdline, strutils]
import serve/reactorhttp
import serve/stream
import serve/static
import http/request
import http/response

const Events = 5

var gFilePath = ""

proc lastPathPart(p: string): string =
  result = p
  var i = p.len - 1
  while i >= 0:
    if p[i] == '/':
      result = ""
      var j = i + 1
      while j < p.len:
        result.add p[j]
        inc j
      return result
    dec i

proc parentDirOf(p: string): string =
  result = "."
  var i = p.len - 1
  while i >= 0:
    if p[i] == '/':
      result = ""
      var j = 0
      while j < i:
        result.add p[j]
        inc j
      if result.len == 0: result = "/"
      return result
    dec i

proc handler(req: Request): Response {.nimcall.} =
  if req.path == "/hello":
    return response(200, "text/plain", "hello, not streamed\n")
  response(404, "text/plain", "not found\n")

proc wantsStream(req: Request): bool {.nimcall.} =
  req.path == "/events" or req.path == "/file" or req.path == "/static"

proc tickProducer(st: var StreamState; chunk: var string): bool {.nimcall.} =
  ## One event per call, `st.limit` of them, then done. A real feed would return
  ## an empty chunk when it has nothing yet rather than ending.
  if st.counter >= st.limit:
    chunk = ""
    return false
  inc st.counter
  chunk = sseEvent("tick " & $st.counter, "tick", $st.counter)
  true

proc streamHandler(req: Request): StreamResponse {.nimcall.} =
  if req.path == "/file" and gFilePath.len > 0:
    return fileStream(gFilePath, "application/octet-stream")
  if req.path == "/static" and gFilePath.len > 0:
    # The same file through the static layer: byte ranges, ETag/304 and
    # Content-Type come from the request, and the body still never lands in
    # memory. `/file` above is the raw form, for comparison.
    var r2 = req
    r2.path = "/" & lastPathPart(gFilePath)
    return staticStreamFor(parentDirOf(gFilePath), r2)
  var st = emptyState()
  st.limit = Events
  sseStream(tickProducer, st)

var port = 8190
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8190
if paramCount() >= 2:
  gFilePath = paramStr(2)

setReactorStreamHandler(streamHandler, wantsStream)
serveHttpReactor(port, handler)
