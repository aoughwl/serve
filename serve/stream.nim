## serve/stream.nim — responses whose body is PRODUCED, not materialised.
##
## Every response path in the stack builds the whole body in memory first. That
## rules out three things a server has to do: server-sent events (a body that is
## never finished), downloads larger than RAM (which is why the static file
## handler needs a size cap at all), and any response whose first byte should
## reach the client before the last is computed.
##
## The shape is a PULL producer rather than a push API:
##
##     proc next(st: var StreamState; chunk: var string): bool {.nimcall.}
##
## called repeatedly by the connection coroutine until it returns false. That is
## the one shape the coroutine transform allows — a handler cannot suspend, so
## it cannot write; it can only be asked for the next piece and let the caller,
## which is the coroutine, do the suspending write. nghttp2's data provider
## works exactly this way, which is a good sign it is the right seam.

when defined(nimony):
  {.feature: "lenientnils".}

import std/syncio
import http/headers
import http/response

const StreamChunkBytes* = 32 * 1024

type
  StreamState* = object
    ## Scratch the producer owns across calls. Deliberately concrete rather than
    ## a closure environment: a `{.nimcall.}` producer cannot capture, and a
    ## closure could not cross the coroutine boundary anyway.
    file*: File          ## for `fileProducer`
    hasFile*: bool
    remaining*: int64    ## bytes still to send (-1 = until EOF)
    counter*: int        ## free for the producer (event number, retry count, …)
    limit*: int          ## free for the producer (how many events to send, …)
    text*: string        ## free for the producer (a template, a prefix, …)

  ChunkProducer* = proc(st: var StreamState; chunk: var string): bool {.nimcall.}
    ## Fill `chunk` with the next piece and return true, or return false when
    ## the body is complete. Returning true with an EMPTY chunk is allowed and
    ## means "nothing right now" — the caller does not treat it as the end.

  StreamResponse* = object
    ## A response the server writes incrementally. `headers` are sent as given;
    ## the transport adds the framing (`Transfer-Encoding: chunked`).
    status*: int
    contentType*: string
    headers*: seq[Header]
    producer*: ChunkProducer
    state*: StreamState

proc emptyState*(): StreamState =
  StreamState(file: default(File), hasFile: false, remaining: -1'i64,
              counter: 0, limit: 0, text: "")

proc noBody(st: var StreamState; chunk: var string): bool {.nimcall.} =
  chunk = ""
  false

proc emptyStream*(status = 204): StreamResponse =
  ## A stream that ends immediately — the "nothing to say" case, and the value a
  ## handler global is initialised with so it is never nil.
  StreamResponse(status: status, contentType: "text/plain", headers: @[],
                 producer: noBody, state: emptyState())

# ---------------------------------------------------------------------------
# built-in producers
# ---------------------------------------------------------------------------

proc fileProducer*(st: var StreamState; chunk: var string): bool {.nimcall.} =
  ## Read the next `StreamChunkBytes` from `st.file`, honouring `st.remaining`
  ## (-1 = to EOF). Closes the file when it is done, including on a read error —
  ## a producer that leaks descriptors would be worse than one that truncates.
  chunk = ""
  if not st.hasFile:
    return false
  var want = StreamChunkBytes
  if st.remaining >= 0'i64 and st.remaining < int64(want):
    want = int(st.remaining)
  if want <= 0:
    st.file.close()
    st.hasFile = false
    return false
  var buf = newSeq[char](want)
  let got = st.file.readBuffer(addr buf[0], want)
  if got <= 0:
    st.file.close()
    st.hasFile = false
    return false
  var i = 0
  while i < got:
    chunk.add buf[i]
    inc i
  if st.remaining >= 0'i64:
    st.remaining = st.remaining - int64(got)
  return true

proc fileStream*(path: string; contentType: string; status = 200;
                 offset = 0'i64; length = -1'i64): StreamResponse =
  ## Stream a file from disk without reading it whole. `offset`/`length` carve
  ## out a byte range. A file that cannot be opened yields a 404 stream, so the
  ## caller has one thing to write back either way.
  result = emptyStream(404)
  var f = default(File)
  if not open(f, path, fmRead):
    return result
  if offset > 0'i64:
    # `.raises`: a seek past the end, or on something unseekable, must not take
    # the server down — the stream simply starts where the file did.
    try:
      f.setFilePos(offset)
    except:
      discard
  result = StreamResponse(status: status, contentType: contentType,
                          headers: @[], producer: fileProducer,
                          state: StreamState(file: f, hasFile: true,
                                             remaining: length, counter: 0,
                                             limit: 0, text: ""))

proc sseEvent*(data: string; event = ""; id = ""): string =
  ## One server-sent event, framed per the EventSource wire format: optional
  ## `event:`/`id:` lines, then `data:` per line, then a blank line. Multi-line
  ## payloads are split, because a raw newline inside `data:` would end the
  ## event early — the mistake every hand-rolled SSE writer makes once.
  result = ""
  if event.len > 0:
    result.add "event: " & event & "\n"
  if id.len > 0:
    result.add "id: " & id & "\n"
  var line = ""
  var i = 0
  while i < data.len:
    if data[i] == '\n':
      result.add "data: " & line & "\n"
      line = ""
    elif data[i] != '\r':
      line.add data[i]
    inc i
  result.add "data: " & line & "\n\n"

proc sseStream*(producer: ChunkProducer; state: StreamState): StreamResponse =
  ## An `text/event-stream` response with the headers a browser's EventSource
  ## needs: no caching, and no proxy buffering (`X-Accel-Buffering`), without
  ## which an intermediary can hold events until the connection ends and undo
  ## the whole point.
  result = StreamResponse(status: 200, contentType: "text/event-stream",
                          headers: @[], producer: producer, state: state)
  result.headers.add Header(name: "Cache-Control", value: "no-cache")
  result.headers.add Header(name: "X-Accel-Buffering", value: "no")

# ---------------------------------------------------------------------------
# framing
# ---------------------------------------------------------------------------

proc chunkHeader*(n: int): string =
  ## `<hex length>CRLF` — the size line of one HTTP/1.1 chunk.
  const hexDigits = "0123456789abcdef"
  var v = n
  var digits = default(array[16, char])
  var c = 0
  if v == 0:
    digits[0] = '0'
    c = 1
  while v > 0:
    digits[c] = hexDigits[v and 15]
    v = v shr 4
    inc c
  result = ""
  var i = c - 1
  while i >= 0:
    result.add digits[i]
    dec i
  result.add "\r\n"

proc streamHeaderBlock*(r: StreamResponse; version: string): string =
  ## The status line and headers for a streamed response. `Transfer-Encoding:
  ## chunked` is added for HTTP/1.1; for anything older there is no chunked
  ## framing, so the body is delimited by the close and `Connection: close` says
  ## so — silently sending chunks to an HTTP/1.0 client would corrupt the body.
  result = "HTTP/1.1 "
  result.add $r.status
  let phrase = reasonPhrase(r.status)
  if phrase.len > 0:
    result.add " " & phrase
  result.add "\r\n"
  if r.contentType.len > 0:
    result.add "Content-Type: " & r.contentType & "\r\n"
  for h in r.headers:
    result.add h.name & ": " & h.value & "\r\n"
  if version == "HTTP/1.1":
    result.add "Transfer-Encoding: chunked\r\n"
    result.add "Connection: keep-alive\r\n"
  else:
    result.add "Connection: close\r\n"
  result.add "\r\n"
