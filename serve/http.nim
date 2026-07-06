## serve/http.aowl — minimal, non-raising HTTP/1.1 request parsing + response
## building. Standard-library only (no aoughwl substrate) so `serve` stays a
## clean, reusable HTTP lib.
##
## We char-walk rather than slice: string slices (`s[a..b]`) are `.raises` in
## nimony, and `splitLines`/`split` allocate; a hand walk keeps this proc pure
## and allocation-frugal.

type
  Request* = object
    ## The parsed HTTP request line. Bodies/headers are ignored — a static
    ## file host only needs the method and the target path.
    meth*: string   ## e.g. "GET"
    path*: string   ## e.g. "/styles.css" (raw, may carry a ?query)

proc parseRequest*(raw: string): Request =
  ## Extract the method + request-target from the first line of a request:
  ## `GET /path HTTP/1.1\r\n...`. Tolerant of a short/truncated read.
  result = Request(meth: "", path: "")
  var i = 0
  # method: up to first space / EOL
  while i < raw.len and raw[i] != ' ' and raw[i] != '\r' and raw[i] != '\n':
    result.meth.add raw[i]
    inc i
  # skip the space(s)
  while i < raw.len and raw[i] == ' ':
    inc i
  # request-target: up to next space / EOL
  while i < raw.len and raw[i] != ' ' and raw[i] != '\r' and raw[i] != '\n':
    result.path.add raw[i]
    inc i

proc reasonPhrase*(status: int): string =
  ## Reason phrase for the small set of statuses this server emits.
  case status
  of 200: "OK"
  of 400: "Bad Request"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 500: "Internal Server Error"
  else: "OK"

proc httpResponse*(status: int; contentType: string; body: string): string =
  ## Build a complete HTTP/1.1 response with `Connection: close` (no keep-alive
  ## bookkeeping) and a correct `Content-Length`.
  result = "HTTP/1.1 " & $status & " " & reasonPhrase(status) & "\r\n" &
           "Content-Type: " & contentType & "\r\n" &
           "Content-Length: " & $body.len & "\r\n" &
           "Connection: close\r\n\r\n" & body
