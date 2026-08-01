## serve/static.aowl — map a URL path onto a file under a served root dir and
## build the HTTP response for it. Standard-library only.
##
## Rules:
##   * `/`               -> `/index.html`
##   * any `?query`      -> stripped before the file lookup
##   * percent escapes   -> decoded before lookup
##   * a path with `..`  -> 403 (no directory traversal)
##   * missing file      -> 404
##   * Content-Type by extension for common web assets

import std/os        # fileExists, dirExists, getFileSize, getLastModificationTime
import std/syncio    # readFile
import http/url
import http/headers
import http/request
import http/response

const MaxStaticFileBytes* = 64 * 1024 * 1024
  ## Default cap on a file this module will serve. The body is read whole into
  ## memory (there is no streaming file path yet), so an uncapped root meant any
  ## file dropped in it could exhaust the process.

var gMaxStaticBytes = MaxStaticFileBytes
var gStaticTooLarge = 0

proc setStaticFileLimit*(maxBytes: int) =
  ## Cap for subsequently served files. `maxBytes <= 0` removes the cap, which
  ## is only safe if you control what is in the root.
  gMaxStaticBytes = maxBytes

proc staticFilesRefused*(): int =
  ## Files refused for exceeding the cap. Counted, not shrugged off.
  gStaticTooLarge

proc endsWithSuffix*(s, suffix: string): bool =
  ## Non-allocating "does s end with suffix?".
  if suffix.len > s.len: return false
  var i = 0
  let off = s.len - suffix.len
  while i < suffix.len:
    if s[off + i] != suffix[i]: return false
    inc i
  return true

proc contentTypeFor*(path: string): string =
  ## Pick a Content-Type from the file extension (char-walk suffix match).
  if endsWithSuffix(path, ".html") or endsWithSuffix(path, ".htm"): "text/html; charset=utf-8"
  elif endsWithSuffix(path, ".js") or endsWithSuffix(path, ".mjs"): "text/javascript; charset=utf-8"
  elif endsWithSuffix(path, ".css"): "text/css; charset=utf-8"
  elif endsWithSuffix(path, ".json"): "application/json; charset=utf-8"
  elif endsWithSuffix(path, ".txt") or endsWithSuffix(path, ".text"): "text/plain; charset=utf-8"
  elif endsWithSuffix(path, ".svg"): "image/svg+xml"
  elif endsWithSuffix(path, ".png"): "image/png"
  elif endsWithSuffix(path, ".jpg") or endsWithSuffix(path, ".jpeg"): "image/jpeg"
  elif endsWithSuffix(path, ".gif"): "image/gif"
  elif endsWithSuffix(path, ".webp"): "image/webp"
  elif endsWithSuffix(path, ".ico"): "image/x-icon"
  elif endsWithSuffix(path, ".wasm"): "application/wasm"
  elif endsWithSuffix(path, ".pdf"): "application/pdf"
  elif endsWithSuffix(path, ".woff"): "font/woff"
  elif endsWithSuffix(path, ".woff2"): "font/woff2"
  else: "application/octet-stream"

proc hasDotDot(s: string): bool =
  ## True if the path contains a ".." segment (traversal attempt).
  var i = 0
  while i < s.len:
    let atStart = i == 0 or s[i - 1] == '/'
    if atStart and i + 1 < s.len and s[i] == '.' and s[i + 1] == '.':
      let atEnd = i + 2 == s.len or s[i + 2] == '/'
      if atEnd: return true
    inc i
  return false

proc normalizeUrlPath*(urlPath: string): string =
  ## Strip query/fragment, percent-decode, force a leading slash, and map `/`
  ## to `/index.html`. Does not join with the filesystem root.
  var p = percentDecode(pathOnly(urlPath))
  if p.len == 0 or p[0] != '/':
    p = "/" & p
  if p.len == 0 or p == "/":
    p = "/index.html"
  result = p

proc relativePath*(urlPath: string): string =
  ## Convert a normalized URL path into a relative filesystem path.
  let p = normalizeUrlPath(urlPath)
  result = ""
  var j = 0
  if p.len > 0 and p[0] == '/':
    j = 1
  while j < p.len:
    result.add p[j]
    inc j

# ---------------------------------------------------------------------------
# validators: ETag, Last-Modified, and conditional / range requests
# ---------------------------------------------------------------------------

proc appendUInt(s: var string; v: int64) =
  if v < 0:
    s.add '-'
  var n = if v < 0: -v else: v
  var digits = default(array[24, char])
  var c = 0
  if n == 0:
    digits[0] = '0'
    c = 1
  while n > 0:
    digits[c] = char(ord('0') + int(n mod 10))
    n = n div 10
    inc c
  var i = c - 1
  while i >= 0:
    s.add digits[i]
    dec i

proc pad2(s: var string; v: int) =
  if v < 10: s.add '0'
  appendUInt(s, int64(v))

proc httpDate*(epoch: int64): string =
  ## An IMF-fixdate — `Sun, 06 Nov 1994 08:49:37 GMT` — from a Unix timestamp.
  ## Pure integer civil-from-days arithmetic (Howard Hinnant's algorithm), so no
  ## locale, no timezone database, and no dependency on a C `gmtime` that would
  ## have to be made thread-safe.
  const dayNames = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
  const monNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
  var days = epoch div 86400'i64
  var rem = epoch - days * 86400'i64
  if rem < 0:
    rem = rem + 86400'i64
    days = days - 1
  let hour = int(rem div 3600'i64)
  let minute = int((rem mod 3600'i64) div 60'i64)
  let second = int(rem mod 60'i64)
  # 1970-01-01 was a Thursday, which is why the table starts there.
  var dow = int(days mod 7'i64)
  if dow < 0: dow = dow + 7

  var z = days + 719468'i64
  let era = (if z >= 0: z else: z - 146096'i64) div 146097'i64
  let doe = z - era * 146097'i64
  let yoe = (doe - doe div 1460'i64 + doe div 36524'i64 - doe div 146096'i64) div 365'i64
  var y = yoe + era * 400'i64
  let doy = doe - (365'i64 * yoe + yoe div 4'i64 - yoe div 100'i64)
  let mp = (5'i64 * doy + 2'i64) div 153'i64
  let d = int(doy - (153'i64 * mp + 2'i64) div 5'i64 + 1'i64)
  let m = int(if mp < 10'i64: mp + 3'i64 else: mp - 9'i64)
  if m <= 2: y = y + 1

  result = dayNames[dow]
  result.add ", "
  pad2(result, d)
  result.add ' '
  result.add monNames[m - 1]
  result.add ' '
  appendUInt(result, y)
  result.add ' '
  pad2(result, hour)
  result.add ':'
  pad2(result, minute)
  result.add ':'
  pad2(result, second)
  result.add " GMT"

proc etagFor*(size: int64; mtime: int64): string =
  ## `"<size>-<mtime>"`. Size and mtime together change on any edit that matters
  ## for serving, and both come from one `stat` — no hashing the file.
  result = "\""
  appendUInt(result, size)
  result.add '-'
  appendUInt(result, mtime)
  result.add '\"'

proc etagMatches(header, etag: string): bool =
  ## `If-None-Match`: `*`, or a comma-separated list containing our tag. A `W/`
  ## prefix is accepted since we never issue weak tags but clients may echo one.
  if header.len == 0: return false
  if header == "*": return true
  var i = 0
  while i < header.len:
    while i < header.len and (header[i] == ' ' or header[i] == ',' or header[i] == '\t'):
      inc i
    var start = i
    while i < header.len and header[i] != ',':
      inc i
    var stop = i
    while stop > start and (header[stop-1] == ' ' or header[stop-1] == '\t'):
      dec stop
    var cand = ""
    var k = start
    while k < stop:
      cand.add header[k]
      inc k
    if cand.len > 2 and cand[0] == 'W' and cand[1] == '/':
      var trimmed = ""
      var j = 2
      while j < cand.len:
        trimmed.add cand[j]
        inc j
      cand = trimmed
    if cand == etag: return true
  false

proc parseByteRange*(header: string; total: int64;
                     rangeStart, rangeEnd: var int64): int =
  ## Parse a single `Range: bytes=…`. Returns 1 (satisfiable, bounds set),
  ## 0 (no/unsupported range — serve the whole thing), or -1 (unsatisfiable →
  ## 416). Multi-range is deliberately 0: answering the full entity is allowed
  ## and is better than pretending to support multipart/byteranges.
  rangeStart = 0
  rangeEnd = total - 1
  if header.len < 7: return 0
  var i = 0
  const prefix = "bytes="
  while i < prefix.len:
    if i >= header.len or header[i] != prefix[i]: return 0
    inc i
  var j = i
  while j < header.len:
    if header[j] == ',': return 0        # multi-range
    inc j
  var dash = -1
  j = i
  while j < header.len:
    if header[j] == '-':
      dash = j
      break
    inc j
  if dash < 0: return 0
  var haveFirst = false
  var first = 0'i64
  var k = i
  while k < dash:
    if header[k] < '0' or header[k] > '9': return 0
    first = first * 10'i64 + int64(ord(header[k]) - ord('0'))
    haveFirst = true
    inc k
  var haveLast = false
  var last = 0'i64
  k = dash + 1
  while k < header.len:
    if header[k] == ' ': 
      inc k
      continue
    if header[k] < '0' or header[k] > '9': return 0
    last = last * 10'i64 + int64(ord(header[k]) - ord('0'))
    haveLast = true
    inc k
  if not haveFirst and not haveLast: return 0
  if not haveFirst:
    # `bytes=-N`: the LAST n bytes.
    if last <= 0'i64: return -1
    if last > total: last = total
    rangeStart = total - last
    rangeEnd = total - 1
    return 1
  if first >= total: return -1
  rangeStart = first
  rangeEnd = if haveLast: last else: total - 1
  if rangeEnd >= total: rangeEnd = total - 1
  if rangeEnd < rangeStart: return -1
  return 1

proc staticResponseObj*(root: string; urlPath: string): Response =
  ## Route a URL path to a file under `root` and return the in-memory `Response`
  ## model (status, headers, and full body). The transport layer decides how to
  ## serialize it (e.g. omitting the body for `HEAD`). This is the object-model
  ## core that both `staticResponse` and the handler-based loop build on.
  let p = normalizeUrlPath(urlPath)
  if hasDotDot(p):
    return response(403, "text/plain", "Forbidden\n")

  var full = root & "/" & relativePath(p)
  if dirExists(full):
    full = full & "/index.html"

  if not fileExists(full):
    return response(404, "text/plain", "Not Found\n")

  var body = ""
  var ok = true
  try:
    body = readFile(full)
  except:
    ok = false
  if not ok:
    return response(500, "text/plain", "Internal Server Error\n")

  result = response(200, contentTypeFor(full), body)
  result.withHeader("X-Content-Type-Options", "nosniff")

proc resolveStaticPath(root, urlPath: string; full: var string): int =
  ## Shared routing: 0 = serve `full`, otherwise the status to answer with.
  let p = normalizeUrlPath(urlPath)
  if hasDotDot(p):
    return 403
  full = root & "/" & relativePath(p)
  if dirExists(full):
    full = full & "/index.html"
  if not fileExists(full):
    return 404
  return 0

proc subRange(s: string; a, b: int64): string =
  result = ""
  var i = a
  while i <= b and i < int64(s.len):
    result.add s[int(i)]
    inc i

proc staticResponseFor*(root: string; req: Request): Response =
  ## Static serving that uses the REQUEST: conditional requests (`If-None-Match`
  ## / `If-Modified-Since` → 304), byte ranges (`Range` → 206, unsatisfiable →
  ## 416), and the file-size cap. `staticResponseObj` remains the
  ## path-only form and always sends the whole entity.
  ##
  ## `If-Modified-Since` is honoured by exact match against the `Last-Modified`
  ## we issue. A client that sends a different-but-later date gets a 200 rather
  ## than a 304 — conservative in the only direction that cannot serve a stale
  ## body, and it avoids parsing arbitrary date formats to decide freshness.
  var full = ""
  let routed = resolveStaticPath(root, req.path, full)
  if routed == 403:
    return response(403, "text/plain", "Forbidden\n")
  if routed == 404:
    return response(404, "text/plain", "Not Found\n")

  # `getFileSize` / `getLastModificationTime` are `.raises`; a file that
  # vanished between the existence check and here is a 404, not a crash.
  var size = 0'i64
  var mtime = 0'i64
  var statOk = true
  try:
    size = getFileSize(full)
    mtime = getLastModificationTime(full)
  except:
    statOk = false
  if not statOk:
    return response(404, "text/plain", "Not Found\n")
  let etag = etagFor(size, mtime)
  let lastMod = httpDate(mtime)

  # --- conditional: nothing to send -----------------------------------------
  if etagMatches(headerValue(req.headers, "If-None-Match"), etag) or
     (headerValue(req.headers, "If-Modified-Since") == lastMod and lastMod.len > 0):
    result = response(304, contentTypeFor(full), "")
    result.withHeader("ETag", etag)
    result.withHeader("Last-Modified", lastMod)
    result.withHeader("Cache-Control", "no-cache")
    return result

  if gMaxStaticBytes > 0 and size > int64(gMaxStaticBytes):
    inc gStaticTooLarge
    result = response(500, "text/plain", "file too large to serve\n")
    return result

  var body = ""
  var ok = true
  try:
    body = readFile(full)
  except:
    ok = false
  if not ok:
    return response(500, "text/plain", "Internal Server Error\n")

  # --- ranges ---------------------------------------------------------------
  let rangeHeader = headerValue(req.headers, "Range")
  var a = 0'i64
  var b = int64(body.len) - 1'i64
  let verdict = parseByteRange(rangeHeader, int64(body.len), a, b)
  if verdict < 0:
    result = response(416, "text/plain", "Range Not Satisfiable\n")
    var cr = "bytes */"
    appendUInt(cr, int64(body.len))
    result.withHeader("Content-Range", cr)
    result.withHeader("ETag", etag)
    return result

  if verdict > 0:
    result = response(206, contentTypeFor(full), subRange(body, a, b))
    var cr = "bytes "
    appendUInt(cr, a)
    cr.add '-'
    appendUInt(cr, b)
    cr.add '/'
    appendUInt(cr, int64(body.len))
    result.withHeader("Content-Range", cr)
  else:
    result = response(200, contentTypeFor(full), body)

  result.withHeader("ETag", etag)
  result.withHeader("Last-Modified", lastMod)
  result.withHeader("Accept-Ranges", "bytes")
  result.withHeader("X-Content-Type-Options", "nosniff")

proc staticResponse*(root: string; urlPath: string; includeBody = true): string =
  ## Route a URL path to a file under `root` and return a full HTTP response
  ## string. Thin wrapper over `staticResponseObj`.
  responseToString(staticResponseObj(root, urlPath), includeBody)

proc serveFile*(root: string; urlPath: string): string =
  ## Backwards-compatible static GET helper.
  staticResponse(root, urlPath, true)
