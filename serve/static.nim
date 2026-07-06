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

import std/os        # fileExists, dirExists
import std/syncio    # readFile
import http/url
import http/response

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

proc staticResponse*(root: string; urlPath: string; includeBody = true): string =
  ## Route a URL path to a file under `root` and return a full HTTP response.
  let p = normalizeUrlPath(urlPath)
  if hasDotDot(p):
    return httpResponse(403, "text/plain", "Forbidden\n")

  var full = root & "/" & relativePath(p)
  if dirExists(full):
    full = full & "/index.html"

  if not fileExists(full):
    return httpResponse(404, "text/plain", "Not Found\n")

  var body = ""
  var ok = true
  try:
    body = readFile(full)
  except:
    ok = false
  if not ok:
    return httpResponse(500, "text/plain", "Internal Server Error\n")

  var res = response(200, contentTypeFor(full), body)
  res.withHeader("X-Content-Type-Options", "nosniff")
  return responseToString(res, includeBody)

proc serveFile*(root: string; urlPath: string): string =
  ## Backwards-compatible static GET helper.
  staticResponse(root, urlPath, true)
