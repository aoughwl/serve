## serve/static.aowl — map a URL path onto a file under a served root dir and
## build the HTTP response for it. Standard-library only.
##
## Rules:
##   * `/`               -> `/index.html`
##   * any `?query`      -> stripped before the file lookup
##   * a path with `..`  -> 403 (no directory traversal)
##   * missing file      -> 404
##   * Content-Type by extension: .html/.js/.css, else text/plain

import std/os        # fileExists
import std/syncio    # readFile
import http

proc endsWithSuffix(s, suffix: string): bool =
  ## Non-allocating "does s end with suffix?".
  if suffix.len > s.len: return false
  var i = 0
  let off = s.len - suffix.len
  while i < suffix.len:
    if s[off + i] != suffix[i]: return false
    inc i
  return true

proc contentTypeFor(path: string): string =
  ## Pick a Content-Type from the file extension (char-walk suffix match).
  if endsWithSuffix(path, ".html") or endsWithSuffix(path, ".htm"): "text/html"
  elif endsWithSuffix(path, ".js"): "text/javascript"
  elif endsWithSuffix(path, ".css"): "text/css"
  else: "text/plain"

proc hasDotDot(s: string): bool =
  ## True if the path contains a ".." segment (traversal attempt).
  var i = 0
  while i + 1 < s.len:
    if s[i] == '.' and s[i + 1] == '.': return true
    inc i
  return false

proc serveFile*(root: string; urlPath: string): string =
  ## Route a URL path to a file under `root` and return a full HTTP response.
  # 1. strip any ?query
  var p = ""
  var i = 0
  while i < urlPath.len and urlPath[i] != '?':
    p.add urlPath[i]
    inc i
  # 2. default document
  if p.len == 0 or p == "/":
    p = "/index.html"
  # 3. reject traversal
  if hasDotDot(p):
    return httpResponse(403, "text/plain", "Forbidden\n")
  # 4. join root + path (drop the leading '/')
  var rel = ""
  var j = 0
  if p.len > 0 and p[0] == '/':
    j = 1
  while j < p.len:
    rel.add p[j]
    inc j
  let full = root & "/" & rel
  # 5. read + respond
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
  return httpResponse(200, contentTypeFor(p), body)
