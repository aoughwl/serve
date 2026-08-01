## Static serving with the request in hand: ETag / Last-Modified / 304, byte
## ranges (206, 416), and the file-size cap.
##
## Before this, `staticRoute` ignored the request entirely and re-sent every
## unchanged asset in full on every visit.

import std/[syncio, os]
import http/headers
import http/request
import http/response
import serve/static

var failures = 0
proc check(cond: bool; what: string) =
  if not cond:
    echo "FAIL: ", what
    inc failures

proc req(path: string; hname = ""; hvalue = ""): Request =
  var raw = "GET " & path & " HTTP/1.1\r\nHost: h\r\n"
  if hname.len > 0:
    raw.add hname & ": " & hvalue & "\r\n"
  raw.add "\r\n"
  parseRequest(raw)

const Root = "/tmp/aoughwl-static-test"
const Body = "0123456789abcdefghij"          # 20 bytes, easy offsets

proc main =
  # --- the date formatter, against known values ------------------------------
  check(httpDate(0'i64) == "Thu, 01 Jan 1970 00:00:00 GMT",
        "epoch 0 formats as the Unix epoch: " & httpDate(0'i64))
  check(httpDate(784111777'i64) == "Sun, 06 Nov 1994 08:49:37 GMT",
        "RFC 7231's own example date: " & httpDate(784111777'i64))
  check(httpDate(1451606400'i64) == "Fri, 01 Jan 2016 00:00:00 GMT",
        "a leap-year boundary: " & httpDate(1451606400'i64))

  # --- range parsing, in isolation ------------------------------------------
  var a = 0'i64
  var b = 0'i64
  check(parseByteRange("bytes=0-4", 20'i64, a, b) == 1 and a == 0 and b == 4, "bytes=0-4")
  check(parseByteRange("bytes=5-", 20'i64, a, b) == 1 and a == 5 and b == 19, "open-ended range")
  check(parseByteRange("bytes=-5", 20'i64, a, b) == 1 and a == 15 and b == 19, "suffix range")
  check(parseByteRange("bytes=0-999", 20'i64, a, b) == 1 and b == 19, "end clamped to the entity")
  check(parseByteRange("bytes=20-25", 20'i64, a, b) == -1, "start past the end is unsatisfiable")
  check(parseByteRange("bytes=0-4,6-9", 20'i64, a, b) == 0, "multi-range falls back to the whole entity")
  check(parseByteRange("items=0-4", 20'i64, a, b) == 0, "a non-bytes unit is ignored")
  check(parseByteRange("", 20'i64, a, b) == 0, "no Range header")

  # --- and end to end over a real file ---------------------------------------
  # No mkdir in nimony's std/os, so the directory comes from the shell; the
  # test creates only the file.
  discard execShellCmd("mkdir -p " & Root)
  try:
    writeFile(Root & "/f.txt", Body)
  except:
    echo "SKIP: could not write under ", Root
    quit(0)

  let full = staticResponseFor(Root, req("/f.txt"))
  check(full.status == 200, "200 for a plain GET")
  check(full.body == Body, "whole body")
  let etag = headerValue(full.headers, "ETag")
  check(etag.len > 2 and etag[0] == '"', "an ETag was issued: " & etag)
  let lastMod = headerValue(full.headers, "Last-Modified")
  check(lastMod.len > 0, "a Last-Modified was issued")
  check(headerValue(full.headers, "Accept-Ranges") == "bytes", "Accept-Ranges advertised")

  let notMod = staticResponseFor(Root, req("/f.txt", "If-None-Match", etag))
  check(notMod.status == 304, "If-None-Match with our own tag is a 304")
  check(notMod.body.len == 0, "a 304 carries no body")

  let star = staticResponseFor(Root, req("/f.txt", "If-None-Match", "*"))
  check(star.status == 304, "If-None-Match: * is a 304")

  let weak = staticResponseFor(Root, req("/f.txt", "If-None-Match", "W/" & etag))
  check(weak.status == 304, "a weak echo of our tag still matches")

  let stale = staticResponseFor(Root, req("/f.txt", "If-None-Match", "\"nope\""))
  check(stale.status == 200, "a tag that does not match gets the body")

  let ims = staticResponseFor(Root, req("/f.txt", "If-Modified-Since", lastMod))
  check(ims.status == 304, "If-Modified-Since echoing our own Last-Modified is a 304")

  let part = staticResponseFor(Root, req("/f.txt", "Range", "bytes=5-9"))
  check(part.status == 206, "a range is a 206")
  check(part.body == "56789", "the right bytes came back: " & part.body)
  check(headerValue(part.headers, "Content-Range") == "bytes 5-9/20",
        "Content-Range: " & headerValue(part.headers, "Content-Range"))

  let bad = staticResponseFor(Root, req("/f.txt", "Range", "bytes=99-120"))
  check(bad.status == 416, "an unsatisfiable range is a 416")
  check(headerValue(bad.headers, "Content-Range") == "bytes */20",
        "416 states the entity length")

  # --- the cap ---------------------------------------------------------------
  let before = staticFilesRefused()
  setStaticFileLimit(5)
  let tooBig = staticResponseFor(Root, req("/f.txt"))
  check(tooBig.status == 500, "a file over the cap is refused")
  check(staticFilesRefused() == before + 1, "and the refusal is counted")
  setStaticFileLimit(MaxStaticFileBytes)

  let traversal = staticResponseFor(Root, req("/../etc/passwd"))
  check(traversal.status == 403, "traversal is still refused")

  if failures == 0:
    echo "tserve_static_cond: all checks passed"
    quit(0)
  else:
    echo "tserve_static_cond: ", failures, " failures"
    quit(1)

main()
