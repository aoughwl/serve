## serve/encoding.nim — response compression negotiation for `serve` handlers.
## (Named `encoding` rather than `compress` to avoid a build-key collision with
## `http/compress`, whose codecs it wraps.)
##
## Opt-in: a handler wraps its `Response` in `compressResponse(req, resp)`, which
## checks the request's `Accept-Encoding`, compresses the body with the best
## supported codec (br > gzip), and sets `Content-Encoding` + `Vary`. Kept out of
## the core loop so plain servers pay no CPU for compression they didn't ask for.

import http/headers
import http/request
import http/response
import http/contentcoding
export contentcoding

const MinCompressBytes = 64

proc compressResponse*(req: Request; resp: Response): Response =
  ## Return `resp` with its body compressed for the client's `Accept-Encoding`,
  ## or unchanged when no encoding applies (tiny body, already encoded, client
  ## accepts none, or compression didn't help).
  result = resp
  if hasHeader(resp.headers, "Content-Encoding"): return result
  if resp.body.len < MinCompressBytes: return result
  let enc = pickEncoding(headerValue(req.headers, "Accept-Encoding"))
  if enc.len == 0: return result
  let encoded = encodeFor(enc, resp.body)
  if encoded.len == 0 or encoded.len >= resp.body.len: return result
  result.body = encoded
  result.withHeader("Content-Encoding", enc)
  result.withHeader("Vary", "Accept-Encoding")
