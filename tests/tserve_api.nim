## tserve_api.aowl — public API smoke test for serve.

import serve

var fd = InvalidTcpHandle
discard fd

discard contentTypeFor("/tmp/index.html")
discard normalizeUrlPath("/x?q=1")
discard httpResponse(200, "text/plain", "ok")
