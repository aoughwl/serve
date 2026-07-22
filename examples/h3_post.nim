## A minimal HTTP/3 (QUIC) POST client: POST a body to a path, print status+body.
##   LD_LIBRARY_PATH=<serve>/quic bin/h3_post 8443 /mcp '{"jsonrpc":"2.0",...}'

import std/[cmdline, strutils, syncio]
import serve/reactorh3

var port = 8443
var path = "/"
var body = ""
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
if paramCount() >= 2: path = paramStr(2)
if paramCount() >= 3: body = paramStr(3)

let r = h3Post("127.0.0.1", port, "localhost", path, body)
echo "STATUS=", r.status
stdout.write r.body
