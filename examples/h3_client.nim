## A minimal HTTP/3 (QUIC) client: fetch one path and print status + body.
##   LD_LIBRARY_PATH=<serve>/quic bin/h3_client 8443 /hello

import std/[cmdline, strutils, syncio]
import serve/reactorh3

var port = 8443
var path = "/"
if paramCount() >= 1:
  try: port = parseInt(paramStr(1))
  except: port = 8443
if paramCount() >= 2: path = paramStr(2)

let r = h3Get("127.0.0.1", port, "localhost", path)
echo "STATUS=", r.status
stdout.write r.body
