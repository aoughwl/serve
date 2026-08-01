## serve/asyncclient.nim — an HTTP/1.1 client that runs INSIDE a reactor
## coroutine.
##
## The stack could serve requests asynchronously and make them only
## synchronously: every client path (`net`, `tls`, `requests`) blocks the
## calling thread. On a single-threaded server that is fatal — one upstream call
## stops every other connection — so a server could not proxy, call a webhook,
## or talk to an upstream API without giving up the reactor model.
##
## These are templates for the same reason `asyncio`'s are: each must inline its
## own suspend points into the calling coroutine.
##
## Scope, stated rather than implied:
##   * HTTP/1.1 over plaintext or TLS, one request per connection (`Connection:
##     close`). No pooling, no keep-alive reuse, no redirect following — those
##     are policy, and belong above this.
##   * **DNS resolution blocks.** `getaddrinfo` has no non-blocking form worth
##     the name; a resolver thread is the fix and is not built. Pass an IP
##     literal to avoid it entirely — `awaitFetch` accepts one — and know that a
##     hostname costs the reactor thread the lookup.

when defined(nimony):
  {.feature: "lenientnils".}

import tcp
import net
import tls
import ./reactor
import ./asyncio
import ./asyncconn
import tcp/epoll as ep
import http/response
import http/headers

const ClientChunk = 4096

var gClientTlsCtx = TlsContext(handle: nil, mode: tlsClient, stateId: 0)

proc clientTlsContext*(): TlsContext =
  ## The shared client-side TLS context, created on first use (system trust
  ## store, hostname verification on). Exposed so a caller can pin a CA, relax
  ## verification for a test, or set groups/versions once for every request.
  if not gClientTlsCtx.isValid:
    gClientTlsCtx = newTlsClientContext(true)
    discard gClientTlsCtx.setAlpnProtocols(@["http/1.1"])
  gClientTlsCtx

proc setClientTlsContext*(ctx: TlsContext) =
  ## Replace the shared client context.
  gClientTlsCtx = ctx

proc buildRequest*(meth, path, host, body: string): string =
  ## A complete HTTP/1.1 request. `Connection: close` because this client does
  ## one request per connection — saying so is what lets the server frame the
  ## response by EOF if it wants to.
  result = meth & " " & path & " HTTP/1.1\r\n"
  result.add "Host: " & host & "\r\n"
  result.add "Connection: close\r\n"
  if body.len > 0:
    result.add "Content-Length: " & $body.len & "\r\n"
  result.add "\r\n"
  result.add body

template awaitConnect*(r: Reactor; ip: uint32; port: int; fdOut: var cint;
                       okOut: var bool) =
  ## Start a non-blocking connect and suspend until it resolves. `fdOut` is the
  ## registered socket on success; the caller owns it either way.
  okOut = false
  fdOut = InvalidTcpHandle
  let res = connectTcp4NonBlocking(uint32(ip), port)
  if isValidTcp(res.handle):
    fdOut = res.handle
    r.register(fdOut)
    if res.status == tcpConnectConnected:
      okOut = true
    else:
      # In progress: the socket becomes WRITABLE when the handshake resolves,
      # either way — SO_ERROR is what says which.
      let k = delay()
      r.park(fdOut, ep.EPOLLOUT, k)
      suspend()
      okOut = finishTcpConnect(fdOut)

template awaitFetch*(r: Reactor; hostOrIp: string; port: int; useTls: bool;
                     meth, path, body: string; resp: var Response;
                     okOut: var bool) =
  ## One HTTP/1.1 request from inside a coroutine: connect, optionally TLS
  ## handshake, write, read to EOF or Content-Length, parse. `okOut` is false if
  ## any step failed; `resp.status` is 0 on a response that never parsed.
  ##
  ## Everything here suspends — the calling coroutine yields the thread at every
  ## step, so a server can call out while continuing to serve everyone else.
  okOut = false
  resp = Response(status: 0, contentType: "", headers: @[], body: "")
  var ip = 0'u32
  if resolveTcp4(hostOrIp, ip):        # blocking; see the module doc
    var cfd = InvalidTcpHandle
    var connected = false
    r.awaitConnect(ip, port, cfd, connected)
    if isValidTcp(cfd):
      var c = plainConn(cfd)
      if connected and useTls:
        c = Conn(fd: cfd, isTls: true,
                 tls: wrapClient(clientTlsContext(), Socket(handle: cfd), hostOrIp))
      var ready = false
      if connected:
        r.awaitConnHandshake(c, ready)
      # --- write the request ------------------------------------------------
      var sent = false
      if ready:
        let reqStr = buildRequest(meth, path, hostOrIp, body)
        var sbuf = newSeq[char](reqStr.len)
        var si = 0
        while si < reqStr.len:
          sbuf[si] = reqStr[si]
          inc si
        if sbuf.len == 0:
          sent = true
        else:
          r.awaitConnWriteAll(c, addr sbuf[0], sbuf.len, sent)
      # --- read the response ------------------------------------------------
      var raw = ""
      if sent:
        var rbuf = default(array[ClientChunk, char])
        var reading = true
        var headEnd = -1
        var wantLen = -1
        while reading:
          var got = 0
          r.awaitConnRead(c, addr rbuf[0], ClientChunk, got)
          if got <= 0:
            reading = false          # EOF (or error) ends the body too
          else:
            var k = 0
            while k < got:
              raw.add rbuf[k]
              inc k
            if headEnd < 0:
              headEnd = responseHeaderEnd(raw)
              if headEnd >= 0:
                let head = parseResponse(raw)
                let cl = headerValue(head, "Content-Length")
                if cl.len > 0:
                  var v = 0
                  var good = cl.len > 0
                  var ci = 0
                  while ci < cl.len:
                    if cl[ci] < '0' or cl[ci] > '9': good = false
                    else: v = v * 10 + (ord(cl[ci]) - ord('0'))
                    inc ci
                  if good:
                    wantLen = v
            if headEnd >= 0 and wantLen >= 0 and raw.len >= headEnd + wantLen:
              reading = false        # framed by Content-Length: stop, do not
                                     # wait for a close the server may not send
        if raw.len > 0:
          resp = parseResponse(raw)
          if eqIgnoreCase(headerValue(resp, "Transfer-Encoding"), "chunked"):
            resp.body = decodeChunked(resp.body)
          okOut = resp.status > 0
      var scratch = default(array[64, char])
      r.closeConn(c, addr scratch[0], 64, 0)
