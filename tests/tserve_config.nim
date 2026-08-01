## tserve_config.nim — one value describing a server.
##
## Two properties, and the second is the one that used to bite. `setServeLimits`
## takes both a request cap and a keep-alive count, so raising one meant passing
## a value for the other -- and passing the default for the other is how "I
## raised the request cap" silently reset the keep-alive count. An override
## record that mentions one field must leave the other exactly as it was.
##
## The listener policy is checked by reading the option back off the descriptor
## `serveListen` produced, not by trusting that it was stored.

import std/syncio
import tcp
import http/stream
import serve/applyconfig
import serve/listener
import serve/loop
import serve/reactorhttp
import serve/static

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc main =
  initTcp()

  # --- the defaults are readable, and the two models differ on purpose ----
  let shipped = defaultServerConfig()
  check(shipped.maxRequestBytes == DefaultMaxRequestBytes, "default request cap")
  check(shipped.maxKeepAlive == DefaultServeKeepAlive, "blocking keep-alive")
  check(shipped.reactorMaxKeepAlive == DefaultReactorKeepAlive, "reactor keep-alive")
  check(shipped.reactorMaxKeepAlive != shipped.maxKeepAlive,
        "the two models keep different defaults, and one field cannot hold both")
  check(shipped.readTimeoutMs == DefaultReadTimeoutMs, "default read timeout")

  # --- merge recurses into the sub-records --------------------------------
  var over = noServerConfig()
  over.maxRequestBytes = 1024
  over.listener.backlog = 512
  let merged = merge(defaultServerConfig(), over)
  check(merged.maxRequestBytes == 1024, "the set scalar overrides")
  check(merged.maxKeepAlive == DefaultServeKeepAlive, "the unset scalar inherits")
  check(merged.listener.backlog == 512, "the sub-record's set field overrides")
  check(merged.listener.reuseAddr == optOn,
        "the sub-record's unset field inherits from the base's listener policy")
  check(merged.parser.maxLine == DefaultMaxLine,
        "an untouched sub-record keeps every default")

  check(not usesTls(defaultServerConfig()), "no cert pair means no TLS")
  check(usesTls(withTls(defaultServerConfig(), "c.pem", "k.pem")),
        "withTls attaches the pair")
  check(resolve(ServeUnset, 7) == 7, "unset resolves to the fallback")
  check(resolve(0, 7) == 0, "zero is a real value, not an absence")

  # --- an override touches only what it mentions --------------------------
  applyServerConfig(defaultServerConfig())
  let before = serveLimits()
  check(before.maxKeepAlive == DefaultServeKeepAlive, "baseline keep-alive")

  var raiseCap = noServerConfig()
  raiseCap.maxRequestBytes = 32 * 1024 * 1024
  applyServerConfig(raiseCap)

  let after = serveLimits()
  check(after.maxRequestBytes == 32 * 1024 * 1024, "the request cap was raised")
  check(after.maxKeepAlive == before.maxKeepAlive,
        "raising the request cap must not reset the keep-alive count")

  # The reactor's own limits are separate globals and must move together with
  # the shared record, without inheriting the blocking server's keep-alive.
  let reactorAfter = reactorLimits()
  check(reactorAfter.maxRequestBytes == 32 * 1024 * 1024,
        "the reactor's request cap was raised too")
  check(reactorAfter.maxKeepAlive == DefaultReactorKeepAlive,
        "and the reactor kept its own keep-alive default")

  # --- timeouts and the static cap ----------------------------------------
  var timeouts = noServerConfig()
  timeouts.readTimeoutMs = 3000
  timeouts.idleTimeoutMs = 9000
  timeouts.maxStaticBytes = 4096
  applyServerConfig(timeouts)
  check(serveReadTimeout() == 3000, "read timeout applied")
  check(reactorIdleTimeout() == 9000,
        "idle timeout applied — it was previously settable only as an entry-point argument")

  let now = currentServerConfig()
  check(now.readTimeoutMs == 3000, "the current policy is readable back")
  check(now.maxRequestBytes == 32 * 1024 * 1024, "including what an earlier merge set")

  # --- the listener policy reaches a real socket --------------------------
  var listenerCfg = noServerConfig()
  listenerCfg.listener = defaultListenerOpts()
  listenerCfg.listener.reuseAddr = optOff       # the opt-out that did not exist
  listenerCfg.listener.recvBufferSize = 131072
  applyServerConfig(listenerCfg)

  let fd = serveListen(0)
  check(isValidTcp(fd), "listener created under the configured policy")
  check(ok(lastListenReport()),
        "policy accepted: " & lastListenReport().firstFailure)

  var value = 0
  check(getTcpOptionByName(fd, "reuseaddr", value), "read back reuseaddr")
  check(value == 0,
        "reuseAddr: optOff reached the listening socket a server actually creates")
  check(getTcpOptionByName(fd, "rcvbuf", value), "read back rcvbuf")
  check(value >= 131072, "recvBufferSize reached the listening socket")
  closeTcp(fd)

  # Restore something sane for anything else in the process.
  applyServerConfig(defaultServerConfig())
  check(serveListenerOpts().reuseAddr == optOn, "the policy is replaceable")

  shutdownTcp()
  echo "tserve_config: all checks passed"

main()
