## quic/quicconfig.nim — QUIC transport parameters as a record.
##
## Eight values in the shim's `default_tp` were literals, so a deployment could
## not touch one of them: not the flow-control windows, not the idle timeout,
## not the stream budgets. The stream budget is not a detail — 3 HTTP/3 control
## streams once consumed the entire `initial_max_streams_uni` allowance, which
## is why it is 100 and not 3.
##
## `QuicKeep` (-1) means "leave the built-in default alone", and it is
## deliberately not 0, because 0 is a real value for `maxDatagramSize`: it
## disables RFC 9221 datagrams and with them WebTransport datagrams. If unset
## and off were the same value, "do not touch datagrams" and "turn datagrams
## off" would be the same request.
##
## Scope: these are the *transport* parameters. The shim's fixed capacities
## (MAX_CONNS, MAX_STREAMS, MAX_CIDS, MAX_REQ) are still compile-time
## `#ifndef`s, counted in `AqStats` when they overflow but not settable here.

when defined(nimony):
  {.feature: "lenientnils".}

const lib = "libaowlquic.so"

const
  QuicKeep* = -1'i64
    ## Leave the shim's built-in default in place for this field.

type
  QuicConfig* = object
    ## Hand-laid to match the shim's `aq_config`: eight `int64_t` in this order.
    ## The same stance the stack takes with nghttp2's structs and zlib's
    ## `z_stream` — the shim is loaded by `dynlib`, so there is no header to
    ## import and field order is the contract.
    maxStreamsBidi*: int64
    maxStreamsUni*: int64
    streamDataBidiLocal*: int64
    streamDataBidiRemote*: int64
    streamDataUni*: int64
    maxData*: int64
    maxIdleMs*: int64
    maxDatagramSize*: int64

proc aqSetConfig(c: pointer) {.importc: "aq_set_config", dynlib: lib.}
proc aqGetConfig(o: pointer) {.importc: "aq_get_config", dynlib: lib.}
proc aqDefaultConfig(o: pointer) {.importc: "aq_default_config", dynlib: lib.}

proc noQuicConfig*(): QuicConfig =
  ## The empty override: every field keeps the shim's default. Applying this is
  ## a no-op, which is what makes it a safe base for a merge.
  QuicConfig(
    maxStreamsBidi: QuicKeep, maxStreamsUni: QuicKeep,
    streamDataBidiLocal: QuicKeep, streamDataBidiRemote: QuicKeep,
    streamDataUni: QuicKeep, maxData: QuicKeep,
    maxIdleMs: QuicKeep, maxDatagramSize: QuicKeep)

proc defaultQuicConfig*(): QuicConfig =
  ## The shim's own built-in values, read back from the shim rather than
  ## restated here — two copies of a default is one copy too many, and the C
  ## side is where they take effect.
  result = noQuicConfig()
  aqDefaultConfig(cast[pointer](addr result))

proc currentQuicConfig*(): QuicConfig =
  ## The override currently in force. Fields still at `QuicKeep` are the ones
  ## the shim will fill from its defaults.
  result = noQuicConfig()
  aqGetConfig(cast[pointer](addr result))

proc merge*(base: QuicConfig; over: QuicConfig): QuicConfig =
  ## A field set in `over` wins; `QuicKeep` inherits.
  result = base
  if over.maxStreamsBidi != QuicKeep: result.maxStreamsBidi = over.maxStreamsBidi
  if over.maxStreamsUni != QuicKeep: result.maxStreamsUni = over.maxStreamsUni
  if over.streamDataBidiLocal != QuicKeep:
    result.streamDataBidiLocal = over.streamDataBidiLocal
  if over.streamDataBidiRemote != QuicKeep:
    result.streamDataBidiRemote = over.streamDataBidiRemote
  if over.streamDataUni != QuicKeep: result.streamDataUni = over.streamDataUni
  if over.maxData != QuicKeep: result.maxData = over.maxData
  if over.maxIdleMs != QuicKeep: result.maxIdleMs = over.maxIdleMs
  if over.maxDatagramSize != QuicKeep:
    result.maxDatagramSize = over.maxDatagramSize

proc applyQuicConfig*(cfg: QuicConfig) =
  ## Apply a transport-parameter policy to every context created afterwards.
  ## It is read when a connection's parameters are built, so it must be set
  ## before `quicServer` / `quicClient`, not after.
  var c = cfg
  aqSetConfig(cast[pointer](addr c))

proc resetQuicConfig*() =
  ## Drop the override entirely; subsequent contexts use the shim's defaults.
  aqSetConfig(cast[pointer](0))

proc datagramsEnabled*(cfg: QuicConfig): bool =
  ## Whether this policy leaves RFC 9221 datagrams available. `QuicKeep` does
  ## (the default enables them); an explicit 0 does not.
  cfg.maxDatagramSize != 0
