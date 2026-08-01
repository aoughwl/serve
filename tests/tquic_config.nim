## tquic_config.nim — QUIC transport parameters as a record.
##
## The assertions that can be made cheaply and honestly here are about the
## record and the C boundary: that the layout matches (the shim fills eight
## int64 fields and nimony reads back the values the shim actually holds), that
## `QuicKeep` is distinguishable from a real 0, and that an override is
## readable back. Whether each parameter then changes the bytes on the wire is
## ngtcp2's job, and is covered by the H3 and datagram e2e suites continuing to
## pass with a config applied.

import std/syncio
import quic/quicconfig

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc main =
  # --- the layout matches across the FFI boundary -------------------------
  # These values are written by the C side into a struct nimony declared by
  # hand. If the field order or width drifted, they would land in the wrong
  # fields and these comparisons would fail — which is the point of asserting
  # the actual numbers rather than "the call returned".
  let shipped = defaultQuicConfig()
  check(shipped.maxStreamsUni == 100,
        "uni stream budget read back as 100, got " & $shipped.maxStreamsUni)
  check(shipped.maxStreamsBidi == 100, "bidi stream budget")
  check(shipped.streamDataBidiLocal == 256 * 1024, "bidi-local window")
  check(shipped.streamDataBidiRemote == 256 * 1024, "bidi-remote window")
  check(shipped.streamDataUni == 256 * 1024, "uni window")
  check(shipped.maxData == 1024 * 1024, "connection window")
  check(shipped.maxIdleMs == 30000, "idle timeout in ms")
  check(shipped.maxDatagramSize == 65535, "datagram frame size")

  # The stream budget is not a cosmetic default: 3 HTTP/3 control streams once
  # consumed the entire allowance when it was 3.
  check(shipped.maxStreamsUni > 3,
        "the uni budget must leave room beyond the H3 control streams")

  # --- keep is not off ----------------------------------------------------
  check(QuicKeep != 0,
        "keep and 0 must differ: 0 disables datagrams, and that is a real request")
  check(datagramsEnabled(noQuicConfig()),
        "an empty override leaves datagrams alone")
  var off = noQuicConfig()
  off.maxDatagramSize = 0
  check(not datagramsEnabled(off), "an explicit 0 turns datagrams off")

  # --- merge --------------------------------------------------------------
  var over = noQuicConfig()
  over.maxIdleMs = 5000
  let merged = merge(defaultQuicConfig(), over)
  check(merged.maxIdleMs == 5000, "the set field overrides")
  check(merged.maxStreamsUni == 100, "unset fields keep the base value")
  check(merged.maxData == 1024 * 1024, "including the connection window")

  # --- an override survives the round trip through the shim ---------------
  applyQuicConfig(over)
  let inForce = currentQuicConfig()
  check(inForce.maxIdleMs == 5000, "the override reached the shim")
  check(inForce.maxStreamsUni == QuicKeep,
        "and the fields it did not mention are still 'keep', not zeroed")

  resetQuicConfig()
  let cleared = currentQuicConfig()
  check(cleared.maxIdleMs == QuicKeep, "reset drops the override")
  check(cleared.maxStreamsUni == QuicKeep, "on every field")

  echo "tquic_config: all checks passed"

main()
