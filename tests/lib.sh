#!/usr/bin/env bash
# Shared helpers for the e2e gates.
#
# `build_example <name>` compiles examples/<name>.nim into a caller-supplied
# nimcache and echoes the binary path.
#
# It retries ONCE, and says so, because the nimony link step is intermittently
# non-deterministic under `nifmake -j`: a build occasionally ends with an
# undefined reference to a runtime symbol (`mi_free`, or a module's string
# literals) that is plainly present, and the identical command succeeds
# immediately afterwards. That is a toolchain bug, not a test-environment
# nicety — the retry exists so a gate reports the state of the SERVER rather
# than the state of that race, and it prints a note every time it fires so the
# race stays visible instead of being quietly absorbed.

NIMONY="${NIMONY:-$HOME/nimony/bin/nimony}"

net_paths() {   # net_paths <repo-root>
  local root="$1" h="$HOME"
  echo "--path:$root --path:$h/aoughwl-http --path:$h/aoughwl-tcp \
--path:$h/aoughwl-net --path:$h/aoughwl-tls --path:$h/aoughwl-ws \
--path:$h/aoughwl-compress"
}

build_example() {   # build_example <repo-root> <nimcache-dir> <example-name>
  local root="$1" nc="$2" name="$3" bin=""
  local attempt
  for attempt in 1 2; do
    # shellcheck disable=SC2046  # word splitting of the --path list is intended
    "$NIMONY" c --nimcache:"$nc" $(net_paths "$root") \
      "$root/examples/$name.nim" 2>&1 | grep -viE '^nifmake|^FAILURE|niflink' >&2 || true
    bin="$(find "$nc" -type f -name "$name" -executable | head -1)"
    if [[ -n "$bin" ]]; then
      if (( attempt > 1 )); then
        echo "note: $name linked only on retry (transient nifmake -j link race)" >&2
      fi
      echo "$bin"
      return 0
    fi
  done
  return 1
}
