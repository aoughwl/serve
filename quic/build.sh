#!/usr/bin/env bash
# Build the QUIC/HTTP-3 glue shim (libaowlquic.so) against system
# ngtcp2 + ngtcp2_crypto_gnutls + nghttp3 + gnutls.
#
# Ubuntu deps:  libngtcp2-dev libngtcp2-crypto-gnutls-dev libnghttp3-dev libgnutls28-dev
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PKGS="libngtcp2 libngtcp2_crypto_gnutls libnghttp3 gnutls"
for p in $PKGS; do
  pkg-config --exists "$p" || { echo "missing pkg-config module: $p (apt install lib${p#lib}-dev)"; exit 1; }
done
gcc -O2 -fPIC -shared -Wall -o libaowlquic.so quicglue.c \
  $(pkg-config --cflags --libs $PKGS)
echo "built: $(pwd)/libaowlquic.so"
