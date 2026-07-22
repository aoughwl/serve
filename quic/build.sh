#!/usr/bin/env bash
# Build the QUIC/HTTP-3 glue shim (libaowlquic.so) against system
# ngtcp2 + ngtcp2_crypto_gnutls + nghttp3 + gnutls.
#
# Ubuntu deps:  libngtcp2-dev libngtcp2-crypto-gnutls-dev libnghttp3-dev libgnutls28-dev
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
HERE="$(pwd)"
VENDOR="$HERE/vendor"

# WebTransport needs nghttp3 >= 1.x (extended CONNECT + H3 datagrams). Ubuntu
# ships only 0.8.0, so if a vendored build is present (quic/vendor, built by
# build-nghttp3.sh) we prefer it; otherwise fall back to the system nghttp3
# (plain HTTP/3 works, WebTransport is disabled).
if [[ -f "$VENDOR/lib/pkgconfig/libnghttp3.pc" ]]; then
  NGH3_CFLAGS="-I$VENDOR/include"
  NGH3_LIBS="-L$VENDOR/lib -lnghttp3 -Wl,-rpath,$VENDOR/lib"
  echo "using vendored nghttp3 $(PKG_CONFIG_PATH="$VENDOR/lib/pkgconfig" pkg-config --modversion libnghttp3) (WebTransport enabled)"
  WT=1
else
  NGH3_CFLAGS="$(pkg-config --cflags libnghttp3)"
  NGH3_LIBS="$(pkg-config --libs libnghttp3)"
  echo "using system nghttp3 $(pkg-config --modversion libnghttp3) (WebTransport disabled)"
  WT=0
fi

PKGS="libngtcp2 libngtcp2_crypto_gnutls gnutls"
for p in $PKGS; do
  pkg-config --exists "$p" || { echo "missing pkg-config module: $p"; exit 1; }
done
gcc -O2 -fPIC -shared -Wall -DAQ_WEBTRANSPORT=$WT -o libaowlquic.so quicglue.c \
  $NGH3_CFLAGS $(pkg-config --cflags $PKGS) \
  $NGH3_LIBS $(pkg-config --libs $PKGS)
echo "built: $HERE/libaowlquic.so"
