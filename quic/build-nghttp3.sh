#!/usr/bin/env bash
# Build nghttp3 >= 1.x into quic/vendor so the glue shim gets WebTransport support
# (extended CONNECT + H3 datagrams) that Ubuntu's nghttp3 0.8.0 lacks. Run once;
# then quic/build.sh auto-detects quic/vendor and enables WebTransport.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
VENDOR="$(pwd)/vendor"
VER="${NGHTTP3_VERSION:-1.6.0}"
TMP="$(mktemp -d)"
url="https://github.com/ngtcp2/nghttp3/releases/download/v$VER/nghttp3-$VER.tar.gz"
echo "fetching $url"
curl -sSL -o "$TMP/nghttp3.tar.gz" "$url"
tar xzf "$TMP/nghttp3.tar.gz" -C "$TMP"
cd "$TMP/nghttp3-$VER"
./configure --prefix="$VENDOR" --enable-lib-only --disable-dependency-tracking >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
rm -rf "$TMP"
echo "installed nghttp3 $VER -> $VENDOR"
