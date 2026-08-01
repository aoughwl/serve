#!/usr/bin/env python3
"""A THIRD-PARTY HTTP/3 client (aioquic) for interop-testing our QUIC server.

Every HTTP/3 and WebTransport test in this repo drives our own shim against our
own shim. That proves the two halves agree with each other; it proves nothing
about whether either agrees with RFC 9000/9114. This script closes that hole by
speaking to the server with an implementation we did not write.

  python3 tests/h3_interop_client.py <host> <port> <path> [post-body]

Prints "STATUS=<n>" and "BODY=<text>" on success, or "ERROR=<reason>".
"""
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._status = None
        self._body = b""
        self._done = asyncio.Event()

    def quic_event_received(self, event):
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                for name, value in ev.headers:
                    if name == b":status":
                        self._status = int(value)
                if ev.stream_ended:
                    self._done.set()
            elif isinstance(ev, DataReceived):
                self._body += ev.data
                if ev.stream_ended:
                    self._done.set()

    async def request(self, authority, path, body=None):
        stream_id = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", b"POST" if body else b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ]
        self._http.send_headers(stream_id, headers, end_stream=not body)
        if body:
            self._http.send_data(stream_id, body.encode(), end_stream=True)
        self.transmit()
        await asyncio.wait_for(self._done.wait(), timeout=10)
        return self._status, self._body


async def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    path = sys.argv[3] if len(sys.argv) > 3 else "/"
    body = sys.argv[4] if len(sys.argv) > 4 else None

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    # the test server uses a self-signed cert; interop is about the protocol
    cfg.verify_mode = ssl.CERT_NONE

    async with connect(host, port, configuration=cfg,
                       create_protocol=H3Client) as client:
        status, payload = await client.request(host, path, body)
        print("STATUS=%s" % status)
        print("BODY=%s" % payload.decode("utf-8", "replace").strip())


if __name__ == "__main__":
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except Exception as exc:  # noqa: BLE001 - the harness wants the reason
        print("ERROR=%s: %s" % (type(exc).__name__, exc))
        sys.exit(1)
