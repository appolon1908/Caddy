#!/usr/bin/env python3
"""Read-only WebSocket upgrade probe for the production canary.

Opens one TLS connection to a fixed address with the canonical server name,
verifies the certificate, asks for a WebSocket upgrade and closes immediately.
It sends no frames, so no application message is ever delivered.
"""
from __future__ import annotations

import base64
import secrets
import socket
import ssl
import sys


def probe(host: str, address: str, path: str, port: int = 443, *, context: ssl.SSLContext | None = None) -> str:
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    context = context or ssl.create_default_context()
    with socket.create_connection((address, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n".encode("ascii")
            )
            status = connection.recv(4096).decode("latin-1").split("\r\n", 1)[0]
    return status


def main() -> int:
    if len(sys.argv) != 4 or not sys.argv[3].startswith("/"):
        print("usage: websocket_probe.py SERVER_NAME ADDRESS PATH", file=sys.stderr)
        return 2
    try:
        status = probe(*sys.argv[1:4])
    except (OSError, ssl.SSLError) as exc:
        print(f"WEBSOCKET_CANARY=FAIL:{type(exc).__name__}", file=sys.stderr)
        return 2
    if not status.startswith("HTTP/1.1 101"):
        print(f"WEBSOCKET_CANARY=FAIL:{status or 'empty'}", file=sys.stderr)
        return 2
    print("WEBSOCKET_CANARY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
