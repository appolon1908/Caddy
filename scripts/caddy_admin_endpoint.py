#!/usr/bin/env python3
"""How Codestra tooling reaches the private Caddy admin API.

Production serves the admin API on a Unix socket, so only local processes with
file access to the socket can reconfigure Caddy. Loopback TCP stays accepted for
disposable test instances. Anything else is rejected.
"""
from __future__ import annotations

import http.client
import socket
import urllib.parse
from dataclasses import dataclass

ADMIN_SOCKET = "/run/caddy/admin.sock"
ADMIN_ADDRESS = f"unix/{ADMIN_SOCKET}"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
UNIX_SCHEME = "http+unix"


class AdminEndpointError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AdminEndpoint:
    socket_path: str | None = None
    host: str | None = None
    port: int | None = None

    @property
    def caddy_address(self) -> str:
        """The form `caddy reload --address` and the Caddyfile `admin` option use."""
        return f"unix/{self.socket_path}" if self.socket_path else f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        if self.socket_path:
            return f"{UNIX_SCHEME}://{urllib.parse.quote(self.socket_path, safe='')}"
        host = f"[{self.host}]" if ":" in (self.host or "") else self.host
        return f"http://{host}:{self.port}"


def _socket_endpoint(path: str) -> AdminEndpoint:
    if not path.startswith("/") or "/../" in f"{path}/" or "\0" in path:
        raise AdminEndpointError("ADMIN_API_URL_INVALID", "admin socket path must be absolute")
    return AdminEndpoint(socket_path=path)


def parse(address: str) -> AdminEndpoint:
    """Accept `unix//path`, `http+unix://<quoted path>`, or a loopback HTTP URL."""
    if address.startswith("unix/"):
        return _socket_endpoint(address[len("unix/"):])
    parsed = urllib.parse.urlsplit(address)
    if parsed.scheme == UNIX_SCHEME:
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise AdminEndpointError("ADMIN_API_URL_INVALID", "admin socket URL must not carry a path")
        return _socket_endpoint(urllib.parse.unquote(parsed.netloc))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AdminEndpointError("ADMIN_API_URL_INVALID", "invalid Caddy admin API URL")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise AdminEndpointError("ADMIN_API_URL_INVALID", "credentials are forbidden in Caddy admin API URL")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise AdminEndpointError("ADMIN_API_NOT_PRIVATE", "Caddy admin API must bind to loopback/private control plane")
    return AdminEndpoint(host=parsed.hostname, port=parsed.port or 2019)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def request(method: str, url: str, body: bytes | None = None, content_type: str | None = None,
            *, timeout: float = 5.0, limit: int = 2 * 1024 * 1024) -> tuple[int, bytes]:
    """Send one request to an `http+unix://` URL; never follows redirects or proxies."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != UNIX_SCHEME:
        raise AdminEndpointError("ADMIN_API_URL_INVALID", "not an admin socket URL")
    connection = _UnixHTTPConnection(urllib.parse.unquote(parsed.netloc), timeout)
    headers = {"Accept": "application/json", "Host": "localhost"}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        connection.request(method, (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else ""), body, headers)
        response = connection.getresponse()
        return response.status, response.read(limit + 1)
    finally:
        connection.close()
