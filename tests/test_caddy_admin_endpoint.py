"""The private admin endpoint: production socket by default, loopback for disposable tests."""
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import socketserver

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import caddy_admin_endpoint as endpoint  # noqa: E402
from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError  # noqa: E402


def test_production_default_is_the_private_socket():
    assert endpoint.ADMIN_ADDRESS == "unix//run/caddy/admin.sock"
    parsed = endpoint.parse(endpoint.ADMIN_ADDRESS)
    assert parsed.socket_path == "/run/caddy/admin.sock"
    assert parsed.caddy_address == endpoint.ADMIN_ADDRESS
    assert endpoint.parse(parsed.base_url) == parsed
    assert "admin unix//run/caddy/admin.sock" in (ROOT / "Caddyfile").read_text(encoding="utf-8")


@pytest.mark.parametrize("address, code", [
    ("unix/relative/admin.sock", "ADMIN_API_URL_INVALID"),
    ("unix//run/caddy/../../etc/admin.sock", "ADMIN_API_URL_INVALID"),
    ("http+unix://%2Frun%2Fcaddy%2Fadmin.sock/config/", "ADMIN_API_URL_INVALID"),
    ("http://0.0.0.0:2019", "ADMIN_API_NOT_PRIVATE"),
    ("http://caddy.internal:2019", "ADMIN_API_NOT_PRIVATE"),
    ("http://127.0.0.1:2019@evil.example", "ADMIN_API_URL_INVALID"),
    ("http://user:pw@127.0.0.1:2019", "ADMIN_API_URL_INVALID"),
])
def test_non_private_or_malformed_addresses_are_rejected(address, code):
    with pytest.raises(endpoint.AdminEndpointError) as caught:
        endpoint.parse(address)
    assert caught.value.code == code


def test_loopback_remains_available_for_disposable_instances():
    parsed = endpoint.parse("http://127.0.0.1:2999")
    assert (parsed.base_url, parsed.caddy_address) == ("http://127.0.0.1:2999", "127.0.0.1:2999")


@pytest.mark.skipif(not hasattr(socketserver, "UnixStreamServer"), reason="requires Unix domain sockets")
def test_runtime_reads_back_through_the_admin_socket():
    served = {"apps": {"http": {"servers": {}}}}
    seen = []

    class Admin(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            seen.append(self.path)
            body = json.dumps(served).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Server(socketserver.UnixStreamServer, HTTPServer):
        def server_bind(self):
            socketserver.UnixStreamServer.server_bind(self)
            self.server_name, self.server_port = "localhost", 0

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "admin.sock")
        server = Server(path, Admin)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            assert CaddyRuntime(f"unix/{path}").config() == served
            assert seen == ["/config/"]
        finally:
            server.shutdown()
            server.server_close()
        with pytest.raises(RuntimeReadbackError) as caught:
            CaddyRuntime(f"unix/{path}").config()
        assert caught.value.code == "ADMIN_API_UNAVAILABLE"
