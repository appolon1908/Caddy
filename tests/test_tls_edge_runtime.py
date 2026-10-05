"""The full production Caddyfile, booted natively with a local CA: HTTPS only, TLS 1.2+, unknown hosts refused."""
import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import synthetic_private_pki  # noqa: E402

HTTP_PORT, HTTPS_PORT = 19080, 19443


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    binary = os.environ.get("CADDY_BIN") or shutil.which("caddy")
    if not binary or not shutil.which("openssl") or os.name == "nt":
        pytest.skip("requires CADDY_BIN, openssl and a POSIX host")
    work = tmp_path_factory.mktemp("tls-edge")
    for name in ("snippets", "sites"):
        shutil.copytree(ROOT / name, work / name)
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    # Same configuration, test-only globals: no admin socket, a local CA, high ports.
    caddyfile = caddyfile.replace("\tadmin unix//run/caddy/admin.sock\n",
                                  f"\tadmin off\n\tlocal_certs\n\thttp_port {HTTP_PORT}\n\thttps_port {HTTPS_PORT}\n", 1)
    assert "local_certs" in caddyfile
    (work / "Caddyfile").write_text(caddyfile, encoding="utf-8")
    pki = synthetic_private_pki.generate(work / "pki")
    environment = dict(os.environ)
    for line in (ROOT / "config" / "runtime-values.example").read_text(encoding="utf-8").splitlines():
        if re.match(r"^CADDY_[A-Z0-9_]+=", line):
            name, value = line.split("=", 1)
            environment[name] = value
    environment.update(
        CADDY_EDITOR_ADMIN_CIDRS="192.0.2.0/24", CADDY_PUBLIC_BIND="127.0.0.1",
        CADDY_PRIVATE_METRICS_BIND="127.0.0.3", CADDY_PRIVATE_INGRESS_BIND="127.0.0.2",
        **{name: str(path) for name, path in pki.items()},
        CADDY_LOG_DIR=str(work / "logs"), XDG_DATA_HOME=str(work / "data"), XDG_CONFIG_HOME=str(work / "config"),
    )
    for name in ("CADDY_KLYROW_SOURCE_CIDRS", "CADDY_VICIDIAL_SOURCE_CIDRS", "CADDY_STAGING_EVENT_SOURCE_CIDRS"):
        environment.setdefault(name, "192.0.2.9/32")
    log = (work / "caddy.log").open("w")
    process = subprocess.Popen([binary, "run", "--config", str(work / "Caddyfile"), "--adapter", "caddyfile"],
                               cwd=work, env=environment, stdout=log, stderr=log)
    try:
        deadline = time.time() + 60
        while True:
            try:
                handshake("api.codestra.co")
                break
            except (OSError, ssl.SSLError):
                if process.poll() is not None or time.time() > deadline:
                    pytest.fail((work / "caddy.log").read_text())
                time.sleep(0.2)
        yield
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()


def handshake(server_name, version=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if version is not None:
        context.minimum_version = context.maximum_version = version
    with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            return tls.version()


def get(host, path, port=HTTP_PORT):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", path, headers={"Host": host})
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status, {k.lower(): v for k, v in response.getheaders()}


def tls_get(host, path):
    context = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := tls.recv(65536):
                data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    status = int(head[0].split()[1])
    return status, {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in head[1:] if ":" in line}


@pytest.mark.parametrize("host", ["api.codestra.co", "auth.codestra.co", "crm.codestra.agency"])
def test_plain_http_only_redirects_to_https(edge, host):
    status, headers = get(host, "/platform/v1/kernel/describe?x=1")
    assert status in {301, 308}
    # Caddy redirects to the default HTTPS port; production listens on 443.
    assert headers["location"] == f"https://{host}/platform/v1/kernel/describe?x=1"


def test_unknown_host_on_port_80_is_404(edge):
    assert get("evil.example", "/")[0] == 404
    assert get("127.0.0.1", "/platform/v1/kernel/describe")[0] == 404


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_12_and_13_are_served(edge, version):
    assert handshake("api.codestra.co", version) == {ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[version]


def test_tls_below_12_is_refused(edge):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pytest.skip("the local OpenSSL cannot offer TLS 1.1")
    with pytest.raises((ssl.SSLError, ConnectionError)):
        handshake("api.codestra.co", ssl.TLSVersion.TLSv1_1)


def test_unknown_sni_gets_no_certificate(edge):
    with pytest.raises((ssl.SSLError, ConnectionError)):
        handshake("evil.example")


def test_https_carries_hsts_and_keeps_private_paths_closed(edge):
    status, headers = tls_get("api.codestra.co", "/metrics")
    assert status == 404
    assert headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "server" not in headers
