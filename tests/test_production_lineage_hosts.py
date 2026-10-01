"""Hosts carried forward from the production lineage (caddy-production-2489bf0).

Static checks bind the reviewed host inventory and its gates; the native test
runs the pinned Caddy binary on loopback against a synthetic upstream and a
synthetic oauth2-proxy stand-in. No real certificate, identity or provider is used.
"""
import http.client
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_observability_exposure as exposure  # noqa: E402

PRODUCTION_ADDRESSES = {
    "api.breero.com", "api.codestra.agency", "api.codestra.co", "auth.codestra.co", "automation.codestra.co",
    "crm.codestra.agency", "dialer.codestra.agency", "phone.codestra.agency", "monitoring.codestra.co",
    "n8n.codestra.agency", "n8n-staging.codestra.agency", "graf.codestra.media", "supe.codestra.media",
    "bao.codestra.media", "api.staging.internal.codestra.agency", "n8n.staging.internal.codestra.agency",
    "auth.staging.internal.codestra.agency", "odoo.staging.internal.codestra.agency", "auth-staging.codestra.co",
    "bridge-staging.codestra.agency", "middleware.internal.codestra.agency",
    "middleware-staging.internal.codestra.agency", "middleware-email-events.internal.codestra.agency:18080",
    ":2020",
}


def imported_addresses():
    source = re.sub(r"(?m)^\s*#.*$", "", exposure.load_root_caddy_sources())
    return set(exposure.extract_static_site_addresses(source))


def test_every_production_lineage_address_is_served_by_main():
    missing = PRODUCTION_ADDRESSES - imported_addresses()
    assert not missing, f"deploying main would drop production addresses: {sorted(missing)}"


def test_kyyow_hosts_stay_out_of_the_deployed_configuration():
    assert not any(address.endswith("kyyow.com") for address in imported_addresses())
    assert (ROOT / "sites-pending" / "kyyow.com.caddy").is_file()
    assert "sites-pending" not in (ROOT / "Caddyfile").read_text(encoding="utf-8")


def _validate_with(site_file, old, new):
    sources = exposure.load_root_caddy_sources()
    original = (ROOT / "sites" / site_file).read_text(encoding="utf-8") if site_file else (ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert old in original, old
    mutated = sources.replace(original, original.replace(old, new, 1))
    exposure.validate(
        exposure.load_contract(),
        exposure.SITE_PATH.read_text(encoding="utf-8"),
        mutated,
        exposure.RUNTIME_PATH.read_text(encoding="utf-8"),
        exposure.HEADERS_PATH.read_text(encoding="utf-8"),
    )


def test_reviewed_sources_pass_unmodified():
    _validate_with("api.breero.com.caddy", "api.breero.com {", "api.breero.com {")


@pytest.mark.parametrize(
    "site_file, old, new",
    [
        ("middleware-private.caddy", "mode require_and_verify", "mode request"),
        ("middleware-private.caddy", "\t\t\trespond 403\n", "\t\t\trespond 200\n"),
        ("klyrow-events.private.caddy", "bind {$CADDY_PRIVATE_INGRESS_BIND}", "bind 0.0.0.0"),
        ("n8n-legacy.codestra.agency.caddy", "@staff_private remote_ip private_ranges", "@staff_private remote_ip 0.0.0.0/0"),
        ("api.breero.com.caddy", "\timport public_boundary\n", "\n"),
        ("staging-internal.caddy", "\ttls internal\n", "\n"),
        ("crm.codestra.agency.caddy", "crm.codestra.agency {", "crm.codestra.agency, unreviewed.codestra.agency {"),
        (None, "bind {$CADDY_PRIVATE_METRICS_BIND}", "bind 0.0.0.0"),
    ],
)
def test_weakened_gates_are_rejected(site_file, old, new):
    with pytest.raises(exposure.ExposureError):
        _validate_with(site_file, old, new)


def test_legacy_agency_host_never_widens_the_canonical_host():
    canonical = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
    legacy = (ROOT / "sites" / "api.codestra.agency.caddy").read_text(encoding="utf-8")

    def matcher(source, name):
        return re.search(rf"(?m)^\s*@{name} path (.+)$", source).group(1).split()

    canonical_kong = matcher(canonical, "kong")
    for prefix in matcher(legacy, "kong"):
        assert any(prefix == c or (c.endswith("*") and prefix.startswith(c[:-1])) for c in canonical_kong), prefix
    assert matcher(legacy, "pending_contract") == matcher(canonical, "pending_contract")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_native_production_lineage_behavior(tmp_path, monkeypatch):
    binary = os.environ.get("CADDY_BIN") or shutil.which("caddy")
    if not binary:
        pytest.skip("requires pinned CADDY_BIN")
    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _reply(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/oauth2/auth":
                self.send_response(200)
                self.send_header("X-Auth-Request-User", "TEST_SYN_GATEWAY_USER")
                self.send_header("X-Auth-Request-Access-Token", "TEST_SYN_GATEWAY_TOKEN")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            seen.append({"path": self.path, "method": self.command,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _reply

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    target = f"127.0.0.1:{upstream.server_port}"
    for name in re.findall(r"^([A-Z0-9_]+)=", (ROOT / "config/runtime-values.example").read_text(), re.M):
        if name.endswith("_UPSTREAM"):
            monkeypatch.setenv(name, target)
    monkeypatch.setenv("CADDY_PRIVATE_INGRESS_BIND", "127.0.0.2")
    monkeypatch.setenv("CADDY_VICIDIAL_SOURCE_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("CADDY_KLYROW_SOURCE_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("CADDY_STAGING_EVENT_SOURCE_CIDRS", "192.0.2.9/32")
    monkeypatch.setenv("CADDY_EDITOR_ADMIN_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("CADDY_N8N_EDITOR_MAX_REQUEST_BODY", "16777216")
    monkeypatch.setenv("CADDY_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    port = _free_port()

    shutil.copytree(ROOT / "snippets", tmp_path / "snippets")
    (tmp_path / "sites").mkdir()
    for name in ("api.breero.com.caddy", "api.codestra.agency.caddy", "agent-desktop.codestra.agency.caddy",
                 "monitoring.codestra.co.caddy", "middleware-private.caddy", "klyrow-events.private.caddy",
                 "staging-internal.caddy", "automation.codestra.co.caddy"):
        source = (ROOT / "sites" / name).read_text(encoding="utf-8")
        # Loopback HTTP stand-in: drop certificate material and serve each
        # reviewed address as a plain-HTTP virtual host on one test port.
        source = re.sub(r"(?ms)^\ttls \S+ \S+ \{.*?^\t\}\n", "", source)
        source = re.sub(r"(?m)^\ttls internal\n", "", source)
        # One listener: private binds are enforced by the static validator, the
        # source-CIDR gates are what this native test exercises.
        source = re.sub(r"(?m)^\tbind \S+\n", "", source)
        source = re.sub(r"(?m)^(?:https://)?([a-z0-9.-]+\.[a-z]+)(?::\d+)? \{$",
                        rf"http://\1:{port} {{", source)
        assert re.findall(r"(?m)^\S+ \{$", source) == re.findall(rf"(?m)^http://\S+:{port} \{{$", source)
        (tmp_path / "sites" / name).write_text(source, encoding="utf-8")
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("{\n\tadmin off\n\tauto_https off\n\tpersist_config off\n\torder route before handle\n}\n"
                         "import snippets/*.caddy\nimport sites/*.caddy\n", encoding="utf-8")
    log = (tmp_path / "process.log").open("w")
    process = subprocess.Popen([binary, "run", "--config", str(caddyfile), "--adapter", "caddyfile"],
                               cwd=tmp_path, stdout=log, stderr=log)

    def request(host, path, method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(method, path, headers={"Host": host, **(headers or {})})
        response = conn.getresponse()
        result = response.status, {k.lower(): v for k, v in response.getheaders()}
        response.read()
        conn.close()
        return result

    def last():
        return seen[-1]

    try:
        for _ in range(200):
            try:
                request("api.breero.com", "/api/v1/health")
                break
            except OSError:
                if process.poll() is not None:
                    pytest.fail((tmp_path / "process.log").read_text())
                time.sleep(0.05)
        else:
            pytest.fail("native Caddy did not start")

        spoof = {"X-User-ID": "forged", "X-Admin": "yes", "X-Auth-Request-User": "forged",
                 "X-Codestra-Gateway-Secret": "forged", "Forwarded": "for=8.8.8.8",
                 "X-Codestra-Required-Scope": "forged", "X-Codestra-Expected-Azp": "forged",
                 "X-Codestra-Contract-Operation": "forged"}
        kong_internal = {"x-codestra-required-scope", "x-codestra-expected-azp", "x-codestra-contract-operation"}

        # Breero: Kong-bound API with identity stripping and fail-closed defaults.
        assert request("api.breero.com", "/api/v1/orders", headers=spoof)[0] == 200
        assert not {"x-user-id", "x-admin", "x-auth-request-user", "x-codestra-gateway-secret", "forwarded"} & set(last()["headers"])
        assert not kong_internal & set(last()["headers"])
        assert "server" not in request("api.breero.com", "/api/v1/orders")[1]
        for path in ("/other", "/metrics", "/internal/v1/database/health"):
            assert request("api.breero.com", path)[0] == 404

        # Legacy agency host: canonical Host for Kong, pending contracts denied, no widening.
        assert request("api.codestra.agency", "/api/v1/events/delivery")[0] == 200
        assert last()["headers"]["host"] == "api.codestra.co"
        for path in ("/api/v1/events/telnexa", "/api/v1/control/unlisted", "/platform/v1/kernel/describe"):
            assert request("api.codestra.agency", path)[0] == 404

        # Dialer: forward_auth identity reaches the UI; client copies never do.
        assert request("dialer.codestra.agency", "/", headers=spoof)[0] == 200
        assert last()["headers"]["x-auth-request-user"] == "TEST_SYN_GATEWAY_USER"
        assert request("dialer.codestra.agency", "/realtime-api/stream",
                       headers={"X-Auth-Request-Access-Token": "TEST_SYN_CLIENT_TOKEN"})[0] == 200
        assert last()["path"] == "/stream"
        assert last()["headers"]["authorization"] == "Bearer TEST_SYN_GATEWAY_TOKEN"

        # Phone: no site gate, so a spoofed gateway identity is simply removed.
        status, headers = request("phone.codestra.agency", "/", headers=spoof)
        assert status == 200 and "x-auth-request-user" not in last()["headers"]
        assert headers["permissions-policy"] == "camera=(), geolocation=(), microphone=(self)"
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert request("api.breero.com", "/api/v1/x")[1]["x-frame-options"] == "DENY"

        # Automation editor: n8n test hooks and owner bootstrap never reach Kong.
        for path in ("/rest/owner/setup", "/webhook-test/x", "/form-test/x", "/rest/owner/dismiss-banner"):
            assert request("automation.codestra.co", path, "POST")[0] == 404
        assert request("automation.codestra.co", "/rest/workflows", headers=spoof)[0] == 200
        assert not kong_internal & set(last()["headers"])

        # Monitoring receiver: only the receiver API is public.
        assert request("monitoring.codestra.co", "/api/v1/alerts/fire", "POST")[0] == 200
        assert request("monitoring.codestra.co", "/grafana")[0] == 404

        # Private Middleware ingress: one method+path from one CIDR, else 403.
        assert request("middleware.internal.codestra.agency", "/api/v1/events/vicidial", "POST")[0] == 200
        assert request("middleware.internal.codestra.agency", "/api/v1/events/vicidial")[0] == 403
        assert request("middleware.internal.codestra.agency", "/api/v1/other", "POST")[0] == 403
        assert request("middleware-staging.internal.codestra.agency", "/api/v1/staging/events/vicidial", "POST")[0] == 403

        # Klyrow: its /internal route stays reachable here, identity is stripped, all else 403.
        assert request("middleware-email-events.internal.codestra.agency", "/internal/provider-events/klyrow",
                       "POST", headers=spoof)[0] == 200
        assert "x-user-id" not in last()["headers"]
        assert request("middleware-email-events.internal.codestra.agency", "/internal/provider-events/klyrow")[0] == 403

        # Staging bridge keeps the production callback private.
        assert request("bridge-staging.codestra.agency", "/api/v1/events/vicidial", "POST")[0] == 404
        assert request("bridge-staging.codestra.agency", "/api/v1/other")[0] == 200
        assert request("n8n.staging.internal.codestra.agency", "/.well-known/codestra-service")[0] == 200
    finally:
        process.terminate()
        process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        log.close()

    logs = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "logs").glob("*.log"))
    assert "TEST_SYN_GATEWAY_TOKEN" not in logs
    assert "TEST_SYN_CLIENT_TOKEN" not in logs
