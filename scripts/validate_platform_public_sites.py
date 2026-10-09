#!/usr/bin/env python3
"""Validate canonical Codestra/Klyrow public and protected operator URLs."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "platform-public-sites.v1.json"
SITE_PATH = ROOT / "sites" / "codestra.platform-public.caddy"
RUNTIME_PATH = ROOT / "config" / "runtime-values.example"

EXPECTED = {
    "codestra.co": ("proxy", "CADDY_CODESTRA_WEB_UPSTREAM"),
    "www.codestra.co": ("redirect", None),
    "crm.codestra.agency": ("proxy", "CADDY_ODOO_CRM_UPSTREAM"),
    "app.klyrow.com": ("proxy", "CADDY_KLYROW_UPSTREAM"),
    "klyrow.com": ("proxy-with-browser-redirect", "CADDY_KLYROW_UPSTREAM"),
    "www.klyrow.com": ("redirect", None),
    "grafana.codestra.co": ("proxy", "CADDY_GRAFANA_UPSTREAM"),
    "analytics.codestra.co": ("proxy", "CADDY_SUPERSET_UPSTREAM"),
    "auth.codestra.co": ("proxy", "CADDY_KEYCLOAK_UPSTREAM"),
    "monitoring.codestra.co": ("redirect", None),
    "prometheus.codestra.co": ("proxy", "CADDY_PROMETHEUS_UPSTREAM"),
    "alerts.codestra.co": ("proxy", "CADDY_ALERTMANAGER_UPSTREAM"),
}
PROTECTED = {"prometheus.codestra.co", "alerts.codestra.co"}
REDIRECTS = {
    "www.codestra.co": "https://codestra.co{uri}",
    "www.klyrow.com": "https://klyrow.com{uri}",
    "monitoring.codestra.co": "https://grafana.codestra.co{uri}",
}
REQUIRED_PROXY_TOKENS = (
    "import security_headers",
    "import edge_observability",
    "import public_boundary",
    "header_up Host {host}",
    "header_up X-Real-IP {remote_host}",
    "header_up X-Forwarded-Host {host}",
    "header_up X-Forwarded-Proto https",
    "dial_timeout 5s",
)


class PublicSiteError(ValueError):
    pass


def block(source: str, host: str) -> str:
    match = re.search(rf"(?m)^{re.escape(host)}\s*\{{", source)
    if not match:
        raise PublicSiteError(f"missing site block: {host}")
    depth = 0
    for i in range(match.end() - 1, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():i+1]
    raise PublicSiteError(f"unterminated site block: {host}")


def load() -> tuple[dict, str, str]:
    return (
        json.loads(CONTRACT_PATH.read_text(encoding="utf-8")),
        SITE_PATH.read_text(encoding="utf-8"),
        RUNTIME_PATH.read_text(encoding="utf-8"),
    )


def validate(contract: dict, source: str, runtime: str) -> None:
    if contract.get("schema") != "codestra.platform-public-sites.v1":
        raise PublicSiteError("unsupported platform public-sites schema")
    routes = contract.get("routes")
    if not isinstance(routes, list) or [r.get("host") for r in routes] != list(EXPECTED):
        raise PublicSiteError("route inventory/order mismatch")

    if re.search(r"\b(?:10|127|172|192\.168)\.\d+\.\d+\.\d+\b", source):
        raise PublicSiteError("live/private IP literal must not appear in public site source")
    if re.search(r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}", source):
        raise PublicSiteError("credential hash must be supplied through environment, not committed")

    route_map = {r["host"]: r for r in routes}
    for host, (kind, env_name) in EXPECTED.items():
        item = route_map[host]
        if item.get("kind") != kind:
            raise PublicSiteError(f"{host}: kind mismatch")
        b = block(source, host)
        if kind == "redirect":
            location = REDIRECTS[host]
            if f"redir {location}" not in b:
                raise PublicSiteError(f"{host}: redirect mismatch")
            if "reverse_proxy" in b:
                raise PublicSiteError(f"{host}: redirect host must not proxy")
            continue
        if item.get("upstreamEnvironmentVariable") != env_name:
            raise PublicSiteError(f"{host}: upstream contract mismatch")
        if any(token not in b for token in REQUIRED_PROXY_TOKENS):
            raise PublicSiteError(f"{host}: proxy security/forwarding control missing")
        if "{$" + env_name + "}" not in b:
            raise PublicSiteError(f"{host}: exact upstream environment placeholder missing")
        if host in PROTECTED:
            if "basic_auth" not in b or "codestra-admin {$CADDY_MONITORING_ADMIN_HASH}" not in b:
                raise PublicSiteError(f"{host}: edge authentication missing")
        elif "CADDY_MONITORING_ADMIN_HASH" in b:
            raise PublicSiteError(f"{host}: monitoring credential must not bleed into unrelated route")

    crm = block(source, "crm.codestra.agency")
    if "@database_admin path /web/database /web/database/*" not in crm or "respond @database_admin 403" not in crm:
        raise PublicSiteError("CRM database-manager public denial missing")

    klyrow = block(source, "klyrow.com")
    if "@browser path / /login /signup" not in klyrow or "redir @browser https://app.klyrow.com{uri} 302" not in klyrow:
        raise PublicSiteError("Klyrow canonical browser redirect missing")

    values = {}
    for line in runtime.splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
    for _, env_name in EXPECTED.values():
        if env_name and not values.get(env_name, "").startswith("127.0.0.1:"):
            raise PublicSiteError(f"{env_name}: validation reference must remain loopback-only")
    if values.get("CADDY_MONITORING_ADMIN_HASH") != "REPLACE_WITH_BCRYPT_HASH_AT_DEPLOYMENT":
        raise PublicSiteError("monitoring admin hash example must remain an explicit non-secret placeholder")

    private = set(contract.get("privateOnlyServices") or ())
    required_private = {"loki","tempo","alloy","opentelemetry","node-exporter","cadvisor","postgres-exporter","redis-exporter","blackbox-exporter"}
    if private != required_private:
        raise PublicSiteError("private-only telemetry inventory mismatch")


def main() -> None:
    contract, source, runtime = load()
    validate(contract, source, runtime)
    print("CADDY_PLATFORM_PUBLIC_SITES=PASS")
    print(f"CADDY_PLATFORM_PUBLIC_HOSTS={len(EXPECTED)}")
    print("CADDY_PLATFORM_PRIVATE_TELEMETRY=PASS")


if __name__ == "__main__":
    main()
