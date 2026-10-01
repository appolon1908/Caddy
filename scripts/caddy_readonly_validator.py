#!/usr/bin/env python3
"""Fixed-target, read-only production Caddy validator.

This program accepts no arguments and never emits raw Caddy configuration.
Installation and sudo/forced-command wiring are deliberately outside this
source change and require the protected deployment authority.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

CADDY = "/usr/bin/caddy"
SYSTEMCTL = "/usr/bin/systemctl"
CONFIG = Path("/etc/caddy/Caddyfile")
CONFIG_ROOT = Path("/etc/caddy")
SAFE_DIAL = re.compile(r"^(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$")
REQUIRED_REDACTIONS = (
    "request>headers>Authorization delete",
    "request>headers>Apikey delete",
    "request>headers>X-Api-Key delete",
    "delete apikey",
)
# Minimum set that must always be present. Every other `{$NAME}` placeholder
# referenced by the canonical source is required too: Caddy adapts an unset
# placeholder to an empty value, so a missing upstream variable still passes
# `caddy validate` while leaving a reverse_proxy with no upstream at all.
RUNTIME_VARIABLES = {
    "CADDY_KONG_UPSTREAM",
    "CADDY_REALTIME_UPSTREAM",
    "CADDY_EDITOR_ADMIN_CIDRS",
    "CADDY_N8N_EDITOR_HOST",
    "CADDY_N8N_OAUTH2_PROXY_UPSTREAM",
    "CADDY_N8N_EDITOR_MAX_REQUEST_BODY",
}
PLACEHOLDER = re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)(:[^}]*)?\}")


class ValidationError(RuntimeError):
    pass


def run_fixed(command: list[str], environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", **(environment or {})},
    )
    if result.returncode != 0:
        raise ValidationError(f"fixed command failed: {command[1]}")
    return result.stdout


def canonical_source() -> tuple[str, str]:
    paths = [CONFIG]
    for pattern in ("sites/*.caddy", "snippets/*.caddy"):
        paths.extend(sorted(CONFIG_ROOT.glob(pattern)))
    if any(not path.is_file() for path in paths):
        raise ValidationError("canonical Caddy source is incomplete")
    payload = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    return payload, hashlib.sha256(payload.encode()).hexdigest()


def require_redaction(source: str) -> None:
    missing = [token for token in REQUIRED_REDACTIONS if token not in source]
    if missing:
        raise ValidationError("credential redaction policy is incomplete")


def required_runtime_variables(source: str) -> set[str]:
    """Return every variable the source needs: the fixed floor plus each
    `{$NAME}` placeholder that has no `{$NAME:default}` fallback."""
    referenced = {name for name, default in PLACEHOLDER.findall(source) if not default}
    return RUNTIME_VARIABLES | referenced


def runtime_environment(required: set[str]) -> dict[str, str]:
    pid = run_fixed(
        [SYSTEMCTL, "show", "--property", "MainPID", "--value", "caddy.service"]
    ).strip()
    if not pid.isdigit() or pid == "0":
        raise ValidationError("caddy.service has no running process")
    entries = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    selected: dict[str, str] = {}
    for entry in entries:
        if b"=" not in entry:
            continue
        raw_name, raw_value = entry.split(b"=", 1)
        name = raw_name.decode("ascii", errors="strict")
        if name in required:
            selected[name] = raw_value.decode("utf-8", errors="strict")
    if set(selected) != required or any(not value for value in selected.values()):
        raise ValidationError("required Caddy runtime variables are unavailable")
    return selected


def require_proxy_upstreams(adapted: dict[str, Any]) -> None:
    """Every adapted reverse_proxy handler must dial at least one upstream."""

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("handler") == "reverse_proxy":
                upstreams = value.get("upstreams") or []
                if not upstreams or any(not (u or {}).get("dial") for u in upstreams):
                    raise ValidationError("adapted reverse_proxy has no upstream")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(adapted)


def require_transport_security(adapted: dict[str, Any]) -> None:
    """Reject public administration and explicit weakening of Caddy TLS defaults."""
    if (adapted.get("admin") or {}).get("listen") != "127.0.0.1:2019":
        raise ValidationError("admin listener is not fixed loopback")
    servers = (((adapted.get("apps") or {}).get("http") or {}).get("servers") or {})
    if not servers:
        raise ValidationError("HTTP servers are missing")
    for server in servers.values():
        automatic = server.get("automatic_https") or {}
        if automatic.get("disable") or automatic.get("disable_redirects"):
            raise ValidationError("automatic HTTPS or redirects disabled")
        for policy in server.get("tls_connection_policies") or []:
            if policy.get("protocol_min", "tls1.2") not in {"tls1.2", "tls1.3"}:
                raise ValidationError("TLS protocol floor is unsafe")

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("insecure_skip_verify"):
                raise ValidationError("upstream TLS verification disabled")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(adapted)


def active_configuration() -> dict[str, Any]:
    """Read only the fixed loopback admin endpoint; never redirect or use proxies."""
    connection = http.client.HTTPConnection("127.0.0.1", 2019, timeout=5)
    try:
        connection.request("GET", "/config/")
        response = connection.getresponse()
        if response.status != 200:
            raise ValidationError("active configuration readback failed")
        payload = response.read(4 * 1024 * 1024 + 1)
        if len(payload) > 4 * 1024 * 1024:
            raise ValidationError("active configuration exceeds readback limit")
        value = json.loads(payload)
        if not isinstance(value, dict) or not value:
            raise ValidationError("active configuration is not an object")
        return value
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise ValidationError("active configuration readback failed") from exc
    finally:
        connection.close()


def require_served_config(desired: dict[str, Any], active: Any) -> str:
    """Fail closed on drift; hash canonical JSON without disclosing either config."""
    if not isinstance(active, dict) or not active or json.dumps(active, sort_keys=True) != json.dumps(desired, sort_keys=True):
        raise ValidationError("served configuration differs from validated disk configuration")
    return hashlib.sha256(json.dumps(active, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_adapted_redaction(adapted: dict[str, Any]) -> None:
    logs = ((adapted.get("logging") or {}).get("logs") or {})
    access_logs = [value for name, value in logs.items() if name != "default"]
    if not access_logs:
        raise ValidationError("adapted access logs are missing")
    required_headers = {
        "request>headers>Authorization",
        "request>headers>Apikey",
        "request>headers>X-Api-Key",
        "request>headers>Proxy-Authorization",
        "request>headers>Cookie",
        "resp_headers>Set-Cookie",
    }
    for log in access_logs:
        fields = ((log.get("encoder") or {}).get("fields") or {})
        if any((fields.get(name) or {}).get("filter") != "delete" for name in required_headers):
            raise ValidationError("adapted access log header redaction is incomplete")
        uri = fields.get("request>uri") or {}
        actions = uri.get("actions") or []
        required_queries = {"apikey", "api_key", "access_token", "refresh_token", "id_token",
                            "client_secret", "password", "secret", "token"}
        deleted = {action.get("parameter") for action in actions if action.get("type") == "delete"}
        if uri.get("filter") != "query" or not required_queries <= deleted:
            raise ValidationError("adapted access log query redaction is incomplete")


def require_access_log_coverage(adapted: dict[str, Any]) -> None:
    """Every served host must write to a dedicated, redacted access log.

    Redaction is enforced per log, so a host with no log mapping would escape
    it: Caddy writes that host's access entries to the unfiltered default
    logger instead. Each host matched by a server route must map to at least
    one access log, and each mapped log must exist and include that logger.
    """
    logs = ((adapted.get("logging") or {}).get("logs") or {})
    servers = (((adapted.get("apps") or {}).get("http") or {}).get("servers") or {})
    covered = 0
    for server in servers.values():
        hosts = {
            host
            for route in server.get("routes") or []
            for matcher in route.get("match") or []
            for host in matcher.get("host") or []
        }
        if not hosts:
            continue
        logger_names = ((server.get("logs") or {}).get("logger_names") or {})
        for host in hosts:
            names = logger_names.get(host) or []
            if isinstance(names, str):
                names = [names]
            if not names:
                raise ValidationError("served host has no access log")
            for name in names:
                log = logs.get(name)
                if name == "default" or not log or f"http.log.access.{name}" not in (log.get("include") or []):
                    raise ValidationError("served host access log is not configured")
            covered += 1
    if not covered:
        raise ValidationError("adapted access logs are missing")


def sanitized_summary(adapted: dict[str, Any]) -> dict[str, Any]:
    hosts: set[str] = set()
    paths: set[str] = set()
    upstreams: set[str] = set()
    header_names: set[str] = set()
    duration_fields: set[str] = set()
    mtls_present = False

    def visit(value: Any, key: str = "") -> None:
        nonlocal mtls_present
        if isinstance(value, dict):
            for child_key, child in value.items():
                lowered = child_key.lower()
                if lowered in {"client_authentication", "client_certificate", "client_ca_pool"}:
                    mtls_present = True
                if lowered in {"headers", "set", "add", "delete"} and isinstance(child, dict):
                    header_names.update(str(name) for name in child)
                if any(part in lowered for part in ("timeout", "keepalive", "duration")):
                    duration_fields.add(child_key)
                visit(child, child_key)
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str):
            if key == "host" and re.fullmatch(r"[A-Za-z0-9.*_-]+", value):
                hosts.add(value)
            elif key == "path" and value.startswith("/") and "?" not in value:
                paths.add(value)
            elif key == "dial":
                if not SAFE_DIAL.fullmatch(value):
                    raise ValidationError("unsafe upstream representation")
                upstreams.add(value)

    visit(adapted)
    return {
        "hosts": sorted(hosts),
        "paths": sorted(paths),
        "upstreams": sorted(upstreams),
        "header_names": sorted(header_names),
        "duration_fields": sorted(duration_fields),
        "mtls_policy_present": mtls_present,
        "websocket_transport_supported": bool(upstreams),
    }


def main() -> int:
    if len(sys.argv) != 1:
        raise ValidationError("arguments are not accepted")
    source, checksum = canonical_source()
    require_redaction(source)
    environment = runtime_environment(required_runtime_variables(source))
    run_fixed([CADDY, "validate", "--config", str(CONFIG)], environment)
    if run_fixed([SYSTEMCTL, "is-active", "caddy.service"]).strip() != "active":
        raise ValidationError("caddy.service is not active")
    adapted = json.loads(
        run_fixed([CADDY, "adapt", "--config", str(CONFIG), "--pretty"], environment)
    )
    require_adapted_redaction(adapted)
    require_access_log_coverage(adapted)
    require_proxy_upstreams(adapted)
    require_transport_security(adapted)
    active = active_configuration()
    active_digest = require_served_config(adapted, active)
    evidence = {
        "served_config_sha256": active_digest,
        "served_config_matches_disk": True,
        "schema": "codestra.caddy-readonly-validation.v1",
        "config_sha256": checksum,
        "config_validation": "PASS",
        "service_active": True,
        "credential_redaction": "PASS",
        "summary": sanitized_summary(adapted),
    }
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
        print(f"CADDY_READONLY_VALIDATION=FAIL:{type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2)
