#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import hashlib
import json
import urllib.error
import urllib.request
from typing import Any, Callable

import caddy_admin_endpoint
from caddy_admin_endpoint import ADMIN_ADDRESS, AdminEndpointError

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class RuntimeReadbackError(RuntimeError):
    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _validate_admin_base(base_url: str) -> str:
    try:
        endpoint = caddy_admin_endpoint.parse(base_url)
    except AdminEndpointError as exc:
        raise RuntimeReadbackError(exc.code, str(exc)) from exc
    return endpoint.base_url if endpoint.socket_path else base_url.rstrip("/")


def validate_configuration(config: dict[str, Any]) -> None:
    # /adapt parses JSON but does not provision or validate module configuration.
    # Validate locally before any /load request; a missing validator fails closed.
    with tempfile.TemporaryDirectory(prefix="caddy-validate-") as directory:
        path = os.path.join(directory, "candidate.json")
        with open(path, "wb") as handle:
            handle.write(canonical_json(config))
        try:
            result = subprocess.run([os.environ.get("CADDY_BIN", "caddy"), "validate", "--config", path], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeReadbackError("CONFIG_VALIDATION_UNAVAILABLE", "Caddy validation unavailable") from exc
        if result.returncode:
            raise RuntimeReadbackError("CONFIG_VALIDATION_FAILED", "Caddy configuration validation failed")


Transport = Callable[[str, str, bytes | None, str | None], tuple[int, bytes]]


def default_transport(method: str, url: str, body: bytes | None, content_type: str | None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        if url.startswith(caddy_admin_endpoint.UNIX_SCHEME + "://"):
            status, raw = caddy_admin_endpoint.request(method, url, body, content_type, limit=MAX_RESPONSE_BYTES)
        else:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        status = int(exc.code)
    except OSError as exc:
        raise RuntimeReadbackError("ADMIN_API_UNAVAILABLE", "Caddy admin API request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeReadbackError("ADMIN_API_RESPONSE_TOO_LARGE", "Caddy admin API response exceeded size limit")
    return status, raw




def extract_runtime_inventory(config: dict[str, Any]) -> dict[str, Any]:
    paths: set[str] = set()
    hosts: set[str] = set()
    upstreams: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            match = value.get("match")
            if isinstance(match, list):
                for matcher in match:
                    if not isinstance(matcher, dict):
                        continue
                    for path in matcher.get("path") or []:
                        if isinstance(path, str):
                            paths.add(path)
                    for host in matcher.get("host") or []:
                        if isinstance(host, str):
                            hosts.add(host)
            if value.get("handler") == "reverse_proxy":
                for upstream in value.get("upstreams") or []:
                    if isinstance(upstream, dict) and isinstance(upstream.get("dial"), str):
                        upstreams.add(upstream["dial"])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(config)
    return {
        "schema": "codestra.caddy.runtime-inventory.v1",
        "paths": sorted(paths),
        "hosts": sorted(hosts),
        "upstreams": sorted(upstreams),
    }


class CaddyRuntime:
    def __init__(self, base_url: str = ADMIN_ADDRESS, *, transport: Transport = default_transport) -> None:
        self.base_url = _validate_admin_base(base_url)
        self.transport = transport

    def config(self) -> dict[str, Any]:
        status, raw = self.transport("GET", f"{self.base_url}/config/", None, None)
        if status != 200:
            raise RuntimeReadbackError("ADMIN_API_READBACK_FAILED", f"Caddy admin API returned HTTP {status}", status)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeReadbackError("ADMIN_API_INVALID_JSON", "Caddy admin API returned malformed JSON", status) from exc
        if not isinstance(value, dict):
            raise RuntimeReadbackError("ADMIN_API_INVALID_CONFIG", "Caddy runtime config must be a JSON object", status)
        return value

    def inventory(self) -> dict[str, Any]:
        return extract_runtime_inventory(self.config())

    def status(self) -> dict[str, Any]:
        config = self.config()
        apps = config.get("apps") if isinstance(config.get("apps"), dict) else {}
        http_app = apps.get("http") if isinstance(apps, dict) and isinstance(apps.get("http"), dict) else {}
        servers = http_app.get("servers") if isinstance(http_app, dict) and isinstance(http_app.get("servers"), dict) else {}
        return {
            "schema": "codestra.caddy.runtime-status.v1",
            "admin_api": "AVAILABLE",
            "config_sha256": sha256_json(config),
            "server_count": len(servers),
        }

    def validate_json(self, config: dict[str, Any]) -> None:
        validate_configuration(config)
        body = canonical_json(config)
        status, raw = self.transport("POST", f"{self.base_url}/adapt", body, "application/json")
        if status not in {200, 204}:
            message = raw.decode("utf-8", "replace")[:512]
            raise RuntimeReadbackError("ADMIN_API_VALIDATE_FAILED", f"Caddy validation failed HTTP {status}: {message}", status)

    def load_json(self, config: dict[str, Any]) -> None:
        body = canonical_json(config)
        status, raw = self.transport("POST", f"{self.base_url}/load", body, "application/json")
        if status not in {200, 204}:
            message = raw.decode("utf-8", "replace")[:512]
            raise RuntimeReadbackError("ADMIN_API_LOAD_FAILED", f"Caddy load failed HTTP {status}: {message}", status)
