#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUTHORITY = ROOT / "config" / "caddy-route-authority.v1.json"
DEFAULT_OUTPUT = ROOT / "generated" / "pas144-edge.generated.caddy"
DEFAULT_INVENTORY = ROOT / "generated" / "pas144-route-inventory.json"

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ANY"}
ALLOWED_VISIBILITY = {"public", "private"}
FORBIDDEN_IDENTITY_HEADERS = (
    "X-User-ID",
    "X-Username",
    "X-Email",
    "X-Roles",
    "X-Scopes",
    "X-Authenticated-UserID",
    "X-Authenticated-User",
    "X-Authenticated-Client",
    "X-Authenticated-Subject",
    "X-Authenticated-Tenant",
    "X-Authenticated-Campaign",
    "X-Authenticated-Role",
    "X-Authenticated-Email",
    "X-Codestra-Tenant",
    "X-Codestra-Scopes",
    "X-Codestra-Gateway-Secret",
    "X-Internal-Service",
    "X-Admin",
    "X-Consumer-ID",
    "X-Consumer-Username",
    "X-Consumer-Custom-ID",
    "X-Credential-Identifier",
    "X-Anonymous-Consumer",
)


class RouteAuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class Route:
    route_id: str
    host: str
    path: str
    methods: tuple[str, ...]
    visibility: str
    upstream_service: str
    upstream_ref: str
    auth_mode: str
    body_limit: str
    rate_limit_profile: str
    websocket: bool
    sse: bool
    security_header_profile: str
    timeout_profile: str
    owner: str
    environment: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_authority(path: Path = DEFAULT_AUTHORITY) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RouteAuthorityError(f"authority_load_failed:{exc}") from exc
    validate_authority(payload)
    return payload


def _canonical_path(raw: dict[str, Any]) -> str:
    path = raw.get("path")
    prefix = raw.get("path_prefix")
    if bool(path) == bool(prefix):
        raise RouteAuthorityError(f"{raw.get('route_id','unknown')}:exactly_one_of_path_or_path_prefix")
    if path:
        value = str(path)
    else:
        value = str(prefix).rstrip("/") + "*"
    if not value.startswith("/"):
        raise RouteAuthorityError(f"{raw.get('route_id','unknown')}:path_must_start_slash")
    return value


def normalize_routes(authority: dict[str, Any]) -> tuple[Route, ...]:
    routes: list[Route] = []
    for raw in authority.get("routes", []):
        methods = tuple(sorted({str(x).upper() for x in raw.get("methods", [])}))
        routes.append(
            Route(
                route_id=str(raw.get("route_id", "")),
                host=str(raw.get("host", "")),
                path=_canonical_path(raw),
                methods=methods,
                visibility=str(raw.get("visibility", "")),
                upstream_service=str(raw.get("upstream_service", "")),
                upstream_ref=str(raw.get("upstream_ref", "")),
                auth_mode=str(raw.get("auth_mode", "")),
                body_limit=str(raw.get("body_limit", "")),
                rate_limit_profile=str(raw.get("rate_limit_profile", "")),
                websocket=bool(raw.get("websocket", False)),
                sse=bool(raw.get("sse", False)),
                security_header_profile=str(raw.get("security_header_profile", "")),
                timeout_profile=str(raw.get("timeout_profile", "")),
                owner=str(raw.get("owner", "")),
                environment=str(raw.get("environment", "")),
            )
        )
    return tuple(sorted(routes, key=lambda r: (r.host, r.path, r.route_id)))


def validate_authority(authority: dict[str, Any]) -> None:
    if authority.get("schema") != "codestra.caddy.route-authority.v1":
        raise RouteAuthorityError("unsupported_schema")
    if authority.get("version") != 1:
        raise RouteAuthorityError("unsupported_version")
    canonical = authority.get("canonical_api_upstream") or {}
    if canonical.get("reference") != "CADDY_KONG_UPSTREAM":
        raise RouteAuthorityError("canonical_api_upstream_must_be_kong")
    if canonical.get("canonical_middleware_port") != 8095:
        raise RouteAuthorityError("canonical_middleware_port_must_be_8095")

    forbidden = tuple(str(x).lower() for x in authority.get("forbidden_public_upstreams", []))
    private_prefixes = tuple(str(x) for x in authority.get("private_path_prefixes", []))
    if not {"/metrics", "/internal"} <= set(private_prefixes):
        raise RouteAuthorityError("required_private_prefix_missing")

    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    profiles = authority.get("profiles") or {}
    security_profiles = (profiles.get("security_headers") or {}).keys()
    timeout_profiles = (profiles.get("timeouts") or {}).keys()

    for route in normalize_routes(authority):
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", route.route_id):
            raise RouteAuthorityError(f"{route.route_id or 'unknown'}:invalid_route_id")
        if route.route_id in seen_ids:
            raise RouteAuthorityError(f"{route.route_id}:duplicate_route_id")
        seen_ids.add(route.route_id)
        if not route.host or "." not in route.host:
            raise RouteAuthorityError(f"{route.route_id}:invalid_host")
        if route.visibility not in ALLOWED_VISIBILITY:
            raise RouteAuthorityError(f"{route.route_id}:invalid_visibility")
        if not route.methods or any(x not in ALLOWED_METHODS for x in route.methods):
            raise RouteAuthorityError(f"{route.route_id}:invalid_methods")
        if route.security_header_profile not in security_profiles:
            raise RouteAuthorityError(f"{route.route_id}:unknown_security_header_profile")
        if route.timeout_profile not in timeout_profiles:
            raise RouteAuthorityError(f"{route.route_id}:unknown_timeout_profile")
        for method in route.methods:
            key = (route.host, route.path, method)
            if key in seen_keys:
                raise RouteAuthorityError(f"{route.route_id}:duplicate_route:{key}")
            seen_keys.add(key)

        is_private_namespace = any(
            route.path == prefix or route.path.startswith(prefix + "/") or route.path.startswith(prefix + "*")
            for prefix in private_prefixes
        )
        if route.visibility == "public":
            if is_private_namespace:
                raise RouteAuthorityError(f"{route.route_id}:private_namespace_public")
            if route.upstream_ref != "CADDY_KONG_UPSTREAM" or route.upstream_service != "kong":
                raise RouteAuthorityError(f"{route.route_id}:public_route_must_use_kong")
            lowered = f"{route.upstream_ref} {route.upstream_service}".lower()
            if any(token in lowered for token in forbidden):
                raise RouteAuthorityError(f"{route.route_id}:forbidden_public_upstream")
            if route.websocket and route.sse:
                raise RouteAuthorityError(f"{route.route_id}:websocket_and_sse_mutually_exclusive")
        else:
            if route.upstream_ref != "NONE" or route.upstream_service != "none":
                raise RouteAuthorityError(f"{route.route_id}:private_route_must_not_have_public_upstream")


def _matcher_name(route_id: str) -> str:
    return "pas144_" + re.sub(r"[^a-zA-Z0-9_]", "_", route_id)


def _path_line(route: Route) -> str:
    return f"\t\tpath {route.path}"


def _method_line(route: Route) -> list[str]:
    if route.methods == ("ANY",):
        return []
    return ["\t\tmethod " + " ".join(route.methods)]


def _headers_block() -> list[str]:
    lines = [
        "\t\t\theader_up Host {host}",
        "\t\t\theader_up X-Real-IP {remote_host}",
    ]
    lines.extend(f"\t\t\theader_up -{name}" for name in FORBIDDEN_IDENTITY_HEADERS)
    return lines


def compile_caddy(authority: dict[str, Any]) -> str:
    validate_authority(authority)
    profiles = authority["profiles"]
    timeout_profiles = profiles["timeouts"]
    security_profiles = profiles["security_headers"]
    routes = normalize_routes(authority)

    lines = [
        "# Code generated by scripts/caddy_route_compiler.py; DO NOT EDIT.",
        "# Source: config/caddy-route-authority.v1.json",
        "",
        "(pas144_canonical_edge_policy) {",
    ]

    for route in routes:
        matcher = _matcher_name(route.route_id)
        lines.append(f"\t@{matcher} {{")
        lines.append(_path_line(route))
        lines.extend(_method_line(route))
        lines.append("\t}")
        lines.append(f"\thandle @{matcher} {{")
        if route.visibility == "private":
            lines.append("\t\trespond 404")
        else:
            if route.body_limit and route.body_limit != "0":
                lines.extend(["\t\trequest_body {", f"\t\t\tmax_size {route.body_limit}", "\t\t}"])
            for key, value in sorted(security_profiles[route.security_header_profile].items()):
                lines.append(f'\t\theader {key} "{value}"')
            timeout = timeout_profiles[route.timeout_profile]
            lines.append(f"\t\treverse_proxy {{$CADDY_KONG_UPSTREAM}} {{")
            lines.extend(_headers_block())
            lines.extend(
                [
                    "\t\t\ttransport http {",
                    f"\t\t\t\tdial_timeout {timeout['dial']}",
                    f"\t\t\t\tresponse_header_timeout {timeout['response_header']}",
                    "\t\t\t}",
                ]
            )
            lines.append("\t\t}")
        lines.append("\t}")
        lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def build_inventory(authority: dict[str, Any], generated: str) -> dict[str, Any]:
    routes = normalize_routes(authority)
    source_bytes = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "codestra.caddy.route-inventory.v1",
        "source_sha256": _sha256(source_bytes),
        "generated_sha256": _sha256(generated.encode()),
        "route_count": len(routes),
        "public_count": sum(1 for r in routes if r.visibility == "public"),
        "private_count": sum(1 for r in routes if r.visibility == "private"),
        "routes": [
            {
                "route_id": r.route_id,
                "host": r.host,
                "path": r.path,
                "methods": list(r.methods),
                "visibility": r.visibility,
                "upstream_ref": r.upstream_ref,
                "owner": r.owner,
            }
            for r in routes
        ],
    }


def compile_to_files(
    authority_path: Path = DEFAULT_AUTHORITY,
    output_path: Path = DEFAULT_OUTPUT,
    inventory_path: Path = DEFAULT_INVENTORY,
    *,
    check: bool = False,
) -> dict[str, Any]:
    authority = load_authority(authority_path)
    generated = compile_caddy(authority)
    inventory = build_inventory(authority, generated)
    inventory_text = json.dumps(inventory, indent=2, sort_keys=True) + "\n"

    if check:
        if not output_path.exists() or output_path.read_text(encoding="utf-8") != generated:
            raise RouteAuthorityError("generated_caddy_drift")
        if not inventory_path.exists() or inventory_path.read_text(encoding="utf-8") != inventory_text:
            raise RouteAuthorityError("generated_inventory_drift")
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(generated, encoding="utf-8")
        inventory_path.write_text(inventory_text, encoding="utf-8")
    return inventory


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile governed Caddy route authority.")
    parser.add_argument("--authority", type=Path, default=DEFAULT_AUTHORITY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        inventory = compile_to_files(args.authority, args.output, args.inventory, check=args.check)
    except RouteAuthorityError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **inventory}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
