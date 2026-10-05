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
DEFAULT_AUTHORITY = ROOT / "config" / "caddy-kong-contract.v1.json"
DEFAULT_OUTPUT = ROOT / "sites" / "api.codestra.co.caddy"
DEFAULT_INVENTORY = ROOT / "generated" / "caddy-route-inventory.json"

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ANY"}
ALLOWED_VISIBILITY = {"public", "private"}
HEADER_POLICY = json.loads((ROOT / "config" / "header-policy.v1.json").read_text(encoding="utf-8"))
# Client-asserted identity: deleted at the public boundary and again on every Kong handoff.
FORBIDDEN_IDENTITY_HEADERS = tuple(HEADER_POLICY["strip"]["identity"])


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
    if authority.get("schema") == "codestra.caddy-kong-edge.v1":
        validate_edge_authority(authority)
        return
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

    for headers in (profiles.get("security_headers") or {}).values():
        for name, value in headers.items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name) or not isinstance(value, str) or any(c in value for c in '\r\n"{}\\'):
                raise RouteAuthorityError("invalid_security_header")
    for timeout in (profiles.get("timeouts") or {}).values():
        if any(not re.fullmatch(r"[0-9]+(?:ms|s|m)", str(timeout.get(k, ""))) for k in ("dial", "response_header")):
            raise RouteAuthorityError("invalid_timeout")

    for route in normalize_routes(authority):
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", route.route_id):
            raise RouteAuthorityError(f"{route.route_id or 'unknown'}:invalid_route_id")
        if route.route_id in seen_ids:
            raise RouteAuthorityError(f"{route.route_id}:duplicate_route_id")
        seen_ids.add(route.route_id)
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", route.host) or "." not in route.host:
            raise RouteAuthorityError(f"{route.route_id}:invalid_host")
        if not re.fullmatch(r"/[A-Za-z0-9/._~%:@*+-]*", route.path):
            raise RouteAuthorityError(f"{route.route_id}:invalid_path")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*(?:KB|MB|GB)?)", route.body_limit):
            raise RouteAuthorityError(f"{route.route_id}:invalid_body_limit")
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
    if authority.get("schema") == "codestra.caddy-kong-edge.v1":
        return compile_edge_site(authority)
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
    if authority.get("schema") == "codestra.caddy-kong-edge.v1":
        return edge_inventory(authority, generated)
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
        output_path.write_text(generated, encoding="utf-8", newline="\n")
        inventory_path.write_text(inventory_text, encoding="utf-8", newline="\n")
    return inventory



START = "\t\t# BEGIN GENERATED MIDDLEWARE CONTRACT ROUTES"
END = "\t\t# END GENERATED MIDDLEWARE CONTRACT ROUTES"
PUBLIC_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
DELETED_IDENTITY_HEADERS = FORBIDDEN_IDENTITY_HEADERS

def route_regex(path: str) -> str:
    marker = "CODESTRAPARAMETER"
    marked = re.sub(r"\{[a-z_]+\}", marker, path)
    return re.escape(marked).replace(marker, PUBLIC_ID)


def proxy_lines(indent: str = "\t\t\t") -> list[str]:
    lines = [
        f"{indent}reverse_proxy {{$CADDY_KONG_UPSTREAM}} {{",
        f"{indent}\theader_up Host {{host}}",
        f"{indent}\theader_up X-Real-IP {{remote_host}}",
    ]
    lines.extend(f"{indent}\theader_up -{name}" for name in DELETED_IDENTITY_HEADERS)
    lines += [
        f"{indent}\ttransport http {{",
        f"{indent}\t\tdial_timeout 5s",
        f"{indent}\t\tresponse_header_timeout 30s",
        f"{indent}\t}}",
        f"{indent}}}",
    ]
    return lines


def route_block(routes: list[dict]) -> str:
    lines = [
        START,
        "\t\t# Generated from config/middleware-public-api-route-contract.v1.json.",
        "\t\t# Caddy selects exact method+path pairs; Kong owns authentication and policy.",
        "\t\t# Client identity headers are stripped here; auth/correlation/idempotency/trace pass through.",
    ]
    for method in sorted({row["method"] for row in routes}):
        selected = sorted(route_regex(row["path"]) for row in routes if row["method"] == method)
        expression = "^(" + "|".join(selected) + ")$"
        matcher = f"canonical_{method.lower()}"
        lines.extend(
            [
                f"\t\t@{matcher} {{",
                f"\t\t\tmethod {method}",
                f"\t\t\tpath_regexp {expression}",
                "\t\t}",
                f"\t\thandle @{matcher} {{",
                f"\t\t\tvars edge_route_id edge.canonical.{method.lower()}",
                *proxy_lines(),
                "\t\t}",
                "",
            ]
        )
    lines.append(END)
    return "\n".join(lines)



def validate_edge_authority(authority: dict[str, Any]) -> None:
    if authority.get('kongUpstreamEnvironmentVariable') != 'CADDY_KONG_UPSTREAM':
        raise RouteAuthorityError('public_route_must_use_kong')
    if authority.get('unknownRoutePolicy', {}).get('status') != 404 or authority.get('migration', {}).get('legacyFallbackTemporarilyAllowed') is not False:
        raise RouteAuthorityError('unknown_routes_must_fail_closed')
    if authority.get('canonicalHost') != 'api.codestra.co':
        raise RouteAuthorityError('invalid_canonical_host')
    if 'kongManagedPathPrefixes' in authority:
        raise RouteAuthorityError('prefix_fallback_forbidden')
    paths = authority.get('privateOnlyPaths', []) + authority.get('pendingContractPaths', []) + authority.get('transitionalPaths', [])
    if any(not re.fullmatch(r'/[A-Za-z0-9/._*+-]*', x) for x in paths):
        raise RouteAuthorityError('invalid_path')
    contract = authority['serviceJwtRouteContract']['routes'] + authority['middlewareDeniedRoutes'] + authority['kongOwnedRoutes']
    for row in contract:
        methods = row.get('methods') or [row['method']]
        if not set(methods) <= ALLOWED_METHODS - {'ANY'} or not re.fullmatch(r'/[A-Za-z0-9/._{}-]*', row['path']):
            raise RouteAuthorityError('invalid_contract_route')
    if any(row.get('classification') not in {'denied', 'private_only'} for row in authority['middlewareDeniedRoutes']):
        raise RouteAuthorityError('unknown_classification')
    validate_route_ownership(authority)
    if not {'/metrics', '/metrics/*', '/internal', '/internal/*'} <= set(authority['privateOnlyPaths']):
        raise RouteAuthorityError('required_private_prefix_missing')
    if set(authority['identityHeaders']['deletedBeforeKong']) != set(FORBIDDEN_IDENTITY_HEADERS):
        raise RouteAuthorityError('identity_header_contract_drift')
    if authority.get('realtimeUpstreamEnvironmentVariable') != 'CADDY_REALTIME_UPSTREAM':
        raise RouteAuthorityError('invalid_compatibility_upstream')


def _probe(path: str) -> str:
    return re.sub(r'\{[a-z_]+\}', 'probe-1', path)


def _kong_owned_regex(row: dict) -> str:
    base = route_regex(row['path'])
    return f'^{base}(/.*)?$' if row['match'] == 'prefix' else f'^{base}$'


def validate_route_ownership(authority: dict[str, Any]) -> None:
    """Each method+path has one owner; nothing forwarded overlaps a denied or private route."""
    shared = [(row['method'], row['path']) for row in authority['serviceJwtRouteContract']['routes']]
    closed = [(row['method'], row['path']) for row in authority['middlewareDeniedRoutes']]
    if len(set(shared)) != len(shared):
        raise RouteAuthorityError('duplicate_operation_ownership')
    for method, path in closed:
        if (method, path) in shared:
            raise RouteAuthorityError(f'denied_route_with_upstream:{method}:{path}')
    private = tuple(p.rstrip('*').rstrip('/') for p in authority['privateOnlyPaths'])
    for row in authority['kongOwnedRoutes']:
        if row['match'] not in {'exact', 'prefix'}:
            raise RouteAuthorityError('unknown_classification')
        if row['path'].startswith(private):
            raise RouteAuthorityError('private_only_routed_publicly')
        pattern = re.compile(_kong_owned_regex(row))
        for method, path in shared:
            if method in row['methods'] and pattern.match(_probe(path)):
                raise RouteAuthorityError(f'duplicate_operation_ownership:{method}:{path}')
        for method, path in closed:
            if method in row['methods'] and pattern.match(_probe(path)):
                raise RouteAuthorityError(f'denied_route_with_upstream:{method}:{path}')


def kong_owned_block(routes: list[dict]) -> list[str]:
    lines = ['\t\t# Kong-owned routes beyond the public route contract (config/kong-owned-edge-routes.v1.json).']
    for index, row in enumerate(routes):
        matcher = f'kong_owned_{index:02d}'
        lines += [f'\t\t@{matcher} {{', '\t\t\tmethod ' + ' '.join(row['methods']),
                  f'\t\t\tpath_regexp {_kong_owned_regex(row)}', '\t\t}',
                  f'\t\thandle @{matcher} {{', f'\t\t\tvars edge_route_id edge.kong.{row["kongRoute"]}',
                  *proxy_lines(), '\t\t}', '']
    return lines


AGENCY_START = "\t\t# BEGIN GENERATED LEGACY AGENCY KONG ROUTES"
AGENCY_END = "\t\t# END GENERATED LEGACY AGENCY KONG ROUTES"


def legacy_agency_block(authority: dict[str, Any]) -> str:
    """api.codestra.agency serves only flagged Kong-owned routes, exactly as the canonical host does."""
    lines = [AGENCY_START, '\t\t# Generated from config/kong-owned-edge-routes.v1.json (legacyAgencyHost); Kong sees the canonical host.']
    for index, row in enumerate(authority['kongOwnedRoutes']):
        if not row.get('legacyAgencyHost'):
            continue
        matcher = f'kong_owned_{index:02d}'
        proxy = proxy_lines()
        proxy[1] = proxy[1].replace('header_up Host {host}', 'header_up Host api.codestra.co')
        proxy[2:2] = ['\t\t\t\theader_up X-Forwarded-Host {host}', '\t\t\t\theader_up X-Forwarded-Proto {scheme}']
        lines += [f'\t\t@{matcher} {{', '\t\t\tmethod ' + ' '.join(row['methods']),
                  f'\t\t\tpath_regexp {_kong_owned_regex(row)}', '\t\t}',
                  f'\t\thandle @{matcher} {{', f'\t\t\tvars edge_route_id edge.legacy_agency.{row["kongRoute"]}',
                  *proxy, '\t\t}', '']
    lines.append(AGENCY_END)
    return '\n'.join(lines)


def render_legacy_agency_site(authority: dict[str, Any], source: str) -> str:
    start, end = source.index(AGENCY_START), source.index(AGENCY_END) + len(AGENCY_END)
    return source[:start] + legacy_agency_block(authority) + source[end:]


def denied_block(routes: list[dict]) -> list[str]:
    lines = ['\t\t# Middleware denied and private_only operations terminate here; they never reach Kong.']
    for method in sorted({row['method'] for row in routes}):
        expression = '^(' + '|'.join(sorted(route_regex(row['path']) for row in routes if row['method'] == method)) + ')$'
        lines += [f'\t\t@contract_denied_{method.lower()} {{', f'\t\t\tmethod {method}', f'\t\t\tpath_regexp {expression}',
                  '\t\t}', f'\t\thandle @contract_denied_{method.lower()} {{', '\t\t\trespond 404', '\t\t}', '']
    return lines


def compile_edge_site(authority: dict[str, Any]) -> str:
    validate_edge_authority(authority)
    lines = ['\troute {']
    for matcher, paths in [('private_only', authority['privateOnlyPaths']), ('pending_contract', authority['pendingContractPaths'])]:
        lines += [f'\t\t@{matcher} path ' + ' '.join(paths), f'\t\thandle @{matcher} {{', '\t\t\trespond 404', '\t\t}', '']
    lines += denied_block(authority['middlewareDeniedRoutes'])
    lines.append(route_block(authority['serviceJwtRouteContract']['routes']))
    lines += ['', *kong_owned_block(authority['kongOwnedRoutes'])]
    lines += ['\t\t# Transitional compatibility remains explicitly allowlisted.', '\t\t@realtime path ' + ' '.join(authority['transitionalPaths']), '\t\thandle @realtime {', '\t\t\tvars edge_route_id edge.realtime']
    lines += [x.replace('CADDY_KONG_UPSTREAM', 'CADDY_REALTIME_UPSTREAM') for x in proxy_lines()]
    lines += ['\t\t}', '', '\t\t# Unknown public API paths fail closed.', '\t\thandle {', '\t\t\trespond 404', '\t\t}', '\t}']
    return (ROOT / 'config/api-site.template.caddy').read_text().replace('@@ROUTES@@', '\n'.join(lines))


def edge_inventory(authority: dict[str, Any], generated: str) -> dict[str, Any]:
    validate_edge_authority(authority)
    rows = []
    def add(path, methods, visibility, upstream, group):
        identity = f'{authority["canonicalHost"]}:{",".join(methods)}:{path}'
        rows.append({'route_id': 'edge.' + _sha256(identity.encode())[:20], 'handler_id': group,
                     'host': authority['canonicalHost'], 'path': path, 'methods': methods,
                     'visibility': visibility, 'upstream_ref': upstream,
                     'upstream_service': 'kong' if upstream == 'CADDY_KONG_UPSTREAM' else ('none' if upstream == 'NONE' else 'realtime'),
                     'owner': 'appolon1908/Caddy'})
    for row in authority['serviceJwtRouteContract']['routes']:
        add(row['path'], [row['method']], 'public', 'CADDY_KONG_UPSTREAM', 'edge.canonical.' + row['method'].lower())
    for row in authority['kongOwnedRoutes']:
        add(row['path'] + ('/*' if row['match'] == 'prefix' else ''), row['methods'], 'public', 'CADDY_KONG_UPSTREAM', 'edge.kong.' + row['kongRoute'])
    for row in authority['middlewareDeniedRoutes']:
        add(row['path'], [row['method']], 'private', 'NONE', 'edge.contract.' + row['classification'])
    for path in authority['transitionalPaths']:
        add(path, ['ANY'], 'compatibility', 'CADDY_REALTIME_UPSTREAM', 'edge.realtime')
    for path in authority['privateOnlyPaths'] + authority['pendingContractPaths']:
        add(path, ['ANY'], 'private', 'NONE', 'edge.denied')
    add('*', ['ANY'], 'private', 'NONE', 'edge.unknown')
    rows.sort(key=lambda x: (x['path'], x['methods']))
    return {'schema': 'codestra.caddy.route-inventory.v1', 'source_sha256': _sha256(json.dumps(authority,sort_keys=True,separators=(',',':')).encode()),
            'generated_sha256': _sha256(generated.encode()), 'route_count': len(rows),
            'public_count': sum(x['visibility'] == 'public' for x in rows),
            'private_count': sum(x['visibility'] == 'private' for x in rows), 'routes': rows}


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
