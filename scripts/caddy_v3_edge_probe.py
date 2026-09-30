#!/usr/bin/env python3
"""Resolve the V3 kernel edge matrix through Caddy's adapted JSON.

Static, source-only check. It reads the JSON that ``caddy adapt`` produced for
the complete root Caddyfile and answers, for each probe on the canonical API
host, which upstream dial (or static status) Caddy would select. It never
contacts a runtime and never proves what listens on an upstream.

Probe groups:

``V3_KERNEL``   the six Middleware V3 kernel operations. Each must reach the
                Kong upstream. Caddy does not need an exact rule per operation;
                a host or prefix rule that lands on Kong is sufficient.
``FAMILY``      the other public route families the edge contract retains
                (``/v2/automation/*``, ``/api/v1/odoo/events``). Same rule.
``NEGATIVE``    requests that must never reach the legacy fallback or any
                non-Kong upstream: wrong methods, unknown subpaths, the retired
                n8n integration namespace, ``/metrics`` and ``/internal*``.
                Kong (which answers 404/405) or a Caddy 403/404/405 are the only
                acceptable outcomes.
``HEADER_UP``   the Kong handoff must not set or delete ``Authorization``,
                ``Idempotency-Key``, ``X-Correlation-ID``, ``traceparent`` or
                ``tracestate`` and must not mint trusted identity headers.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

CANONICAL_HOST = "api.codestra.co"

V3_KERNEL_PROBES = (
    ("POST", "/platform/v1/commands"),
    ("GET", "/platform/v1/kernel/describe"),
    ("GET", "/platform/v1/operations/OP-TEST-SYN-0001"),
    ("GET", "/platform/v1/operations/OP-TEST-SYN-0001/timeline"),
    ("POST", "/platform/v1/operations/OP-TEST-SYN-0001/cancel"),
    ("POST", "/platform/v1/operations/OP-TEST-SYN-0001/replay"),
)
FAMILY_PROBES = (
    ("POST", "/v2/automation/commands"),
    ("GET", "/v2/automation/jobs/JOB-TEST-SYN-0001"),
    ("POST", "/api/v1/odoo/events"),
    ("POST", "/api/v1/integrations/n8n/results"),
)
NEGATIVE_PROBES = (
    ("DELETE", "/platform/v1/commands"),
    ("PUT", "/platform/v1/operations/OP-TEST-SYN-0001/replay"),
    ("GET", "/platform/v1/metrics"),
    ("GET", "/v2/automation/unknown"),
    ("POST", "/v1/integrations/n8n/commands"),
    ("GET", "/api/v1/odoo/events"),
    ("GET", "/api/v1/integrations/n8n/results"),
    ("GET", "/metrics"),
    ("GET", "/metrics/runtime"),
    ("GET", "/internal/v1/anything"),
    ("GET", "/internal/v1/database/health"),
    ("POST", "/api/v1/events/telnexa"),
    ("POST", "/api/v1/n8n/acknowledgements"),
    ("POST", "/v1/observability/incidents"),
    ("POST", "/v1/observability/kpis"),
    ("POST", "/webhooks/sms/inbound/test"),
    ("POST", "/webhooks/vicidial/call-result/test"),
)
DENIED_STATUSES = frozenset({403, 404, 405})

# Headers Caddy must carry to Kong unchanged. Setting or deleting any of them
# in the handoff would make Caddy an identity, idempotency or trace authority.
PRESERVED_HEADERS = frozenset(
    name.lower()
    for name in (
        "Authorization",
        "Idempotency-Key",
        "X-Correlation-ID",
        "traceparent",
        "tracestate",
    )
)
# Client-asserted identity/consumer headers must be removed before the Kong
# handoff. Kong may mint authenticated identity after validation; Caddy must not
# trust or forward these inbound values.
REQUIRED_STRIPPED_HEADERS = frozenset(
    name.lower()
    for name in (
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
)
# Neither preserved transport headers nor spoofable identity headers may be
# minted by Caddy on the Kong handoff.
FORBIDDEN_SET_HEADERS = PRESERVED_HEADERS | REQUIRED_STRIPPED_HEADERS


class Resolution(NamedTuple):
    upstream: str | None
    response_status: int | None
    header_set: frozenset[str]
    header_delete: frozenset[str]


class ProbeResult(NamedTuple):
    group: str
    method: str
    path: str
    resolution: Resolution
    ok: bool


def _path_matches(pattern: str, path: str) -> bool:
    expression = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(expression, path) is not None


def _regexp_patterns(value: object) -> Iterable[str]:
    if isinstance(value, Mapping):
        pattern = value.get("pattern")
        if isinstance(pattern, str):
            yield pattern
    elif isinstance(value, list):
        for item in value:
            yield from _regexp_patterns(item)


def _matches(matcher: Mapping[str, Any], method: str, path: str, host: str) -> bool:
    hosts = matcher.get("host")
    if hosts and host.lower() not in {str(value).lower() for value in hosts}:
        return False
    methods = matcher.get("method")
    if methods and method.upper() not in {str(value).upper() for value in methods}:
        return False
    paths = matcher.get("path")
    if paths and not any(_path_matches(str(pattern), path) for pattern in paths):
        return False
    path_regexp = matcher.get("path_regexp")
    if path_regexp and not any(
        re.search(pattern, path) for pattern in _regexp_patterns(path_regexp)
    ):
        return False
    # A negated matcher (for example `not remote_ip`) depends on request
    # properties a static probe does not model; treat it as not matching.
    if matcher.get("not"):
        return False
    return True


def _resolve_routes(
    routes: Iterable[Mapping[str, Any]], method: str, path: str, host: str
) -> Resolution | None:
    for route in routes:
        matcher_sets = route.get("match") or [{}]
        if not any(_matches(matcher, method, path, host) for matcher in matcher_sets):
            continue
        for handler in route.get("handle") or ():
            kind = handler.get("handler")
            if kind == "reverse_proxy":
                upstreams = handler.get("upstreams") or ()
                dial = upstreams[0].get("dial") if upstreams else None
                request_headers = (handler.get("headers") or {}).get("request") or {}
                return Resolution(
                    dial,
                    None,
                    frozenset(name.lower() for name in request_headers.get("set") or {}),
                    frozenset(name.lower() for name in request_headers.get("delete") or ()),
                )
            if kind == "static_response":
                return Resolution(
                    None, int(handler.get("status_code", 200)), frozenset(), frozenset()
                )
            nested = handler.get("routes")
            if nested:
                resolution = _resolve_routes(nested, method, path, host)
                if resolution is not None:
                    return resolution
    return None


def _serves_port(server: Mapping[str, Any], port: int) -> bool:
    """A request reaches only servers listening on its port; unlisted fixtures match."""
    listen = server.get("listen")
    return not listen or any(str(address).rsplit(":", 1)[-1] == str(port) for address in listen)


def resolve_request(
    document: Mapping[str, Any], method: str, path: str, host: str = CANONICAL_HOST, port: int = 443
) -> Resolution:
    servers = document.get("apps", {}).get("http", {}).get("servers", {})
    for server in servers.values():
        if not _serves_port(server, port):
            continue
        resolution = _resolve_routes(server.get("routes") or (), method, path, host)
        if resolution is not None:
            return resolution
    return Resolution(None, None, frozenset(), frozenset())


def probe_edge(document: Mapping[str, Any], kong_upstream: str) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for group, probes in (
        ("V3_KERNEL", V3_KERNEL_PROBES),
        ("FAMILY", FAMILY_PROBES),
    ):
        for method, path in probes:
            resolution = resolve_request(document, method, path)
            results.append(
                ProbeResult(group, method, path, resolution, resolution.upstream == kong_upstream)
            )
    for method, path in NEGATIVE_PROBES:
        resolution = resolve_request(document, method, path)
        denied = resolution.response_status in DENIED_STATUSES
        results.append(
            ProbeResult(
                "NEGATIVE",
                method,
                path,
                resolution,
                resolution.upstream == kong_upstream or denied,
            )
        )
    return results


def header_policy_violations(document: Mapping[str, Any]) -> list[str]:
    """Return fail-closed header-policy violations for the Kong handoff."""
    resolution = resolve_request(document, "POST", "/platform/v1/commands")
    violations = sorted(f"set:{name}" for name in resolution.header_set & FORBIDDEN_SET_HEADERS)
    violations.extend(
        sorted(f"delete:{name}" for name in resolution.header_delete & PRESERVED_HEADERS)
    )
    missing_strips = REQUIRED_STRIPPED_HEADERS - resolution.header_delete
    violations.extend(sorted(f"not-stripped:{name}" for name in missing_strips))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adapted_json", type=Path)
    parser.add_argument("--kong-upstream", required=True)
    args = parser.parse_args(argv)
    document = json.loads(args.adapted_json.read_bytes())

    failures = 0
    for result in probe_edge(document, args.kong_upstream):
        if not result.ok:
            failures += 1
        print(
            f"{'PASS' if result.ok else 'FAIL'} {result.group:<10} {result.method:<6} "
            f"{result.path:<52} upstream={result.resolution.upstream} "
            f"status={result.resolution.response_status}"
        )
    violations = header_policy_violations(document)
    if violations:
        failures += 1
    print(f"{'FAIL' if violations else 'PASS'} HEADER_UP  {' '.join(violations) or 'preserved transport headers untouched; spoofable identity headers stripped'}")

    print(f"CADDY_V3_EDGE_PROBE={'FAIL' if failures else 'PASS'} FAILURES={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
