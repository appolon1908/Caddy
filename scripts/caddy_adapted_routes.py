#!/usr/bin/env python3
"""Resolve requests through Caddy's adapted JSON for edge-contract tests."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple


class Resolution(NamedTuple):
    upstream: str | None
    response_status: int | None
    method_constrained: bool
    path_matcher: str | None


class MatrixResult(NamedTuple):
    canonical_routes: int
    fail_closed_routes: int
    legacy_probes: int


# Matcher kinds that pin an exact request path: a literal ``path`` without a
# wildcard, or an anchored ``path_regexp``. A wildcard literal is a prefix.
EXACT_PATH_MATCHERS = frozenset({"path", "path_regexp"})

# (method, path). Every canonical probe must resolve to Kong through a
# method-constrained, exact-path matcher, never through a prefix or fallback.
CANONICAL_PROBES = (
    ("POST", "/api/v1/integrations/n8n/results"),
    ("GET", "/api/v1/integrations/n8n/results/EVT-TEST-SYN-0001"),
    ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN"),
    ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state"),
    ("POST", "/api/v1/odoo/events"),
    ("POST", "/v2/automation/commands"),
    ("GET", "/v2/automation/commands/CMD-TEST-SYN-0001"),
    ("POST", "/v2/automation/jobs/claim"),
    ("GET", "/platform/v1/repositories"),
    ("POST", "/platform/v1/runtime/observations"),
    ("POST", "/api/v1/control/callbacks"),
)
# Wrong methods, non-canonical subpaths and retired aliases. These must reach
# Kong only through a prefix rule (so Kong answers 404/405) or be refused by
# Caddy itself; they must never match an exact rule or reach the legacy upstream.
FAIL_CLOSED_PROBES = (
    ("GET", "/api/v1/integrations/n8n/results"),
    ("DELETE", "/api/v1/integrations/n8n/results"),
    ("POST", "/api/v1/integrations/n8n/results/EVT-TEST-SYN-0001"),
    ("POST", "/api/v1/integrations/odoo/campaigns/TEST_SYN"),
    ("POST", "/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state"),
    ("GET", "/api/v1/integrations/n8n/results/EVT-TEST-SYN-0001/extra"),
    ("GET", "/api/v1/integrations/odoo/campaigns"),
    ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN/extra"),
    ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state/extra"),
    ("POST", "/api/v1/integrations/odoo/campaign-actions"),
    ("POST", "/api/v1/integrations/odoo/campaign-commands"),
    ("GET", "/api/v1/integrations/odoo/campaign-commands/x"),
    ("POST", "/api/v1/integration/campaign-actions"),
    ("POST", "/api/v1/odoo/campaign-actions"),
    ("GET", "/api/v1/odoo/events"),
    ("PUT", "/api/v1/odoo/events"),
    ("POST", "/api/v1/odoo/events/extra"),
    ("DELETE", "/v2/automation/commands"),
    ("GET", "/v2/automation/commands"),
    ("POST", "/v2/automation/commands/CMD-TEST-SYN-0001"),
    ("GET", "/v2/automation/unknown"),
    ("DELETE", "/platform/v1/repositories"),
    ("GET", "/platform/v1/runtime/observations"),
    ("POST", "/v1/integrations/n8n/commands"),
    ("GET", "/v1/integrations/n8n/operations"),
    ("GET", "/v1/integrations/n8n/operations/CMD-TEST-SYN-0001"),
    ("POST", "/v1/integrations/n8n/operations/CMD-TEST-SYN-0001/cancel"),
    ("POST", "/v1/integrations/n8n/operations/CMD-TEST-SYN-0001/reconcile"),
)


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
    if path_regexp and not any(re.search(pattern, path) for pattern in _regexp_patterns(path_regexp)):
        return False
    return True


def _resolve_routes(
    routes: Iterable[Mapping[str, Any]],
    method: str,
    path: str,
    host: str,
    method_constrained: bool = False,
    path_matcher: str | None = None,
) -> Resolution | None:
    for route in routes:
        matcher_sets = route.get("match") or [{}]
        matched = next(
            (matcher for matcher in matcher_sets if _matches(matcher, method, path, host)),
            None,
        )
        if matched is None:
            continue
        route_method_constrained = method_constrained or bool(matched.get("method"))
        route_path_matcher = path_matcher
        if matched.get("path_regexp"):
            route_path_matcher = "path_regexp"
        elif matched.get("path"):
            route_path_matcher = (
                "path_prefix"
                if any("*" in str(pattern) for pattern in matched["path"])
                else "path"
            )
        for handler in route.get("handle") or ():
            kind = handler.get("handler")
            if kind == "reverse_proxy":
                upstreams = handler.get("upstreams") or ()
                dial = upstreams[0].get("dial") if upstreams else None
                return Resolution(dial, None, route_method_constrained, route_path_matcher)
            if kind == "static_response":
                return Resolution(
                    None,
                    int(handler.get("status_code", 200)),
                    route_method_constrained,
                    route_path_matcher,
                )
            nested = handler.get("routes")
            if nested:
                resolution = _resolve_routes(
                    nested,
                    method,
                    path,
                    host,
                    route_method_constrained,
                    route_path_matcher,
                )
                if resolution is not None:
                    return resolution
    return None


def resolve_request(
    document: Mapping[str, Any], method: str, path: str, host: str = "api.codestra.co"
) -> Resolution:
    servers = document.get("apps", {}).get("http", {}).get("servers", {})
    for server in servers.values():
        resolution = _resolve_routes(server.get("routes") or (), method, path, host)
        if resolution is not None:
            return resolution
    return Resolution(None, None, False, None)


def validate_edge_matrix(
    document: Mapping[str, Any], kong_upstream: str, legacy_upstream: str
) -> MatrixResult:
    for method, path in CANONICAL_PROBES:
        resolution = resolve_request(document, method, path)
        if resolution.upstream != kong_upstream:
            raise ValueError(f"canonical_route_not_kong:{method} {path}:{resolution}")
        if (
            not resolution.method_constrained
            or resolution.path_matcher not in EXACT_PATH_MATCHERS
        ):
            raise ValueError(f"canonical_route_not_exact:{method} {path}:{resolution}")

    for method, path in FAIL_CLOSED_PROBES:
        resolution = resolve_request(document, method, path)
        denied = resolution.response_status in (404, 405)
        if resolution.upstream != kong_upstream and not denied:
            raise ValueError(f"fail_closed_route_not_kong:{method} {path}:{resolution}")
        if resolution.method_constrained:
            raise ValueError(f"noncanonical_route_matched_exact_rule:{method} {path}:{resolution}")

    unknown = resolve_request(document, "GET", "/api/v2/unrelated")
    if unknown.upstream is not None or unknown.response_status != 404:
        raise ValueError(f"unknown_route_not_fail_closed:{unknown}")
    return MatrixResult(len(CANONICAL_PROBES), len(FAIL_CLOSED_PROBES), 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adapted_json", type=Path)
    parser.add_argument("--kong-upstream", required=True)
    parser.add_argument("--legacy-upstream", required=True)
    args = parser.parse_args(argv)
    document = json.loads(args.adapted_json.read_text(encoding="utf-8"))
    result = validate_edge_matrix(document, args.kong_upstream, args.legacy_upstream)
    print(
        "CADDY_ADAPTED_ROUTE_MATRIX=PASS "
        f"CANONICAL={result.canonical_routes} "
        f"FAIL_CLOSED={result.fail_closed_routes} "
        f"LEGACY_PROBES={result.legacy_probes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
