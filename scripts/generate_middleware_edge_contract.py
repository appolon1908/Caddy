#!/usr/bin/env python3
"""Render Caddy's Middleware edge authority from the vendored V3 contract.

This generator keeps Caddy as TLS/public-edge authority only:
- exact shared_edge method/path routes go to Kong;
- denied/unsupported canonical families stay on the Kong prefix fallback;
- /metrics, /metrics/*, /internal and /internal/* remain public-edge 404s;
- spoofable identity headers are deleted before Kong;
- Authorization/correlation/idempotency/trace headers are untouched.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "config/middleware-public-api-route-contract.v1.json"
PINNED = ROOT / "config/middleware-public-api-route-contract.sha256"
EDGE = ROOT / "config/caddy-kong-contract.v1.json"
SITE = ROOT / "sites/api.codestra.co.caddy"

MIDDLEWARE_SOURCE_SHA = "2862af0aa97367b18cb360af69212abe4243a1ac"
START = "\t\t# BEGIN GENERATED MIDDLEWARE CONTRACT ROUTES"
END = "\t\t# END GENERATED MIDDLEWARE CONTRACT ROUTES"
INSERT_MARKER = "\t\t# Paths already represented by reviewed Kong source"
PUBLIC_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"

PRESERVED_HEADERS = [
    "Authorization",
    "X-Correlation-ID",
    "Idempotency-Key",
    "traceparent",
    "tracestate",
]
DELETED_IDENTITY_HEADERS = [
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
]


def canonical_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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
    lines.append(f"{indent}}}")
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
                *proxy_lines(),
                "\t\t}",
                "",
            ]
        )
    lines.append(END)
    return "\n".join(lines)


def retired_prefixes(denied: list[dict]) -> list[str]:
    return sorted({row["path"].split("/{", 1)[0] for row in denied})


def render() -> tuple[str, str]:
    contract = json.loads(VENDORED.read_text(encoding="utf-8"))
    digest = canonical_sha256(contract)
    pinned = PINNED.read_text(encoding="utf-8").strip()
    if pinned != digest:
        raise SystemExit(f"vendored contract hash mismatch: pinned={pinned} actual={digest}")

    shared = [row for row in contract["routes"] if row["classification"] == "shared_edge"]
    denied = [row for row in contract["routes"] if row["classification"] == "denied"]
    private = [row for row in contract["routes"] if row["classification"] == "private_only"]

    edge = json.loads(EDGE.read_text(encoding="utf-8"))
    edge.update(
        {
            "principalRepository": "ingtrader21-spec/Caddy",
            "gatewayRepository": "ingtrader21-spec/Kong",
            "identityRepository": "ingtrader21-spec/Keycloak",
            "writeBoundaryRepository": "ingtrader21-spec/Middleware-",
            "referenceRepository": "appolon1908-hue/codestra-production-platform",
        }
    )

    prefixes = set(edge.get("kongManagedPathPrefixes", []))
    prefixes.update({"/platform/v1", "/v2/automation", "/api/v1/odoo"})
    edge["kongManagedPathPrefixes"] = sorted(prefixes)
    edge["privateOnlyPaths"] = ["/metrics", "/metrics/*", "/internal", "/internal/*"]
    edge["privateOnlyRule"] = (
        "Private Middleware surfaces are answered 404 at the Caddy public edge before "
        "Kong or any legacy fallback: /metrics and /metrics/* are private monitoring only and "
        "/internal plus /internal/* are service-to-service only."
    )

    edge["middlewareEdgeContract"] = {
        "source": "ingtrader21-spec/Middleware-:deploy/public-api-route-contract.json",
        "sourceSha": MIDDLEWARE_SOURCE_SHA,
        "kongVendoredCopy": "Kong:config/middleware-public-api-route-contract.v1.json",
        "sha256": digest,
        "sharedEdgeOperations": len(shared),
        "deniedOperations": len(denied),
        "privateOnlyOperations": len(private),
        "rule": (
            "every shared_edge and denied path is kept away from the legacy fallback; "
            "private_only operations never appear at the public edge"
        ),
        "sourceNote": "MIDDLEWARE_V3_PROTECTED_MAIN",
    }

    edge["serviceJwtRouteContract"] = {
        "sourceRepository": "ingtrader21-spec/Middleware-",
        "sourcePath": "deploy/public-api-route-contract.json",
        "sourceSha": MIDDLEWARE_SOURCE_SHA,
        "sourceSchema": contract["schema"],
        "sha256": digest,
        "hashRule": contract.get("hash_rule"),
        "routes": [
            {
                "method": row["method"],
                "path": row["path"],
                "scope": row["scope"],
                "audience": row["audience"],
                "callingClient": row["calling_client"],
                "matcher": f"canonical_{row['method'].lower()}",
            }
            for row in shared
        ],
        "unsupportedMethodHandling": (
            "canonical path families remain on the Kong-owned prefix fallback; "
            "Kong answers 404/405 and the legacy fallback never receives them"
        ),
        "retiredPathPrefixes": retired_prefixes(denied),
        "retiredPathHandling": (
            "retired canonical paths remain on the Kong-owned prefix fallback; "
            "they never reach the legacy fallback"
        ),
    }

    edge["identityHeaders"] = {
        "preservedToKong": PRESERVED_HEADERS,
        "deletedBeforeKong": DELETED_IDENTITY_HEADERS,
        "rule": (
            "Caddy deletes client-asserted identity headers on the Kong handoff and "
            "never sets one; Kong mints trusted identity after verification"
        ),
    }
    edge["publicApiDirect"] = {
        "PUBLIC_API_DIRECT_TO_MIDDLEWARE": 0,
        "PUBLIC_API_DIRECT_TO_ODOO": 0,
        "PUBLIC_API_DIRECT_TO_N8N": 0,
        "rule": "api.codestra.co reaches Middleware, Odoo and N8N only through Kong",
    }

    edge["unknownRoutePolicy"] = {
        "classification": "DENIED_UNKNOWN_ROUTE",
        "fallbackUpstream": None,
        "status": 404,
        "rule": "unmatched public paths fail closed at Caddy and never reach Kong, Middleware, Odoo, n8n, or a provider",
    }
    edge["approvedCompatibilityRoutes"] = [
        {"paths": ["/ws/agent", "/api/v1/realtime/sessions", "/healthz", "/readyz", "/version"],
         "upstream": "CADDY_REALTIME_UPSTREAM", "classification": "TRANSITIONAL_EXPLICIT"}
    ]

    edge["middlewareHandoff"] = {
        "authorizationHeaderPreservedByKong": True,
        "middlewareIdentityRevalidation": True,
        "directCaddyToMiddleware": False,
        "approvedServiceHosts": ["middleware-integration-api"],
        "approvedServicePorts": [8095],
        "rule": "Caddy never calls Middleware directly; Kong owns the only public-to-Middleware service handoff.",
    }

    site = SITE.read_text(encoding="utf-8")
    if "{$CADDY_LEGACY_API_UPSTREAM}" in site:
        raise SystemExit("legacy unknown-route upstream is forbidden")
    if "\t\thandle {\n\t\t\trespond 404\n\t\t}" not in site:
        raise SystemExit("fail-closed unknown-route handler missing")
    generated = route_block(shared)
    if START in site and END in site:
        before, rest = site.split(START, 1)
        _old, after = rest.split(END, 1)
        site = before + generated + after
    else:
        if INSERT_MARKER not in site:
            raise SystemExit(f"site insertion marker not found: {INSERT_MARKER!r}")
        site = site.replace(INSERT_MARKER, generated + "\n\n" + INSERT_MARKER, 1)

    return json.dumps(edge, indent=2) + "\n", site


def main() -> None:
    edge, site = render()
    EDGE.write_text(edge, encoding="utf-8")
    SITE.write_text(site, encoding="utf-8")


if __name__ == "__main__":
    main()
