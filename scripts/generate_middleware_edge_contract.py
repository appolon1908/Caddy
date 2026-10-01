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
from caddy_route_compiler import FORBIDDEN_IDENTITY_HEADERS, compile_caddy

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "config/middleware-public-api-route-contract.v1.json"
PINNED = ROOT / "config/middleware-public-api-route-contract.sha256"
EDGE = ROOT / "config/caddy-kong-contract.v1.json"
SITE = ROOT / "sites/api.codestra.co.caddy"

MIDDLEWARE_SOURCE_SHA = "2862af0aa97367b18cb360af69212abe4243a1ac"
# Kong was transferred to appolon1908; the numeric ID is the stable identity.
KONG_REPOSITORY = "appolon1908/Kong"
KONG_REPOSITORY_ID = 1347790742
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
DELETED_IDENTITY_HEADERS = list(FORBIDDEN_IDENTITY_HEADERS)


def canonical_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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
            "gatewayRepository": KONG_REPOSITORY,
            "gatewayRepositoryId": KONG_REPOSITORY_ID,
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

    site = compile_caddy(edge)

    return json.dumps(edge, indent=2) + "\n", site


def main() -> None:
    edge, site = render()
    # LF on every platform keeps the committed outputs byte-identical to CI.
    EDGE.write_text(edge, encoding="utf-8", newline="\n")
    SITE.write_text(site, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
