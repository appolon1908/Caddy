from __future__ import annotations
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = (ROOT / "sites/api.codestra.co.caddy").read_text(encoding="utf-8")
CONTRACT = json.loads((ROOT / "config/caddy-kong-contract.v1.json").read_text(encoding="utf-8"))
MCR = [
    "/platform/v1/campaign-engine",
    "/platform/v1/leads",
    "/platform/v1/campaigns",
    "/platform/v1/delivery-events",
    "/platform/v1/suppressions",
]


def test_every_mcr_route_is_an_exact_kong_owned_route():
    owned = {row["kongRoute"]: row for row in CONTRACT["kongOwnedRoutes"]}
    names = CONTRACT["mcrBoundary"]["coveredByKongOwnedRoutes"]
    assert len(names) == 8
    for name in names:
        assert owned[name]["match"] == "exact" and len(owned[name]["methods"]) == 1, name
        assert any(owned[name]["path"].startswith(prefix) for prefix in MCR), name
    assert "/platform/v1*" not in SITE and "kongManagedPathPrefixes" not in CONTRACT


def test_mcr_boundary_is_explicit_and_not_cutover_authority():
    b = CONTRACT["mcrBoundary"]
    assert b["mission"] == "MCR-K"
    assert b["kongOnly"] is True
    assert b["productionCutoverAuthorizedBySource"] is False
    assert b["authorizationHeaderForwarded"] is True
    assert b["trustedIdentityHeadersCreatedByCaddy"] is False
    assert b["publicInternalAndMetricsForbidden"] is True
    assert b["managedPaths"] == MCR


def test_platform_v1_handoff_targets_kong_not_middleware_or_provider():
    start = SITE.index("# Kong-owned routes")
    end = SITE.index("# Transitional compatibility", start)
    block = SITE[start:end]
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in block
    assert "MIDDLEWARE" not in block.upper()
    assert "KLYROW" not in block.upper()
    assert "TELNEXA" not in block.upper()
    assert "VICIDIAL" not in block.upper()


def test_authorization_is_preserved_to_kong_and_only_redacted_from_logs():
    start = SITE.index("# Kong-owned routes")
    end = SITE.index("# Transitional compatibility", start)
    block = SITE[start:end]
    assert "header_up Authorization" not in block
    assert "header_up -Authorization" not in block
    assert "request_header -Authorization" not in block
    assert "import access_log api-codestra-co" in SITE
    assert "request>headers>Authorization delete" in (ROOT / "snippets/access_log.caddy").read_text(encoding="utf-8")


def test_private_internal_and_metrics_stay_edge_denied():
    assert "@private_only path /metrics /metrics/* /internal /internal/*" in SITE
    assert "handle @private_only" in SITE
    assert "respond 404" in SITE


def _adapted_routes():
    spec = importlib.util.spec_from_file_location(
        "mcr_adapted_routes", ROOT / "tests" / "test_caddy_adapted_routes.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_adapted_config_hands_mcr_and_kernel_to_kong_and_denies_private_paths():
    adapted = _adapted_routes()
    document = adapted.real_adapted_document()
    if document is None:
        pytest.skip("no caddy binary: set CADDY_BIN or run scripts/validate-ci.sh")
    resolver = adapted.load_module()
    kong = adapted.CI_ENVIRONMENT["CADDY_KONG_UPSTREAM"]
    # Kong owns the MCR routes (Kong:config/kong-mcr-routes.v1.json) and hands them
    # to Middleware V3 on :8095; Caddy only ever selects Kong for them.
    for method, path in (
        ("GET", "/platform/v1/kernel/describe"),
        ("POST", "/platform/v1/campaign-engine/plan"),
        ("POST", "/platform/v1/campaign-engine/execute"),
        ("GET", "/platform/v1/campaign-engine/status"),
        ("GET", "/platform/v1/leads/LEAD-TEST-SYN-0001/journey"),
        ("GET", "/platform/v1/leads/LEAD-TEST-SYN-0001/next-action"),
        ("GET", "/platform/v1/campaigns/CMP-TEST-SYN-0001/eligible-leads"),
        ("POST", "/platform/v1/delivery-events"),
        ("POST", "/platform/v1/suppressions"),
    ):
        resolution = resolver.resolve_request(document, method, path)
        assert resolution.upstream == kong, (method, path, resolution)
    for method, path in (("DELETE", "/platform/v1/suppressions"), ("GET", "/platform/v1/unknown"),
                         ("GET", "/platform/v1/campaign-engine/plan"), ("POST", "/platform/v1/leads/L-1/journey")):
        resolution = resolver.resolve_request(document, method, path)
        assert resolution.upstream is None and resolution.response_status == 404, (method, path, resolution)
    for method in ("GET", "POST", "DELETE"):
        for path in ("/internal", "/internal/v1/database/health", "/metrics", "/metrics/runtime"):
            resolution = resolver.resolve_request(document, method, path)
            assert resolution.upstream is None, (method, path, resolution)
            assert resolution.response_status == 404, (method, path, resolution)
