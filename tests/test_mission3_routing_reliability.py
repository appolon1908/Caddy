from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "sites" / "api.codestra.co.caddy"
DOCS = ROOT / "docs"


def test_m3_required_documents_exist():
    required = {
        "reverse-proxy-contract-v1.md",
        "timeout-profiles-v1.md",
        "maintenance-contract-v1.md",
        "error-contract-v1.md",
        "caddy-kong-boundary-v1.md",
        "edge-architecture-v1.md",
    }
    present = {p.name for p in DOCS.iterdir() if p.is_file()}
    assert required.issubset(present)


def test_api_site_routes_kong_and_unknown_routes_fail_closed():
    source = SITE.read_text(encoding="utf-8")
    assert "api.codestra.co {" in source
    assert "@kong path" in source
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in source
    assert "reverse_proxy {$CADDY_LEGACY_API_UPSTREAM}" not in source
    assert source.index("@private_only path") < source.index("@kong path")
    assert source.rindex("reverse_proxy {$CADDY_KONG_UPSTREAM}") < source.rindex("respond 404")


def test_known_paths_and_maintenance_behavior_are_explicit():
    source = SITE.read_text(encoding="utf-8")
    assert "/api/v1/health" in source
    assert "/api/v1/realtime/sessions" in source
    assert "maintenance".lower() in source.lower() or "@realtime" in source


def test_direct_middleware_or_provider_bypass_is_forbidden_for_managed_routes():
    source = SITE.read_text(encoding="utf-8")
    forbidden = (
        "http://middleware",
        "https://middleware",
        "codestra-middleware-integration-api-1",
        ":8095",
        "Caddy -> Middleware",
    )
    for token in forbidden:
        assert token not in source


def test_route_contract_document_mentions_timeout_profiles_and_streaming():
    docs = {
        "reverse-proxy-contract-v1.md": (ROOT / "docs" / "reverse-proxy-contract-v1.md").read_text(encoding="utf-8"),
        "timeout-profiles-v1.md": (ROOT / "docs" / "timeout-profiles-v1.md").read_text(encoding="utf-8"),
    }
    assert "WebSocket" in docs["reverse-proxy-contract-v1.md"]
    assert "STANDARD_API" in docs["timeout-profiles-v1.md"]
    assert "WEBSOCKET" in docs["timeout-profiles-v1.md"]
    assert "SSE_STREAM" in docs["timeout-profiles-v1.md"]


def test_maintenance_and_error_contracts_define_safe_fail_closed_behavior():
    maintenance = (ROOT / "docs" / "maintenance-contract-v1.md").read_text(encoding="utf-8")
    error_contract = (ROOT / "docs" / "error-contract-v1.md").read_text(encoding="utf-8")
    assert "MAINTENANCE" in maintenance
    assert "Retry-After" in maintenance
    assert "unknown host" in error_contract.lower()
    assert "fail closed" in error_contract.lower()
