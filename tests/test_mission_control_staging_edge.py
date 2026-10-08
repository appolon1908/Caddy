"""Offline, staging-only dashboard edge invariants."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/staging/mission-control-dashboard.caddy"


def test_only_get_to_kong_for_dashboard_api():
    s = SOURCE.read_text()
    assert "dashboard.staging.internal.codestra.agency" in s
    assert "tls internal" in s
    assert "method GET" in s
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in s
    assert "reverse_proxy {$CADDY_MISSION_CONTROL_FRONTEND_UPSTREAM}" in s
    assert "handle @dashboard_unknown" in s
    assert "respond 404" in s and "respond 405" in s
    assert "header_up -X-Authenticated-Tenant" in s
    assert "header_up -X-Codestra-Gateway-Secret" in s
    assert "header_up Host dashboard.staging.internal.codestra.agency" in s
    assert "127.0.0.1:8792" not in s
    assert "handle @private_only" in s
    assert "PRODUCTION_GO=YES" not in s
