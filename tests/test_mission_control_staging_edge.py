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


def test_dispatch_order_fail_closed_before_static_frontend():
    source = SOURCE.read_text()
    positions = [
        source.index("handle @private_only"),
        source.index("handle @dashboard_get"),
        source.index("handle @dashboard_unknown"),
        source.index("handle @frontend_read"),
    ]
    assert positions == sorted(positions)
    for endpoint in (
        "contract", "repositories", "repository", "agents", "tasks",
        "task", "local-work", "sources", "notifications",
    ):
        assert f"/platform/v1/dashboard/{endpoint}" in source
    assert "method GET" in source
    assert "respond 405" in source
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in source
    # A single dedicated backend is never exposed as a public Caddy upstream.
    assert "mission-control-readonly:8792" not in source
