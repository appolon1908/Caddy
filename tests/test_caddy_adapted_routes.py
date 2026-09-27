import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "caddy_adapted_routes.py"
# The same synthetic upstream values scripts/validate-ci.sh passes to the
# pinned validator image; the adapted document must never carry real hosts.
CI_ENVIRONMENT = {
    "CADDY_KONG_UPSTREAM": "127.0.0.1:8000",
    "CADDY_LEGACY_API_UPSTREAM": "127.0.0.1:18101",
    "CADDY_REALTIME_UPSTREAM": "127.0.0.1:18102",
    "CADDY_EDITOR_ADMIN_CIDRS": "192.0.2.0/24",
    "CADDY_N8N_EDITOR_HOST": "n8n-editor.invalid",
    "CADDY_N8N_OAUTH2_PROXY_UPSTREAM": "127.0.0.1:4180",
    "CADDY_N8N_EDITOR_MAX_REQUEST_BODY": "16777216",
    "CADDY_GRAFANA_UPSTREAM": "127.0.0.1:18003",
    "CADDY_SUPERSET_UPSTREAM": "127.0.0.1:18088",
    "CADDY_OPENBAO_UPSTREAM": "127.0.0.1:18200",
    "CADDY_OPENBAO_ALLOWED_CIDRS": "192.0.2.0/24 198.51.100.0/24",
}


def real_adapted_document() -> dict | None:
    """Adapt the repository Caddyfile with a local ``caddy`` binary, if any."""
    binary = os.environ.get("CADDY_BIN") or shutil.which("caddy")
    if not binary:
        return None
    completed = subprocess.run(
        [binary, "adapt", "--config", str(ROOT / "Caddyfile"), "--adapter", "caddyfile", "--validate"],
        capture_output=True,
        text=True,
        env={**os.environ, **CI_ENVIRONMENT},
        cwd=ROOT,
        check=True,
    )
    return json.loads(completed.stdout)


def load_module():
    assert MODULE_PATH.exists(), "adapted Caddy route resolver is missing"
    spec = importlib.util.spec_from_file_location("caddy_adapted_routes", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def adapted_fixture() -> dict:
    return {
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "routes": [
                            {
                                "match": [{"host": ["api.codestra.co"]}],
                                "handle": [
                                    {
                                        "handler": "subroute",
                                        "routes": [
                                            {
                                                "match": [
                                                    {
                                                        "method": ["POST"],
                                                        "path": [
                                                            "/api/v1/integrations/n8n/results"
                                                        ],
                                                    }
                                                ],
                                                "handle": [
                                                    {
                                                        "handler": "reverse_proxy",
                                                        "upstreams": [{"dial": "kong:8000"}],
                                                    }
                                                ],
                                            },
                                            {
                                                "match": [
                                                    {
                                                        "method": ["GET"],
                                                        "path_regexp": {
                                                            "name": "integration_read",
                                                            "pattern": "^(/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}|/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(/desired-state)?)$",
                                                        },
                                                    }
                                                ],
                                                "handle": [
                                                    {
                                                        "handler": "reverse_proxy",
                                                        "upstreams": [{"dial": "kong:8000"}],
                                                    }
                                                ],
                                            },
                                            {
                                                "match": [
                                                    {
                                                        "path": [
                                                            "/api/v1/integrations/odoo/campaign-actions*",
                                                            "/api/v1/integrations/odoo/campaign-commands*",
                                                            "/api/v1/integration/campaign-actions*",
                                                            "/api/v1/odoo/campaign-actions*",
                                                        ]
                                                    }
                                                ],
                                                "handle": [
                                                    {
                                                        "handler": "reverse_proxy",
                                                        "upstreams": [{"dial": "kong:8000"}],
                                                    }
                                                ],
                                            },
                                            {
                                                "match": [
                                                    {
                                                        "path": [
                                                            "/api/v1/integrations/n8n/results*",
                                                            "/api/v1/integrations/odoo/campaigns*",
                                                        ]
                                                    }
                                                ],
                                                "handle": [
                                                    {
                                                        "handler": "subroute",
                                                        "routes": [
                                                            {
                                                                "handle": [
                                                                    {
                                                                        "handler": "reverse_proxy",
                                                                        "upstreams": [{"dial": "kong:8000"}],
                                                                    }
                                                                ]
                                                            }
                                                        ],
                                                    }
                                                ],
                                            },
                                            {
                                                "handle": [
                                                    {
                                                        "handler": "static_response",
                                                        "status_code": 404,
                                                    }
                                                ]
                                            },
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        }
    }


def test_resolves_nested_adapted_routes_in_declared_order():
    resolver = load_module()
    document = adapted_fixture()

    exact = resolver.resolve_request(document, "GET", "/api/v1/integrations/n8n/results/EVT-1")
    assert exact.upstream == "kong:8000"
    assert exact.method_constrained is True
    assert exact.path_matcher == "path_regexp"

    guarded = resolver.resolve_request(
        document, "DELETE", "/api/v1/integrations/n8n/results/EVT-1"
    )
    assert guarded.upstream == "kong:8000"
    assert guarded.method_constrained is False
    assert guarded.path_matcher == "path_prefix"

    noncanonical = resolver.resolve_request(
        document, "GET", "/api/v1/integrations/n8n/results/EVT-1/extra"
    )
    assert noncanonical.upstream == "kong:8000"
    assert noncanonical.method_constrained is False

    unknown = resolver.resolve_request(document, "GET", "/api/v2/unrelated")
    assert unknown.upstream is None
    assert unknown.response_status == 404
    assert unknown.method_constrained is False
    assert unknown.path_matcher is None


def test_fixture_distinguishes_exact_prefix_and_regexp_matchers():
    resolver = load_module()
    document = adapted_fixture()

    exact = resolver.resolve_request(document, "POST", "/api/v1/integrations/n8n/results")
    assert exact.upstream == "kong:8000"
    assert exact.method_constrained is True
    assert exact.path_matcher in resolver.EXACT_PATH_MATCHERS

    prefix = resolver.resolve_request(document, "DELETE", "/api/v1/integrations/n8n/results")
    assert prefix.upstream == "kong:8000"
    assert prefix.method_constrained is False
    assert prefix.path_matcher == "path_prefix"
    assert prefix.path_matcher not in resolver.EXACT_PATH_MATCHERS


def test_canonical_probe_table_covers_the_mission_minimum():
    resolver = load_module()
    probes = set(resolver.CANONICAL_PROBES)
    for required in (
        ("POST", "/api/v1/odoo/events"),
        ("POST", "/api/v1/integrations/n8n/results"),
        ("GET", "/api/v1/integrations/n8n/results/EVT-TEST-SYN-0001"),
        ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN"),
        ("GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state"),
        ("POST", "/v2/automation/commands"),
        ("GET", "/platform/v1/repositories"),
    ):
        assert required in probes, required
    fail_closed = set(resolver.FAIL_CLOSED_PROBES)
    for retired in (
        ("POST", "/v1/integrations/n8n/commands"),
        ("GET", "/v1/integrations/n8n/operations"),
        ("POST", "/api/v1/integrations/odoo/campaign-actions"),
        ("POST", "/api/v1/odoo/campaign-actions"),
    ):
        assert retired in fail_closed, retired


def test_real_adapted_config_resolves_the_complete_edge_matrix():
    document = real_adapted_document()
    if document is None:
        pytest.skip("no caddy binary: set CADDY_BIN or run scripts/validate-ci.sh")
    resolver = load_module()
    result = resolver.validate_edge_matrix(document, "127.0.0.1:8000", "127.0.0.1:18101")
    assert result.canonical_routes == len(resolver.CANONICAL_PROBES)
    assert result.fail_closed_routes == len(resolver.FAIL_CLOSED_PROBES)
    assert result.legacy_probes == 1


def test_adapted_matrix_rejects_wrong_method_reaching_legacy():
    resolver = load_module()
    document = real_adapted_document()
    if document is None:
        pytest.skip("no caddy binary: set CADDY_BIN or run scripts/validate-ci.sh")
    broken = json.loads(json.dumps(document))

    def rewrite(routes) -> int:
        changed = 0
        for route in routes:
            for handler in route.get("handle") or ():
                if handler.get("handler") == "reverse_proxy":
                    for upstream in handler.get("upstreams") or ():
                        if upstream.get("dial") == "127.0.0.1:8000":
                            upstream["dial"] = "127.0.0.1:18101"
                            changed += 1
                changed += rewrite(handler.get("routes") or ())
        return changed

    # Point every Kong prefix rule at the legacy upstream: the wrong-method and
    # retired-alias probes must now be rejected as reaching legacy.
    servers = broken["apps"]["http"]["servers"].values()
    assert sum(rewrite(server.get("routes") or ()) for server in servers) > 0
    with pytest.raises(ValueError, match="canonical_route_not_kong|fail_closed_route_not_kong"):
        resolver.validate_edge_matrix(broken, "127.0.0.1:8000", "127.0.0.1:18101")
