from __future__ import annotations

import copy
import http.client
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from caddy_control_api import ControlService, Handler  # noqa: E402
from caddy_route_compiler import (  # noqa: E402
    RouteAuthorityError,
    build_inventory,
    compile_caddy,
    compile_to_files,
    load_authority,
    validate_authority,
)


@pytest.fixture()
def authority():
    return load_authority(ROOT / "config" / "caddy-route-authority.v1.json")


def test_valid_authority_compiles_deterministically(authority) -> None:
    first = compile_caddy(authority)
    second = compile_caddy(copy.deepcopy(authority))
    assert first == second
    inventory = build_inventory(authority, first)
    assert inventory["route_count"] == 6
    assert inventory["public_count"] == 4
    assert inventory["private_count"] == 2
    assert len(inventory["generated_sha256"]) == 64


@pytest.mark.parametrize("prefix", ["/metrics", "/internal", "/admin", "/database", "/debug"])
def test_private_namespace_cannot_be_public(authority, prefix) -> None:
    bad = copy.deepcopy(authority)
    bad["routes"][0].pop("path_prefix", None)
    bad["routes"][0]["path"] = prefix
    with pytest.raises(RouteAuthorityError, match="private_namespace_public"):
        validate_authority(bad)


def test_direct_legacy_upstream_is_rejected(authority) -> None:
    bad = copy.deepcopy(authority)
    bad["routes"][0]["upstream_ref"] = "CADDY_LEGACY_API_UPSTREAM"
    with pytest.raises(RouteAuthorityError, match="public_route_must_use_kong"):
        validate_authority(bad)


def test_direct_provider_upstream_is_rejected(authority) -> None:
    bad = copy.deepcopy(authority)
    bad["routes"][0]["upstream_service"] = "provider-api"
    bad["routes"][0]["upstream_ref"] = "provider.example:443"
    with pytest.raises(RouteAuthorityError, match="public_route_must_use_kong"):
        validate_authority(bad)


def test_duplicate_route_is_rejected(authority) -> None:
    bad = copy.deepcopy(authority)
    duplicate = copy.deepcopy(bad["routes"][0])
    duplicate["route_id"] = "edge.platform-v1-duplicate"
    bad["routes"].append(duplicate)
    with pytest.raises(RouteAuthorityError, match="duplicate_route"):
        validate_authority(bad)


def test_private_routes_compile_to_404(authority) -> None:
    generated = compile_caddy(authority)
    assert "@pas144_edge_private_metrics" in generated
    assert "@pas144_edge_private_internal" in generated
    assert generated.count("respond 404") == 2


def test_compiler_strips_spoofable_identity_headers(authority) -> None:
    generated = compile_caddy(authority)
    assert "header_up -X-User-ID" in generated
    assert "header_up -X-Authenticated-Tenant" in generated
    assert "header_up -X-Codestra-Gateway-Secret" in generated


def test_compile_check_detects_drift(tmp_path: Path, authority) -> None:
    source = tmp_path / "authority.json"
    output = tmp_path / "generated.caddy"
    inventory = tmp_path / "inventory.json"
    source.write_text(json.dumps(authority), encoding="utf-8")
    compile_to_files(source, output, inventory)
    compile_to_files(source, output, inventory, check=True)
    output.write_text(output.read_text(encoding="utf-8") + "# drift\n", encoding="utf-8")
    with pytest.raises(RouteAuthorityError, match="generated_caddy_drift"):
        compile_to_files(source, output, inventory, check=True)


def test_control_service_compile_validate_status(tmp_path: Path, authority) -> None:
    source = tmp_path / "authority.json"
    output = tmp_path / "generated.caddy"
    inventory = tmp_path / "inventory.json"
    source.write_text(json.dumps(authority), encoding="utf-8")
    service = ControlService(source, output, inventory)

    assert service.status()["drift"] is True
    result = service.compile()
    assert result["compiled"] is True
    assert result["runtime_reload_performed"] is False
    assert service.status()["drift"] is False
    assert service.validate()["valid"] is True
    assert service.routes()["routes"]
    assert len(service.digest()["compiled_sha256"]) == 64


def test_http_api_positive_and_negative(tmp_path: Path, authority) -> None:
    source = tmp_path / "authority.json"
    output = tmp_path / "generated.caddy"
    inventory = tmp_path / "inventory.json"
    source.write_text(json.dumps(authority), encoding="utf-8")

    class TestHandler(Handler):
        service = ControlService(source, output, inventory)

    server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        conn.request("POST", "/platform/v1/caddy/config/compile", headers={"X-Correlation-ID": "test-correlation"})
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert response.getheader("X-Correlation-ID") == "test-correlation"
        assert body["ok"] is True
        assert body["runtime_reload_performed"] is False

        conn.request("GET", "/platform/v1/caddy/config/status")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["drift"] is False

        conn.request("GET", "/does-not-exist")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 404
        assert body["error"]["code"] == "not_found"
    finally:
        server.shutdown()
        server.server_close()


def test_control_api_refuses_non_loopback_bind_source() -> None:
    source = (ROOT / "scripts" / "caddy_control_api.py").read_text(encoding="utf-8")
    assert 'args.host not in {"127.0.0.1", "::1", "localhost"}' in source
    assert "refusing non-loopback bind" in source
