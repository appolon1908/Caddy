"""Every Kong public route has an explicit, enforced Caddy ingress decision."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DECISIONS = json.loads((ROOT / "contracts" / "kong-route-ingress-decisions.v1.json").read_text(encoding="utf-8"))


def test_decisions_name_the_paired_kong_and_are_complete_and_explained():
    contract = json.loads((ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8"))
    chain = json.loads((ROOT / "config" / "edge-contract-chain.v1.json").read_text(encoding="utf-8"))
    assert DECISIONS["kongRepository"] == contract["gatewayRepository"] == chain["kong"]["repository"]
    assert DECISIONS["kongRepositoryId"] == contract["gatewayRepositoryId"]
    assert DECISIONS["kongSourceSha"] == chain["kong"]["source_sha"]
    owned = json.loads((ROOT / "config" / "kong-owned-edge-routes.v1.json").read_text(encoding="utf-8"))
    assert owned["kongSourceSha"] == chain["kong"]["source_sha"]
    routes = [item["route"] for item in DECISIONS["decisions"]]
    assert len(routes) == len(set(routes)) == 45
    for item in DECISIONS["decisions"]:
        assert item["decision"] in {"FORWARD_TO_KONG", "DENY_PENDING_CONTRACT", "DENY_MIDDLEWARE_CONTRACT", "DENY_KONG_DEPRECATED",
                                    "DENY_METHOD", "NOT_AN_EDGE_HOST"}
        assert item["probes"], item["route"]
        if item["decision"] != "FORWARD_TO_KONG":
            assert item.get("reason"), item["route"]


def test_every_decision_is_what_the_adapted_edge_does():
    from test_caddy_adapted_routes import CI_ENVIRONMENT, load_module, real_adapted_document
    document = real_adapted_document()
    if document is None:
        pytest.skip("requires CADDY_BIN")
    resolver = load_module()
    kong = CI_ENVIRONMENT["CADDY_KONG_UPSTREAM"]
    for item in DECISIONS["decisions"]:
        for probe in item["probes"]:
            result = resolver.resolve_request(document, probe["method"], probe["path"], probe["host"])
            where = (item["route"], probe)
            if probe["expect"] == "kong":
                assert result.upstream == kong, where
            elif probe["expect"] == "no_site":
                assert result.upstream is None and result.response_status is None, where
            else:
                assert result.upstream is None and result.response_status == probe["expect"], where
