from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


generator = load_script("generate_caddy_edge_certification_postman")
certifier = load_script("certify_caddy_edge_api")

PUBLIC = certifier.load_json(certifier.PUBLIC_PATH)
WEBHOOKS = certifier.load_json(certifier.WEBHOOK_PATH)
CHAIN = certifier.load_json(certifier.CHAIN_PATH)
COLLECTION = certifier.load_json(certifier.COLLECTION_PATH)
ENVIRONMENT = certifier.load_json(certifier.ENV_PATH)


def test_generated_postman_artifacts_are_deterministic() -> None:
    assert COLLECTION == generator.render_collection()
    assert ENVIRONMENT == generator.render_environment()
    assert generator.SOURCE_PATH.read_bytes() == generator.COLLECTION_PATH.read_bytes()


def test_postman_safe_environment_defaults_to_loopback_and_disabled() -> None:
    values = {row["key"]: row["value"] for row in ENVIRONMENT["values"]}
    assert values["base_url"].startswith("https://127.0.0.1:")
    assert values["RUN_CADDY_EDGE_CERTIFICATION"] == "false"
    for key in ("access_token", "wrong_scope_token", "wrong_audience_token", "idempotency_key"):
        assert values[key] == ""


def test_edge_registries_cover_api_private_database_and_webhook_boundaries() -> None:
    report = certifier.validate_registries(PUBLIC, WEBHOOKS)
    assert report["canonical"] == 4
    assert report["pending"] >= 5
    assert report["webhooks"] >= 2
    assert report["database_public_exposure"] == 0


def test_postman_covers_api_webhook_private_and_pending_negative_paths() -> None:
    report = certifier.validate_postman(COLLECTION, ENVIRONMENT)
    assert report["api"] == "PASS"
    assert report["webhook"] == "PASS"
    assert report["private"] == "PASS"
    assert report["safe_environment"] == "PASS"
    assert report["pending_count"] == 3
    assert report["webhook_wrong_method_count"] == 2


def test_postman_api_and_webhook_probes_assert_kong_answers() -> None:
    items = {item["name"]: item for item in certifier.flatten_items(COLLECTION["item"])}
    kernel = "\n".join(items["Kernel describe through public edge"]["event"][0]["script"]["exec"])
    # An edge 404 or a failed Kong hop must never certify the canonical kernel route.
    for status in ("404", "502", "503"):
        assert status not in kernel
    for name in (
        "Kernel describe through public edge",
        "Automation namespace auth negative",
        "N8N result wrong method",
        "Odoo event wrong method",
    ):
        broken = json.loads(json.dumps(COLLECTION))
        for item in certifier.flatten_items(broken["item"]):
            if item["name"] == name:
                item.pop("event")
        with pytest.raises(certifier.CertificationError, match="assertion missing"):
            certifier.validate_postman(broken, ENVIRONMENT)


def test_pas162_chain_is_exact_and_fully_bound() -> None:
    state = certifier.chain_state(CHAIN, certifier.sha256_file(certifier.COLLECTION_PATH))
    expected_contract = "c48c20d8bc71918699abb03cefe1e3c5075536a9d91d8aea8df4fc031891db21"
    expected_postman = "d6ec2e1b0f9ae8043a1bc6b680939a01fb3bd6ced710dc054e7e755b61a722f0"
    assert state["required_digest"] == expected_contract
    assert state["middleware_digest"] == expected_contract
    assert state["digest_match"] is (CHAIN["kong"]["status"] == "PASS")
    assert state["recorded_postman_sha256"] == expected_postman
    assert state["actual_postman_sha256"] == expected_postman
    assert state["postman_match"] is True


def test_certification_refuses_an_unpaired_kong_contract() -> None:
    adapted = os.environ.get("CADDY_ADAPTED_JSON")
    if not adapted:
        pytest.skip("CADDY_ADAPTED_JSON is not set")
    arguments = {"adapted_json": Path(adapted), "kong_upstream": "127.0.0.1:8000"}
    if CHAIN["kong"]["status"] == "PASS":
        assert certifier.certify(**arguments, allow_pending_pas162=False)["verdict"] == "PASS"
        return
    with pytest.raises(certifier.CertificationError, match="not final"):
        certifier.certify(**arguments, allow_pending_pas162=False)
    assert certifier.certify(**arguments, allow_pending_pas162=True)["verdict"] == "PENDING_PAS_162"


def test_collection_has_no_embedded_secret_values() -> None:
    text = json.dumps(COLLECTION)
    environment = {row["key"]: row["value"] for row in ENVIRONMENT["values"]}
    assert "Bearer eyJ" not in text
    assert "sk-" not in text
    assert environment["access_token"] == ""
    assert environment["wrong_scope_token"] == ""
    assert environment["wrong_audience_token"] == ""
