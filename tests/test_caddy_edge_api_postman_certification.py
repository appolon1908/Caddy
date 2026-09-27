from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

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


def test_pas162_chain_is_exact_and_fully_bound() -> None:
    state = certifier.chain_state(CHAIN, certifier.sha256_file(certifier.COLLECTION_PATH))
    expected_contract = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
    expected_postman = "c6cbdeaf91089b5e9c9ca2f1286569a25fd25844f9ecf3aa414e9905293da341"
    assert state["required_digest"] == expected_contract
    assert state["middleware_digest"] == expected_contract
    assert state["kong_digest"] == expected_contract
    assert state["digest_match"] is True
    assert state["recorded_postman_sha256"] == expected_postman
    assert state["actual_postman_sha256"] == expected_postman
    assert state["postman_match"] is True


def test_collection_has_no_embedded_secret_values() -> None:
    text = json.dumps(COLLECTION)
    environment = {row["key"]: row["value"] for row in ENVIRONMENT["values"]}
    assert "Bearer eyJ" not in text
    assert "sk-" not in text
    assert environment["access_token"] == ""
    assert environment["wrong_scope_token"] == ""
    assert environment["wrong_audience_token"] == ""
