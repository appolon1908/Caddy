import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = json.loads((ROOT / "config/public-edge-registry.v1.json").read_text())
WEBHOOKS = json.loads((ROOT / "config/webhook-edge-registry.v1.json").read_text())
CHAIN = json.loads((ROOT / "config/edge-contract-chain.v1.json").read_text())
API_SITE = (ROOT / "sites/api.codestra.co.caddy").read_text()


def test_canonical_namespaces_go_to_kong_without_legacy_fallback():
    by_id = {entry["id"]: entry for entry in PUBLIC["entries"]}
    for key in ("edge.platform-v1", "edge.automation-v2"):
        entry = by_id[key]
        assert entry["classification"] == "CANONICAL"
        assert entry["gateway"] == "ingtrader21-spec/Kong"
        assert entry["caddy_upstream"] == "CADDY_KONG_UPSTREAM"
        assert entry["legacy_fallback"] is False


def test_private_routes_are_explicit_public_404s():
    by_id = {entry["id"]: entry for entry in PUBLIC["entries"]}
    assert by_id["edge.private-internal-root"]["expected_public_status"] == 404
    assert by_id["edge.private-internal"]["expected_public_status"] == 404
    assert by_id["edge.private-metrics"]["expected_public_status"] == 404
    assert "@private_only path /metrics /metrics/* /internal /internal/*" in API_SITE
    assert "respond 404" in API_SITE


def test_database_and_control_plane_destinations_are_never_public():
    names = {entry["name"] for entry in PUBLIC["forbidden_public_destinations"]}
    assert {"postgresql", "redis", "nats", "temporal", "openbao-internal"} <= names
    lowered = API_SITE.lower()
    for forbidden in ("postgres://", "postgresql://", ":5432", "redis://", "nats://"):
        assert forbidden not in lowered


def test_unknown_fallback_is_retired_and_fails_closed():
    entry = next(e for e in PUBLIC["entries"] if e["id"] == "edge.unknown-fallback")
    assert entry["classification"] == "RETIRED_FAIL_CLOSED"
    assert entry["legacy_fallback"] is False
    assert entry["caddy_upstream"] == "NONE"
    assert "reverse_proxy {$CADDY_LEGACY_API_UPSTREAM}" not in API_SITE
    assert "Unknown public API paths fail closed" in API_SITE

def test_webhooks_have_exact_methods_and_explicit_owners():
    assert WEBHOOKS["entries"]
    for entry in WEBHOOKS["entries"]:
        assert entry["methods"] == ["POST"]
        assert entry["gateway"] == "ingtrader21-spec/Kong"
        assert entry["downstream_owner"] == "ingtrader21-spec/Middleware-"
        assert entry["identity_gate_owner"]
        assert entry["replay_protection_owner"]
        assert entry["log_redaction"]


def test_pending_webhooks_are_not_misrepresented_as_canonical():
    by_id = {entry["id"]: entry for entry in WEBHOOKS["entries"]}
    assert by_id["webhook.telnexa"]["classification"] == "TRANSITIONAL_PENDING_CONTRACT"
    assert by_id["webhook.vicidial-call-result"]["classification"] == "TRANSITIONAL_PENDING_CONTRACT"


def test_digest_chain_pins_current_middleware_and_repinned_kong():
    expected = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
    assert CHAIN["middleware"]["source_sha"] == "2862af0aa97367b18cb360af69212abe4243a1ac"
    assert CHAIN["middleware"]["public_contract_sha256"] == expected
    # Kong protected main repinned the final Middleware contract; the chain must
    # record that head and carry the same digest on both sides of the handoff.
    assert CHAIN["kong"]["source_sha"] == "3e68cb2a4955bd71ddb3e839f4d9e3770465fc08"
    assert CHAIN["kong"]["required_sha256"] == expected
    assert CHAIN["kong"]["middleware_contract_sha256"] == expected
    assert CHAIN["kong"]["status"] == "PASS"


def test_digest_chain_postman_digest_matches_committed_collection():
    collection = ROOT / CHAIN["postman"]["collection"]
    # The collection is committed with LF endings; normalise so an autocrlf
    # checkout still hashes the committed bytes.
    material = collection.read_bytes().replace(b"\r\n", b"\n")
    assert CHAIN["postman"]["sha256"] == hashlib.sha256(material).hexdigest()


def test_pending_contract_paths_fail_closed_before_legacy_fallback():
    marker = "@pending_contract path /api/v1/events/telnexa /api/v1/n8n/acknowledgements /v1/observability/incidents /v1/observability/kpis /webhooks/sms/inbound/* /webhooks/vicidial/call-result/*"
    assert marker in API_SITE
    pending = [entry for entry in PUBLIC["entries"] if entry["classification"] == "DENIED_PENDING_CONTRACT"]
    assert len(pending) >= 5
    assert all(entry["expected_public_status"] == 404 for entry in pending)
    assert all(entry["legacy_fallback"] is False for entry in pending)
