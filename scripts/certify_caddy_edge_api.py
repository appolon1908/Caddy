#!/usr/bin/env python3
"""PAS-145 source/adapted-JSON/Postman edge certification.

This validator never reloads or deploys Caddy. It consumes the exact adapted
JSON produced by a real Caddy binary plus the checked-in registries/Postman
artifacts and proves the edge transport/private/webhook invariants owned by
PAS-145.

PAS-162 owns the digest-chain source of truth. During parallel work,
--allow-pending-pas162 permits the known stale Kong/Postman chain bindings while
still requiring every PAS-145-owned gate to pass. Strict final certification
omits that flag.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

import caddy_v3_edge_probe as edge_probe

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PATH = ROOT / "config" / "public-edge-registry.v1.json"
WEBHOOK_PATH = ROOT / "config" / "webhook-edge-registry.v1.json"
CHAIN_PATH = ROOT / "config" / "edge-contract-chain.v1.json"
COLLECTION_PATH = ROOT / "postman" / "Caddy-V3-Edge-Certification.postman_collection.json"
ENV_PATH = ROOT / "postman" / "Caddy-V3-Edge-Certification.postman_environment.json"


class CertificationError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CertificationError(f"{path} must contain a JSON object")
    return value


def sha256_file(path: Path) -> str:
    # Git stores these certification artifacts with LF line endings. Normalize
    # CRLF checkouts so Windows/Appolon and Linux CI hash the same committed text.
    material = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(material).hexdigest()


def flatten_items(items: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for item in items:
        nested = item.get("item")
        if isinstance(nested, list):
            yield from flatten_items(nested)
        else:
            yield item


def request_path(request: dict[str, Any]) -> str:
    url = request.get("url")
    if isinstance(url, str):
        prefix = "{{base_url}}"
        return url[len(prefix):] if url.startswith(prefix) else url
    if isinstance(url, dict):
        raw = str(url.get("raw", ""))
        prefix = "{{base_url}}"
        return raw[len(prefix):] if raw.startswith(prefix) else raw
    return ""


def has_status_assertion(item: dict[str, Any], statuses: set[int]) -> bool:
    scripts: list[str] = []
    for event in item.get("event", []):
        script = event.get("script") or {}
        scripts.extend(str(line) for line in script.get("exec", []))
    text = "\n".join(scripts)
    return all(str(status) in text for status in statuses) if len(statuses) > 1 else any(
        str(status) in text for status in statuses
    )


def validate_registries(public: dict[str, Any], webhooks: dict[str, Any]) -> dict[str, Any]:
    entries = public.get("entries")
    if not isinstance(entries, list):
        raise CertificationError("public edge registry entries missing")
    by_id = {str(row.get("id")): row for row in entries}

    required_canonical = {
        "edge.platform-v1": "/platform/v1/*",
        "edge.automation-v2": "/v2/automation/*",
        "edge.odoo-event": "/api/v1/odoo/events",
        "edge.n8n-results": "/api/v1/integrations/n8n/results*",
    }
    for edge_id, path in required_canonical.items():
        row = by_id.get(edge_id)
        if not row:
            raise CertificationError(f"missing canonical edge registry row: {edge_id}")
        if row.get("path") != path:
            raise CertificationError(f"{edge_id} path drift")
        if row.get("classification") != "CANONICAL":
            raise CertificationError(f"{edge_id} is not canonical")
        if row.get("gateway") != "ingtrader21-spec/Kong":
            raise CertificationError(f"{edge_id} does not route through Kong")
        if row.get("caddy_upstream") != "CADDY_KONG_UPSTREAM":
            raise CertificationError(f"{edge_id} has non-Kong Caddy upstream")
        if row.get("legacy_fallback") is not False:
            raise CertificationError(f"{edge_id} may reach legacy fallback")

    for edge_id in ("edge.private-internal", "edge.private-metrics"):
        row = by_id.get(edge_id)
        if not row or row.get("classification") != "PRIVATE":
            raise CertificationError(f"private registry row missing: {edge_id}")
        if row.get("expected_public_status") != 404:
            raise CertificationError(f"{edge_id} must be public 404")
        if row.get("gateway") != "NONE" or row.get("caddy_upstream") != "NONE":
            raise CertificationError(f"{edge_id} unexpectedly exposes an upstream")

    forbidden = {str(row.get("name")) for row in public.get("forbidden_public_destinations", [])}
    required_forbidden = {"postgresql", "redis", "nats", "temporal", "openbao-internal"}
    if not required_forbidden <= forbidden:
        raise CertificationError(
            f"database/control-plane public denial incomplete: {sorted(required_forbidden - forbidden)}"
        )

    pending = [
        row
        for row in entries
        if row.get("classification") == "DENIED_PENDING_CONTRACT"
    ]
    if not pending:
        raise CertificationError("pending-contract denial rows missing")
    for row in pending:
        if row.get("expected_public_status") != 404:
            raise CertificationError(f"pending route not 404: {row.get('id')}")
        if row.get("legacy_fallback") is not False:
            raise CertificationError(f"pending route may reach legacy: {row.get('id')}")

    webhook_rows = webhooks.get("entries")
    if not isinstance(webhook_rows, list) or not webhook_rows:
        raise CertificationError("webhook registry entries missing")
    for row in webhook_rows:
        if row.get("methods") != ["POST"]:
            raise CertificationError(f"webhook method drift: {row.get('id')}")
        if row.get("gateway") != "ingtrader21-spec/Kong":
            raise CertificationError(f"webhook bypasses Kong: {row.get('id')}")
        if row.get("downstream_owner") != "ingtrader21-spec/Middleware-":
            raise CertificationError(f"webhook downstream owner drift: {row.get('id')}")
        for field in (
            "identity_gate_owner",
            "replay_protection_owner",
            "log_redaction",
            "maximum_body_size",
        ):
            if not row.get(field):
                raise CertificationError(f"webhook {row.get('id')} missing {field}")

    unknown = by_id.get("edge.unknown-fallback")
    if not unknown or unknown.get("classification") != "RETIRED_FAIL_CLOSED":
        raise CertificationError("unknown fallback must remain retired fail-closed")
    if unknown.get("legacy_fallback") is not False or unknown.get("caddy_upstream") != "NONE":
        raise CertificationError("unknown fallback retirement state changed unexpectedly")

    return {
        "canonical": len(required_canonical),
        "pending": len(pending),
        "webhooks": len(webhook_rows),
        "database_public_exposure": 0,
    }


def validate_adapted(document: dict[str, Any], kong_upstream: str) -> dict[str, Any]:
    results = edge_probe.probe_edge(document, kong_upstream)
    failures = [result for result in results if not result.ok]
    if failures:
        rendered = "; ".join(
            f"{row.group}:{row.method}:{row.path}->{row.resolution.upstream or row.resolution.response_status}"
            for row in failures
        )
        raise CertificationError(f"adapted edge probe failures: {rendered}")

    header_violations = edge_probe.header_policy_violations(document)
    if header_violations:
        raise CertificationError("header policy violations: " + ",".join(header_violations))

    canonical = [row for row in results if row.group in {"V3_KERNEL", "FAMILY"}]
    if any(row.resolution.upstream != kong_upstream for row in canonical):
        raise CertificationError("canonical API has non-Kong upstream")

    return {
        "probe_count": len(results),
        "header_violations": 0,
        "public_api_direct_to_middleware": 0,
        "public_api_direct_to_odoo": 0,
        "public_api_direct_to_n8n": 0,
        "failure_bypass_paths": 0,
    }


def validate_postman(collection: dict[str, Any], environment: dict[str, Any]) -> dict[str, Any]:
    values = {str(row.get("key")): row.get("value") for row in environment.get("values", [])}
    if values.get("RUN_CADDY_EDGE_CERTIFICATION") != "false":
        raise CertificationError("Postman live-run flag must default false")
    base_url = str(values.get("base_url", ""))
    if not base_url.startswith("https://127.0.0.1:"):
        raise CertificationError("Postman safe environment base_url must be loopback")
    for token_key in ("access_token", "wrong_scope_token", "wrong_audience_token"):
        if values.get(token_key) not in ("", None):
            raise CertificationError(f"Postman environment embeds token material: {token_key}")

    items = list(flatten_items(collection.get("item", [])))
    by_request: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        request = item.get("request") or {}
        key = (str(request.get("method", "")).upper(), request_path(request))
        by_request.setdefault(key, []).append(item)

    required_api = {
        ("GET", "/platform/v1/kernel/describe"),
        ("POST", "/v2/automation/commands"),
    }
    missing_api = sorted(required_api - set(by_request))
    if missing_api:
        raise CertificationError(f"Postman API probes missing: {missing_api}")

    private_required = {
        ("GET", "/metrics"),
        ("GET", "/metrics/runtime"),
        ("GET", "/internal/v1/authorization/check"),
        ("GET", "/internal/v1/database/health"),
        ("GET", "/internal/v1/database/schema"),
        ("GET", "/internal/v1/database/backups"),
    }
    for key in private_required:
        candidates = by_request.get(key)
        if not candidates or not any(has_status_assertion(item, {404}) for item in candidates):
            raise CertificationError(f"Postman private 404 assertion missing: {key}")

    webhook_wrong_methods = {
        ("GET", "/api/v1/odoo/events"),
        ("GET", "/api/v1/integrations/n8n/results"),
    }
    missing_webhook_wrong_methods = sorted(webhook_wrong_methods - set(by_request))
    if missing_webhook_wrong_methods:
        raise CertificationError(
            f"Postman webhook wrong-method probes missing: {missing_webhook_wrong_methods}"
        )

    pending_required = {
        ("POST", "/api/v1/events/telnexa"),
        ("POST", "/webhooks/vicidial/call-result/"),
        ("POST", "/api/v1/n8n/acknowledgements"),
    }
    for key in pending_required:
        candidates = by_request.get(key)
        if not candidates or not any(has_status_assertion(item, {404}) for item in candidates):
            raise CertificationError(f"Postman pending-contract 404 assertion missing: {key}")

    unknown_probe = ("GET", "/__caddy_unclassified_probe__")
    candidates = by_request.get(unknown_probe)
    if not candidates or not any(has_status_assertion(item, {404}) for item in candidates):
        raise CertificationError("Postman fail-closed unknown-route 404 assertion missing")

    return {
        "api": "PASS",
        "webhook": "PASS",
        "private": "PASS",
        "pending_count": len(pending_required),
        "webhook_wrong_method_count": len(webhook_wrong_methods),
        "safe_environment": "PASS",
    }


def chain_state(chain: dict[str, Any], postman_sha256: str) -> dict[str, Any]:
    middleware_digest = str(chain.get("middleware", {}).get("public_contract_sha256", ""))
    kong_digest = str(chain.get("kong", {}).get("middleware_contract_sha256", ""))
    required_digest = str(chain.get("kong", {}).get("required_sha256", ""))
    recorded_postman = str(chain.get("postman", {}).get("sha256", ""))
    digest_match = bool(middleware_digest) and middleware_digest == kong_digest == required_digest
    postman_match = bool(recorded_postman) and recorded_postman == postman_sha256
    return {
        "digest_match": digest_match,
        "postman_match": postman_match,
        "middleware_digest": middleware_digest,
        "kong_digest": kong_digest,
        "required_digest": required_digest,
        "recorded_postman_sha256": recorded_postman,
        "actual_postman_sha256": postman_sha256,
    }


def certify(
    *,
    adapted_json: Path,
    kong_upstream: str,
    allow_pending_pas162: bool,
) -> dict[str, Any]:
    public = load_json(PUBLIC_PATH)
    webhooks = load_json(WEBHOOK_PATH)
    chain = load_json(CHAIN_PATH)
    collection = load_json(COLLECTION_PATH)
    environment = load_json(ENV_PATH)
    document = load_json(adapted_json)

    registries = validate_registries(public, webhooks)
    adapted = validate_adapted(document, kong_upstream)
    postman = validate_postman(collection, environment)
    chain_report = chain_state(chain, sha256_file(COLLECTION_PATH))

    chain_pass = chain_report["digest_match"] and chain_report["postman_match"]
    if not chain_pass and not allow_pending_pas162:
        raise CertificationError(
            "PAS-162 digest-chain authority is not final: "
            f"middleware={chain_report['middleware_digest']} "
            f"kong={chain_report['kong_digest']} "
            f"required={chain_report['required_digest']} "
            f"postman_recorded={chain_report['recorded_postman_sha256']} "
            f"postman_actual={chain_report['actual_postman_sha256']}"
        )

    return {
        "verdict": "PASS" if chain_pass else "PENDING_PAS_162",
        "registries": registries,
        "adapted": adapted,
        "postman": postman,
        "chain": chain_report,
        "unknown_route_fallback": "ZERO_FAIL_CLOSED",
        "runtime_reload_authorized": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adapted_json", type=Path)
    parser.add_argument("--kong-upstream", required=True)
    parser.add_argument("--allow-pending-pas162", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = certify(
            adapted_json=args.adapted_json.resolve(),
            kong_upstream=args.kong_upstream,
            allow_pending_pas162=args.allow_pending_pas162,
        )
    except CertificationError as exc:
        print("CADDY_EDGE_API_CERTIFICATION=FAIL")
        print(f"ERROR={exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"CADDY_EDGE_API_CERTIFICATION={report['verdict']}")
        print("API_URL_REGISTRY=PASS")
        print("PUBLIC_HOST_REGISTRY=PASS")
        print("UPSTREAM_REGISTRY=PASS")
        print("WEBHOOK_REGISTRY=PASS")
        print("PLATFORM_V1_TO_KONG=PASS")
        print("AUTOMATION_V2_TO_KONG=PASS")
        print("PRIVATE_NAMESPACE_DENIAL=PASS")
        print("DATABASE_PUBLIC_EXPOSURE=0")
        print("SPOOFED_IDENTITY_HEADERS_STRIPPED=PASS")
        print("PRESERVED_TRANSPORT_HEADERS=PASS")
        print("PUBLIC_API_DIRECT_TO_MIDDLEWARE=0")
        print("PUBLIC_API_DIRECT_TO_ODOO=0")
        print("PUBLIC_API_DIRECT_TO_N8N=0")
        print("FAILURE_BYPASS_PATHS=0")
        print("POSTMAN_API_CERTIFICATION=PASS")
        print("POSTMAN_WEBHOOK_CERTIFICATION=PASS")
        print("POSTMAN_PRIVATE_ROUTE_CERTIFICATION=PASS")
        print(
            "MIDDLEWARE_KONG_CADDY_DIGEST_CHAIN="
            + ("PASS" if report["chain"]["digest_match"] else "PENDING_PAS_162")
        )
        print(
            "POSTMAN_DIGEST_CHAIN="
            + ("PASS" if report["chain"]["postman_match"] else "PENDING_PAS_162")
        )
        print("UNKNOWN_ROUTE_FALLBACK_ZERO=YES")
        print("CADDY_LIVE_RELOAD_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
