#!/usr/bin/env python3
"""Generate/check PAS-145 Caddy Postman artifacts deterministically.

The checked-in source manifest is a stable, secret-free Postman definition.
Rendering it with the repository-owned formatter must reproduce the exact
collection bytes pinned by PAS-162. The safe-local environment is generated
separately and is not part of the edge digest-chain authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "postman" / "Caddy-V3-Edge-Certification.source.json"
COLLECTION_PATH = ROOT / "postman" / "Caddy-V3-Edge-Certification.postman_collection.json"
ENV_PATH = ROOT / "postman" / "Caddy-V3-Edge-Certification.postman_environment.json"
PUBLIC_PATH = ROOT / "config" / "public-edge-registry.v1.json"
WEBHOOK_PATH = ROOT / "config" / "webhook-edge-registry.v1.json"


class GenerationError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenerationError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GenerationError(f"{path} must contain a JSON object")
    return value


def dump(value: Any) -> str:
    # Keep insertion order and exact two-space formatting. PAS-162 pins the
    # resulting collection SHA-256, so formatting is part of the evidence.
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def flatten_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for item in items:
        nested = item.get("item")
        if isinstance(nested, list):
            flattened.extend(flatten_items(nested))
        else:
            flattened.append(item)
    return flattened


def request_path(request: dict[str, Any]) -> str:
    url = request.get("url")
    if isinstance(url, str):
        prefix = "{{base_url}}"
        return url[len(prefix):] if url.startswith(prefix) else url
    return ""


def validate_source(
    collection: dict[str, Any],
    public: dict[str, Any],
    webhooks: dict[str, Any],
) -> None:
    items = flatten_items(collection.get("item", []))
    requests = {
        (str((item.get("request") or {}).get("method", "")).upper(), request_path(item.get("request") or {}))
        for item in items
    }

    required = {
        ("GET", "/platform/v1/kernel/describe"),
        ("POST", "/v2/automation/commands"),
        ("GET", "/internal/v1/authorization/check"),
        ("GET", "/metrics"),
        ("GET", "/metrics/runtime"),
        ("GET", "/internal/v1/database/health"),
        ("GET", "/internal/v1/database/schema"),
        ("GET", "/internal/v1/database/backups"),
        ("GET", "/api/v1/integrations/n8n/results"),
        ("GET", "/api/v1/odoo/events"),
        ("POST", "/api/v1/events/telnexa"),
        ("POST", "/webhooks/vicidial/call-result/"),
        ("POST", "/api/v1/n8n/acknowledgements"),
        ("GET", "/__codestra_unknown_route_probe__"),
    }
    missing = sorted(required - requests)
    if missing:
        raise GenerationError(f"Postman source coverage missing: {missing}")

    public_entries = public.get("entries") or []
    private_paths = {str(row.get("path")) for row in public_entries if row.get("classification") == "PRIVATE"}
    if not {"/metrics*", "/internal", "/internal/*"} <= private_paths:
        raise GenerationError("private-route registry does not support Postman source")

    unknown = [row for row in public_entries if row.get("classification") == "DENIED_UNKNOWN_ROUTE"]
    if len(unknown) != 1 or unknown[0].get("caddy_upstream") != "NONE" or unknown[0].get("expected_public_status") != 404:
        raise GenerationError("unknown-route registry must be a single fail-closed 404 with no upstream")

    pending_paths = {
        str(row.get("path"))
        for row in public_entries
        if row.get("classification") == "DENIED_PENDING_CONTRACT"
    }
    for path in ("/api/v1/events/telnexa", "/webhooks/vicidial/call-result/*", "/api/v1/n8n/acknowledgements"):
        if path not in pending_paths:
            raise GenerationError(f"pending route missing from public registry: {path}")

    webhook_paths = {str(row.get("path")) for row in webhooks.get("entries") or []}
    if not {"/api/v1/integrations/n8n/results", "/api/v1/odoo/events"} <= webhook_paths:
        raise GenerationError("canonical webhook source coverage drift")


def render_collection() -> dict[str, Any]:
    collection = load_json(SOURCE_PATH)
    validate_source(collection, load_json(PUBLIC_PATH), load_json(WEBHOOK_PATH))
    return collection


def render_environment() -> dict[str, Any]:
    values = [
        ("base_url", "https://127.0.0.1:9443"),
        ("RUN_CADDY_EDGE_CERTIFICATION", "false"),
        ("access_token", ""),
        ("wrong_scope_token", ""),
        ("wrong_audience_token", ""),
        ("tenant_id", "TEST_SYN"),
        ("correlation_id", "TEST_SYN-caddy-edge"),
        ("idempotency_key", ""),
        ("operation_id", "OP-TEST-SYN-0001"),
    ]
    return {
        "id": "caddy-pas145-safe-local-env-v1",
        "name": "Caddy V3 Edge Certification - Safe Local",
        "values": [
            {"key": key, "value": value, "enabled": True}
            for key, value in values
        ],
        "_postman_variable_scope": "environment",
        "_postman_exported_using": "Codestra PAS-145 deterministic generator",
    }


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump(value), encoding="utf-8", newline="\n")


def check(path: Path, value: Any) -> None:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if current.replace("\r\n", "\n") != dump(value):
        raise GenerationError(f"generated artifact is stale: {path.relative_to(ROOT)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    try:
        collection = render_collection()
        environment = render_environment()
        if args.write:
            write(COLLECTION_PATH, collection)
            write(ENV_PATH, environment)
        if args.check:
            check(COLLECTION_PATH, collection)
            check(ENV_PATH, environment)
    except GenerationError as exc:
        print("CADDY_POSTMAN_GENERATION=FAIL")
        print(f"ERROR={exc}")
        return 1

    print("CADDY_POSTMAN_GENERATION=PASS")
    print(f"SOURCE={SOURCE_PATH.relative_to(ROOT).as_posix()}")
    print(f"COLLECTION={COLLECTION_PATH.relative_to(ROOT).as_posix()}")
    print(f"ENVIRONMENT={ENV_PATH.relative_to(ROOT).as_posix()}")
    print("LIVE_RUN_DEFAULT=FALSE")
    print("DEFAULT_BASE_URL=https://127.0.0.1:9443")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
