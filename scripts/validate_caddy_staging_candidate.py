#!/usr/bin/env python3
"""Validate PAS-146 Caddy staging/reload/rollback preparation.

This validator is deliberately source-only. It proves that the prepared
candidate is immutable, fail-closed, and blocked from runtime execution until
the Linear/GitHub prerequisites are accepted. It never reloads Caddy, changes
DNS/TLS, contacts a provider, or performs a production write.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from mission5_desired_state import configuration_sha256, desired_state_material

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "release" / "pas146" / "caddy-staging-candidate.v1.json"
EVIDENCE_PATH = ROOT / "release" / "pas146" / "caddy-staging-evidence.template.v1.json"

EXPECTED_PREPARATION_PR = 179
EXPECTED_PR_HEAD = "8a0ff7f45e5b50750a603a9e653ff2687e25361a"
EXPECTED_MERGED_MAIN_SHA = "22c6d51ed2f5340139177131fb810e787f0f7550"
EXPECTED_CADDY_IMAGE = (
    "docker.io/library/caddy@sha256:"
    "ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c"
)
EXPECTED_CADDY_DIGEST = (
    "sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c"
)
EXPECTED_CADDY_VERSION = "v2.10.0"
EXPECTED_MIDDLEWARE_SHA = "bd406a6508c8095a3f23b35149a2eebcb94c94c6"
EXPECTED_MIDDLEWARE_CONTRACT = (
    "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
)
EXPECTED_KONG_SHA = "3e68cb2a4955bd71ddb3e839f4d9e3770465fc08"
EXPECTED_GATE_NAMES = {
    "PAS-162",
    "PAS-145",
    "PR179_EXACT_HEAD_CI",
    "PR179_INDEPENDENT_APPROVAL",
    "PR179_MERGED",
    "MERGED_CADDY_MAIN_SHA",
    "INFRA126_REUSABLE_DEPLOY_READINESS_ACCEPTED",
    "CADDY_MAIN_DEPLOY_READINESS_GREEN",
    "PR181_SOURCE_HYGIENE_MERGED",
    "PAS-178_PROTECTED_MAIN_ENFORCEMENT",
}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class StagingPreparationError(ValueError):
    """PAS-146 preparation is incomplete or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StagingPreparationError(message)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.name} must contain an object")
    return value


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_candidate(candidate: dict[str, Any]) -> None:
    require(candidate.get("schema_version") == 1, "candidate schema version drift")
    require(
        candidate.get("kind") == "caddy-staging-candidate-preparation",
        "candidate kind drift",
    )
    require(candidate.get("status") == "PREPARED_BLOCKED", "candidate must stay blocked")

    prepared = candidate.get("prepared_from", {})
    require(prepared.get("repository") == "ingtrader21-spec/Caddy", "repository drift")
    require(prepared.get("pull_request") == EXPECTED_PREPARATION_PR, "PR source drift")
    require(prepared.get("pr_head_sha") == EXPECTED_PR_HEAD, "prepared PR head drift")
    require(SHA40.fullmatch(prepared["pr_head_sha"]) is not None, "PR head must be full SHA")
    require(
        prepared.get("merged_main_sha") == EXPECTED_MERGED_MAIN_SHA,
        "merged main SHA must match protected main after PR #175 merge",
    )

    runtime = candidate.get("immutable_runtime", {})
    require(runtime.get("caddy_version") == EXPECTED_CADDY_VERSION, "Caddy version drift")
    require(runtime.get("image_reference") == EXPECTED_CADDY_IMAGE, "immutable image drift")
    require(runtime.get("image_digest") == EXPECTED_CADDY_DIGEST, "Caddy image digest drift")
    require(DIGEST.fullmatch(runtime["image_digest"]) is not None, "invalid Caddy digest")
    require("@sha256:" in runtime["image_reference"], "Caddy image must be digest-pinned")
    require(runtime.get("mutable_tags_allowed") is False, "mutable Caddy tags are forbidden")

    configuration = candidate.get("configuration", {})
    observed_config = configuration_sha256(desired_state_material(ROOT))
    require(
        configuration.get("configuration_sha256") == observed_config,
        "prepared configuration SHA-256 does not match repository desired state",
    )
    require(
        SHA256.fullmatch(configuration["configuration_sha256"]) is not None,
        "invalid configuration SHA-256",
    )
    for flag in ("format_required", "adapt_required", "validate_required"):
        require(configuration.get(flag) is True, f"{flag} must be true")

    authorities = candidate.get("external_authorities", {})
    middleware = authorities.get("middleware", {})
    require(middleware.get("source_sha") == EXPECTED_MIDDLEWARE_SHA, "Middleware SHA drift")
    require(
        middleware.get("public_contract_sha256") == EXPECTED_MIDDLEWARE_CONTRACT,
        "Middleware contract digest drift",
    )
    require(middleware.get("port") == 8095, "canonical Middleware port must be 8095")
    kong = authorities.get("kong", {})
    require(kong.get("required_source_sha") == EXPECTED_KONG_SHA, "Kong SHA drift")
    require(
        kong.get("required_middleware_contract_sha256") == EXPECTED_MIDDLEWARE_CONTRACT,
        "Kong must require final Middleware contract digest",
    )
    keycloak = authorities.get("keycloak", {})
    keycloak_sha = keycloak.get("required_source_sha")
    require(
        isinstance(keycloak_sha, str) and SHA40.fullmatch(keycloak_sha) is not None,
        "Keycloak source authority must be a full lowercase Git SHA",
    )

    gate = candidate.get("execution_start_gate", {})
    require(
        gate.get("must_be_recomputed_immediately_before_runtime_action") is True,
        "start gate must be recomputed before runtime action",
    )
    require(gate.get("all_required") is True, "all ten start gates must be required")
    rows = gate.get("observed_at_preparation", [])
    require(isinstance(rows, list) and len(rows) == 10, "exactly ten start gates required")
    require({row.get("gate") for row in rows} == EXPECTED_GATE_NAMES, "start-gate set drift")
    all_satisfied = all(row.get("satisfied") is True for row in rows)
    require(not all_satisfied, "preparation snapshot must not claim all execution gates passed")

    chain = candidate.get("staging_chain")
    require(
        chain == ["Caddy staging", "Kong", "Middleware :8095", "TEST_SYN"],
        "staging chain drift",
    )

    evidence = candidate.get("required_runtime_evidence", {})
    for group in ("tls_acme", "transport", "negative_paths", "operations"):
        require(isinstance(evidence.get(group), list) and evidence[group], f"{group} evidence missing")

    reload_policy = candidate.get("reload_policy", {})
    for key in (
        "pre_validation_required",
        "last_known_good_snapshot_required",
        "configuration_hash_match_required",
        "health_before_required",
        "health_after_required",
        "automatic_fallback_to_unknown_route_forbidden",
    ):
        require(reload_policy.get(key) is True, f"reload policy {key} must be true")

    rollback = candidate.get("rollback_policy", {})
    for key in (
        "rehearsal_required",
        "restore_last_known_good_required",
        "post_restore_validate_required",
        "post_restore_health_required",
        "rollback_evidence_required",
    ):
        require(rollback.get(key) is True, f"rollback policy {key} must be true")

    canary = candidate.get("canary_policy", {})
    require(canary.get("mode") == "READ_ONLY_NO_EFFECT", "canary must be read-only/no-effect")
    for key in (
        "provider_effects_allowed",
        "business_writes_allowed",
        "pstn_allowed",
        "payments_allowed",
        "production_write_activation_allowed",
    ):
        require(canary.get(key) is False, f"canary effect {key} must remain false")

    production = candidate.get("production_gate", {})
    require(production.get("unknown_route_fallback_required") == 0, "production requires zero unknown fallback")
    require(
        production.get("observed_unknown_route_fallback") == "ZERO",
        "preparation must record transitional unknown fallback honestly",
    )
    require(production.get("unclassified_public_routes_required") == 0, "unclassified public routes must reach zero")
    require(production.get("unclassified_webhooks_required") == 0, "unclassified webhooks must reach zero")
    require(production.get("unclassified_upstreams_required") == 0, "unclassified upstreams must reach zero")
    require(production.get("production_go") is False, "production GO must remain false")

    auth = candidate.get("authorization", {})
    require(auth.get("staging_execution_authorized") is False, "staging execution cannot be pre-authorized")
    require(auth.get("production_canary_authorized") is False, "production canary cannot be pre-authorized")
    require(auth.get("production_go") is False, "production GO cannot be pre-authorized")
    if not all_satisfied:
        require(
            auth.get("staging_execution_authorized") is False,
            "runtime execution cannot be authorized with unsatisfied gates",
        )


def validate_evidence_template(evidence: dict[str, Any]) -> None:
    require(evidence.get("schema_version") == 1, "evidence schema version drift")
    require(
        evidence.get("kind") == "caddy-staging-certification-evidence",
        "evidence kind drift",
    )
    require(
        evidence.get("status") == "TEMPLATE_PENDING_EXECUTION",
        "evidence template cannot claim execution",
    )
    candidate = evidence.get("candidate", {})
    require(candidate.get("caddy_image_reference") == EXPECTED_CADDY_IMAGE, "evidence image drift")
    require(candidate.get("caddy_version") == EXPECTED_CADDY_VERSION, "evidence Caddy version drift")
    require(
        candidate.get("merged_caddy_source_sha") == "REQUIRED_AT_EXECUTION",
        "evidence template must defer runtime source pin until execution",
    )

    for section in ("reload", "restart"):
        require(evidence.get(section, {}).get("attempted") is False, f"{section} must not be attempted")
    require(evidence.get("rollback", {}).get("rehearsed") is False, "rollback must remain pending")

    effects = evidence.get("effects", {})
    require(
        effects
        == {
            "provider_effects": 0,
            "business_writes": 0,
            "pstn_calls": 0,
            "payments": 0,
            "production_writes": 0,
        },
        "evidence effect counters must all be zero",
    )

    gate = evidence.get("production_gate", {})
    for key in (
        "unknown_route_fallback_zero",
        "unclassified_public_routes_zero",
        "unclassified_webhooks_zero",
        "unclassified_upstreams_zero",
        "production_go",
    ):
        require(gate.get(key) is False, f"template must not pre-certify {key}")
    require(evidence.get("verdict") == "NO_GO", "template verdict must be NO_GO")


def validate() -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = load_json(CANDIDATE_PATH)
    evidence = load_json(EVIDENCE_PATH)
    validate_candidate(candidate)
    validate_evidence_template(evidence)
    return candidate, evidence


def main() -> int:
    candidate, _ = validate()
    gates = candidate["execution_start_gate"]["observed_at_preparation"]
    print("PAS146_PREPARATION=PASS")
    print(f"PREPARED_FROM_PR_HEAD={candidate['prepared_from']['pr_head_sha']}")
    print(f"IMMUTABLE_CADDY_IMAGE={candidate['immutable_runtime']['image_reference']}")
    print(f"CADDY_VERSION={candidate['immutable_runtime']['caddy_version']}")
    print(f"CONFIGURATION_SHA256={candidate['configuration']['configuration_sha256']}")
    print(f"PREPARATION_RECORD_SHA256={file_sha256(CANDIDATE_PATH)}")
    print(f"EVIDENCE_TEMPLATE_SHA256={file_sha256(EVIDENCE_PATH)}")
    print(f"START_GATES_SATISFIED={sum(row['satisfied'] is True for row in gates)}/10")
    print("STAGING_EXECUTION_AUTHORIZED=NO")
    print("PRODUCTION_CANARY_AUTHORIZED=NO")
    print("UNKNOWN_ROUTE_FALLBACK_ZERO=YES")
    print("PROVIDER_EFFECTS=0")
    print("BUSINESS_WRITES=0")
    print("PRODUCTION_GO=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
