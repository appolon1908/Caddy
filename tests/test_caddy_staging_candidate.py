from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_caddy_staging_candidate.py"
SPEC = importlib.util.spec_from_file_location("caddy_pas146_validator", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


@pytest.fixture
def documents() -> tuple[dict, dict]:
    return (
        validator.load_json(validator.CANDIDATE_PATH),
        validator.load_json(validator.EVIDENCE_PATH),
    )


def expect_candidate_failure(candidate: dict, match: str) -> None:
    with pytest.raises(validator.StagingPreparationError, match=match):
        validator.validate_candidate(candidate)


def expect_evidence_failure(evidence: dict, match: str) -> None:
    with pytest.raises(validator.StagingPreparationError, match=match):
        validator.validate_evidence_template(evidence)


def test_pas146_preparation_is_valid_and_execution_remains_blocked(documents):
    candidate, evidence = documents
    validator.validate_candidate(candidate)
    validator.validate_evidence_template(evidence)
    assert candidate["status"] == "PREPARED_BLOCKED"
    assert candidate["authorization"]["staging_execution_authorized"] is False
    assert candidate["authorization"]["production_canary_authorized"] is False
    assert candidate["authorization"]["production_go"] is False
    assert evidence["verdict"] == "NO_GO"


def test_immutable_caddy_image_must_be_digest_pinned(documents):
    candidate, _ = documents
    assert candidate["immutable_runtime"]["image_reference"] == validator.EXPECTED_CADDY_IMAGE

    mutable = copy.deepcopy(candidate)
    mutable["immutable_runtime"]["image_reference"] = "docker.io/library/caddy:2.10.0"
    expect_candidate_failure(mutable, "immutable image drift|digest-pinned")

    mutable_flag = copy.deepcopy(candidate)
    mutable_flag["immutable_runtime"]["mutable_tags_allowed"] = True
    expect_candidate_failure(mutable_flag, "mutable Caddy tags")


def test_configuration_digest_matches_exact_desired_state(documents):
    candidate, _ = documents
    assert candidate["configuration"]["configuration_sha256"] == "ffe4d651d67ac4cad35c7a5f56555fabb1f9fe05e9b7fd935cee37c1a4777bc0"

    tampered = copy.deepcopy(candidate)
    tampered["configuration"]["configuration_sha256"] = "0" * 64
    expect_candidate_failure(tampered, "does not match repository desired state")


def test_all_ten_runtime_start_gates_are_required_and_live_execution_is_not_preapproved(documents):
    candidate, _ = documents
    rows = candidate["execution_start_gate"]["observed_at_preparation"]
    assert {row["gate"] for row in rows} == validator.EXPECTED_GATE_NAMES
    assert len(rows) == 10
    assert sum(row["satisfied"] is True for row in rows) == 8

    missing = copy.deepcopy(candidate)
    missing["execution_start_gate"]["observed_at_preparation"].pop()
    expect_candidate_failure(missing, "exactly ten start gates")

    prematurely_green = copy.deepcopy(candidate)
    for row in prematurely_green["execution_start_gate"]["observed_at_preparation"]:
        row["satisfied"] = True
    expect_candidate_failure(prematurely_green, "must not claim all execution gates passed")


def test_current_pre_staging_blockers_are_exactly_the_two_live_gates(documents):
    candidate, _ = documents
    prepared = candidate["prepared_from"]
    assert prepared["pull_request"] == validator.EXPECTED_PREPARATION_PR
    assert prepared["pr_head_sha"] == validator.EXPECTED_PR_HEAD
    assert prepared["merged_main_sha"] == validator.EXPECTED_MERGED_MAIN_SHA

    rows = {
        row["gate"]: row
        for row in candidate["execution_start_gate"]["observed_at_preparation"]
    }
    unsatisfied = {
        gate
        for gate, row in rows.items()
        if row["satisfied"] is not True
    }
    assert unsatisfied == {
        "CADDY_MAIN_DEPLOY_READINESS_GREEN",
        "PR181_SOURCE_HYGIENE_MERGED",
    }
    assert rows["INFRA126_REUSABLE_DEPLOY_READINESS_ACCEPTED"]["observed"] == (
        "MERGED_5B8CDBB_INDEPENDENT_APPROVAL"
    )
    assert rows["CADDY_MAIN_DEPLOY_READINESS_GREEN"]["observed"] == (
        "PR183_REPIN_SOURCE_AUTHORITY_GREEN_DEPLOY_READINESS_STARTUP_FAILURE"
    )
    assert rows["PR181_SOURCE_HYGIENE_MERGED"]["observed"] == (
        "OPEN_LOCAL_PASS_HOSTED_ZERO_STEP_FAILURE"
    )
    assert rows["PAS-178_PROTECTED_MAIN_ENFORCEMENT"]["observed"] == (
        "PASS_PUBLIC_MAIN_PROTECTED_ACTIVE_RULESETS_NO_BYPASS"
    )


def test_staging_execution_cannot_be_enabled_with_unsatisfied_gates(documents):
    candidate, _ = documents
    enabled = copy.deepcopy(candidate)
    enabled["authorization"]["staging_execution_authorized"] = True
    expect_candidate_failure(enabled, "staging execution cannot be pre-authorized|unsatisfied gates")


def test_staging_chain_is_caddy_kong_middleware_8095_test_syn(documents):
    candidate, _ = documents
    assert candidate["staging_chain"] == [
        "Caddy staging",
        "Kong",
        "Middleware :8095",
        "TEST_SYN",
    ]
    wrong = copy.deepcopy(candidate)
    wrong["staging_chain"][2] = "Middleware :8080"
    expect_candidate_failure(wrong, "staging chain drift")


def test_external_authorities_are_pinned_without_claiming_digest_chain_pass(documents):
    candidate, _ = documents
    assert candidate["external_authorities"]["middleware"]["source_sha"] == validator.EXPECTED_MIDDLEWARE_SHA
    assert candidate["external_authorities"]["middleware"]["public_contract_sha256"] == validator.EXPECTED_MIDDLEWARE_CONTRACT
    assert candidate["external_authorities"]["kong"]["required_middleware_contract_sha256"] == validator.EXPECTED_MIDDLEWARE_CONTRACT
    keycloak_sha = candidate["external_authorities"]["keycloak"]["required_source_sha"]
    assert validator.SHA40.fullmatch(keycloak_sha) is not None
    assert candidate["authorization"]["staging_execution_authorized"] is False


def test_reload_and_rollback_cannot_drop_safety_requirements(documents):
    candidate, _ = documents
    bad_reload = copy.deepcopy(candidate)
    bad_reload["reload_policy"]["last_known_good_snapshot_required"] = False
    expect_candidate_failure(bad_reload, "reload policy last_known_good_snapshot_required")

    bad_rollback = copy.deepcopy(candidate)
    bad_rollback["rollback_policy"]["post_restore_health_required"] = False
    expect_candidate_failure(bad_rollback, "rollback policy post_restore_health_required")


def test_no_effect_canary_policy_is_strict(documents):
    candidate, evidence = documents
    canary = candidate["canary_policy"]
    assert canary["mode"] == "READ_ONLY_NO_EFFECT"
    assert all(
        canary[key] is False
        for key in (
            "provider_effects_allowed",
            "business_writes_allowed",
            "pstn_allowed",
            "payments_allowed",
            "production_write_activation_allowed",
        )
    )
    assert all(value == 0 for value in evidence["effects"].values())

    bad = copy.deepcopy(candidate)
    bad["canary_policy"]["business_writes_allowed"] = True
    expect_candidate_failure(bad, "business_writes_allowed")


def test_unknown_route_fallback_blocks_production_canary_and_go(documents):
    candidate, evidence = documents
    gate = candidate["production_gate"]
    assert gate["unknown_route_fallback_required"] == 0
    assert gate["observed_unknown_route_fallback"] == "TRANSITIONAL_NONZERO"
    assert gate["production_go"] is False
    assert evidence["production_gate"]["unknown_route_fallback_zero"] is False
    assert evidence["verdict"] == "NO_GO"


def test_evidence_template_cannot_claim_reload_restart_or_rollback(documents):
    _, evidence = documents
    reload_done = copy.deepcopy(evidence)
    reload_done["reload"]["attempted"] = True
    expect_evidence_failure(reload_done, "reload must not be attempted")

    restart_done = copy.deepcopy(evidence)
    restart_done["restart"]["attempted"] = True
    expect_evidence_failure(restart_done, "restart must not be attempted")

    rollback_done = copy.deepcopy(evidence)
    rollback_done["rollback"]["rehearsed"] = True
    expect_evidence_failure(rollback_done, "rollback must remain pending")


def test_evidence_template_requires_merged_sha_only_at_execution(documents):
    _, evidence = documents
    assert evidence["candidate"]["merged_caddy_source_sha"] == "REQUIRED_AT_EXECUTION"
    forged = copy.deepcopy(evidence)
    forged["candidate"]["merged_caddy_source_sha"] = validator.EXPECTED_MERGED_MAIN_SHA
    expect_evidence_failure(forged, "evidence template must defer runtime source pin until execution")
