import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from caddy_site_source import read_site  # noqa: E402
from mission5_desired_state import (  # noqa: E402
    Mission5ContractError,
    build_plan,
    classify_drift,
    configuration_identity,
    configuration_sha256,
    desired_state_material,
    desired_state_paths,
    plan_outcome,
    promotion_allowed,
    validate_plan,
)


VALID_IDENTITY = configuration_identity(
    git_sha="a" * 40,
    environment="staging",
    configuration_sha="b" * 64,
    desired_state_version="desired-state-v1",
    generated_at="2026-09-18T12:00:00Z",
)


def make_plan(**overrides):
    values = {
        "candidate": VALID_IDENTITY,
        "hosts": ("api.codestra.co",),
        "routes": ("/api/v1/health",),
        "upstreams": ("CADDY_KONG_UPSTREAM",),
        "changes": ("none",),
    }
    values.update(overrides)
    return build_plan(**values)


def test_valid_desired_state_inventory_is_unique_and_deterministic() -> None:
    paths = desired_state_paths(ROOT)
    assert len(paths) == len(set(paths))
    assert ROOT / "Caddyfile" in paths
    assert ROOT / "sites" / "api.codestra.co.caddy" in paths
    assert configuration_sha256(desired_state_material(ROOT)) == configuration_sha256(
        desired_state_material(ROOT)
    )


def test_valid_configuration_identity() -> None:
    assert VALID_IDENTITY["environment"] == "staging"
    assert len(VALID_IDENTITY["git_sha"]) == 40
    assert len(VALID_IDENTITY["configuration_sha256"]) == 64


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment", "unknown"),
        ("git_sha", "short"),
        ("configuration_sha", "not-a-sha"),
        ("desired_state_version", "runtime-json-v1"),
        ("generated_at", "2026-09-18 12:00:00"),
    ],
)
def test_invalid_configuration_identity_is_rejected(field, value) -> None:
    values = {
        "git_sha": "a" * 40,
        "environment": "staging",
        "configuration_sha": "b" * 64,
        "desired_state_version": "desired-state-v1",
        "generated_at": "2026-09-18T12:00:00Z",
    }
    values[field] = value
    with pytest.raises(Mission5ContractError):
        configuration_identity(**values)


def test_valid_non_mutating_plan() -> None:
    plan = make_plan()
    validate_plan(plan)
    assert plan["mutation"] == "PLAN_ONLY"
    assert plan["runtime_mutated"] is False
    assert plan["candidate"] == VALID_IDENTITY


def test_unidentified_candidate_is_rejected() -> None:
    with pytest.raises(Mission5ContractError, match="unidentified"):
        make_plan(candidate={"environment": "staging"})


def test_mutating_plan_is_rejected() -> None:
    plan = make_plan()
    plan["mutation"] = "APPLY"
    with pytest.raises(Mission5ContractError, match="must not mutate"):
        validate_plan(plan)


def test_secret_bearing_upstream_identity_is_rejected() -> None:
    with pytest.raises(Mission5ContractError, match="secret-bearing"):
        make_plan(upstreams=("production_client_secret",))


def test_drift_classes_cover_expected_and_effective_state() -> None:
    result = classify_drift(
        {"route": "kong", "health": "ready", "removed": "present"},
        {"route": "legacy", "health": "ready", "extra": "present"},
    )
    assert result == {
        "extra": "UNEXPECTED",
        "health": "IN_SYNC",
        "removed": "MISSING",
        "route": "DRIFTED",
    }


def test_unknown_readback_is_blocking() -> None:
    assert classify_drift({"route": "kong"}, None) == {"configuration": "UNKNOWN"}


def test_adjacent_environment_promotion_is_allowed() -> None:
    assert promotion_allowed("development", "staging", "staging")
    assert promotion_allowed("staging", "production", "production")


def test_unknown_or_downgrade_promotion_is_rejected() -> None:
    assert not promotion_allowed("development", "production", "production")
    assert not promotion_allowed("production", "development", "development")
    assert not promotion_allowed("qa", "production", "production")


def test_second_identical_plan_is_no_change() -> None:
    first = make_plan()
    second = make_plan()
    assert plan_outcome(first, second) == "NO_CHANGE"


def test_changed_candidate_plan_is_change() -> None:
    first = make_plan()
    second_identity = dict(VALID_IDENTITY)
    second_identity["configuration_sha256"] = "c" * 64
    second = make_plan(candidate=second_identity)
    assert plan_outcome(first, second) == "CHANGE"


def test_validation_pipeline_is_ordered_and_reload_free() -> None:
    ci = (ROOT / "scripts" / "validate-ci.sh").read_text(encoding="utf-8")
    assert ci.index("scripts/validate_repository.py") < ci.index("caddy adapt")
    assert ci.index("caddy adapt") < ci.index("caddy validate")
    assert "caddy reload" not in ci
    assert "systemctl reload caddy" not in ci


def test_runtime_mutation_paths_are_not_in_repository_scripts() -> None:
    scripts = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "scripts").glob("*.sh"))
    assert "systemctl reload" not in scripts
    assert "caddy reload" not in scripts


def test_validation_workflow_serializes_validation_runs() -> None:
    workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    assert "concurrency:" in workflow
    assert "cancel-in-progress: true" in workflow


def test_exact_release_identity_is_required() -> None:
    workflow = (ROOT / ".github" / "workflows" / "production-readonly-canary-v2.yml").read_text(encoding="utf-8")
    # The canary binds the checkout to the configuration identity the image ships.
    assert "scripts/stage_image_config.py --digest" in workflow
    assert "CADDY_CANARY_SOURCE_SHA" in workflow
    assert "CADDY_CANARY_CONFIG_SHA256" in workflow
    assert "CONFIG_SHA256" in workflow


def test_m1_to_m4_contracts_remain_in_desired_state() -> None:
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    api = read_site(ROOT / "sites" / "api.codestra.co.caddy")
    assert "admin unix//run/caddy/admin.sock" in caddyfile
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in api
    assert "Authorization delete" in api
    assert (ROOT / "docs" / "mission4-observability-operational-control.md").exists()
    assert (ROOT / "docs" / "desired-state-contract-v1.md").exists()
