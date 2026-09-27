"""Pure Mission 5 desired-state, plan, identity, and drift primitives."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ENVIRONMENTS = ("development", "staging", "production")
PROMOTION_EDGES = {
    "development": "staging",
    "staging": "production",
}
DRIFT_CLASSES = ("IN_SYNC", "DRIFTED", "MISSING", "UNEXPECTED", "UNKNOWN")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^desired-state-v[0-9]+$")
SECRET_WORDS = (
    "secret",
    "password",
    "token",
    "private_key",
    "client_secret",
)


def desired_state_paths(root: Path) -> tuple[Path, ...]:
    """Return the ordered, source-controlled files that define Caddy state."""

    paths = [root / "Caddyfile", root / "config" / "runtime-values.example"]
    paths.extend(sorted((root / "config").glob("*.json")))
    paths.extend(sorted((root / "config").glob("*.caddy")))
    paths.extend(sorted((root / "snippets").glob("*.caddy")))
    paths.extend(sorted((root / "sites").glob("*.caddy")))
    return tuple(path for path in paths if path.is_file())


def desired_state_material(root: Path) -> str:
    chunks = []
    for path in desired_state_paths(root):
        chunks.append(f"{path.relative_to(root).as_posix()}\0")
        chunks.append(path.read_text(encoding="utf-8"))
        chunks.append("\0")
    return "".join(chunks)


class Mission5ContractError(ValueError):
    """Raised when a desired-state or deployment contract is unsafe."""


def configuration_sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def configuration_identity(
    *,
    git_sha: str,
    environment: str,
    configuration_sha: str,
    desired_state_version: str,
    generated_at: str,
) -> dict[str, str]:
    if not SHA1_RE.fullmatch(git_sha):
        raise Mission5ContractError("candidate Git SHA is not a full lowercase SHA-1")
    if environment not in ENVIRONMENTS:
        raise Mission5ContractError("unknown deployment environment")
    if not SHA256_RE.fullmatch(configuration_sha):
        raise Mission5ContractError("candidate configuration SHA-256 is invalid")
    if not VERSION_RE.fullmatch(desired_state_version):
        raise Mission5ContractError("desired-state version is invalid")
    if not generated_at.endswith("Z") or "T" not in generated_at:
        raise Mission5ContractError("generation timestamp must be UTC ISO-8601")
    return {
        "git_sha": git_sha,
        "environment": environment,
        "configuration_sha256": configuration_sha,
        "desired_state_version": desired_state_version,
        "generated_at": generated_at,
    }


def build_plan(
    *,
    candidate: Mapping[str, str],
    hosts: tuple[str, ...],
    routes: tuple[str, ...],
    upstreams: tuple[str, ...],
    changes: tuple[str, ...],
    previous: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not candidate.get("git_sha") or not candidate.get("configuration_sha256"):
        raise Mission5ContractError("unidentified candidate")
    if any(any(word in value.lower() for word in SECRET_WORDS) for value in upstreams):
        raise Mission5ContractError("plan contains secret-bearing upstream identity")
    return {
        "kind": "caddy-deployment-plan-v1",
        "candidate": dict(candidate),
        "environment": candidate["environment"],
        "hosts_affected": list(hosts),
        "routes_affected": list(routes),
        "upstreams_affected": list(upstreams),
        "changes": list(changes),
        "previous_configuration": dict(previous or {}),
        "mutation": "PLAN_ONLY",
        "runtime_mutated": False,
    }


def validate_plan(plan: Mapping[str, Any]) -> None:
    required = {
        "kind",
        "candidate",
        "environment",
        "hosts_affected",
        "routes_affected",
        "upstreams_affected",
        "changes",
        "previous_configuration",
        "mutation",
        "runtime_mutated",
    }
    if set(plan) < required or plan["kind"] != "caddy-deployment-plan-v1":
        raise Mission5ContractError("deployment plan contract is incomplete")
    if plan["mutation"] != "PLAN_ONLY" or plan["runtime_mutated"] is not False:
        raise Mission5ContractError("deployment plan must not mutate runtime")
    candidate = plan["candidate"]
    if not isinstance(candidate, Mapping):
        raise Mission5ContractError("deployment plan candidate is missing")
    configuration_identity(
        git_sha=candidate["git_sha"],
        environment=candidate["environment"],
        configuration_sha=candidate["configuration_sha256"],
        desired_state_version=candidate["desired_state_version"],
        generated_at=candidate["generated_at"],
    )
    if plan["environment"] != candidate["environment"]:
        raise Mission5ContractError("plan environment does not match candidate")


def classify_drift(
    expected: Mapping[str, str], effective: Mapping[str, str] | None
) -> dict[str, str]:
    if effective is None:
        return {"configuration": "UNKNOWN"}
    result: dict[str, str] = {}
    for key in sorted(set(expected) | set(effective)):
        if key not in effective:
            result[key] = "MISSING"
        elif key not in expected:
            result[key] = "UNEXPECTED"
        elif expected[key] == effective[key]:
            result[key] = "IN_SYNC"
        else:
            result[key] = "DRIFTED"
    return result


def promotion_allowed(source: str, target: str, candidate_environment: str) -> bool:
    return (
        source in PROMOTION_EDGES
        and PROMOTION_EDGES[source] == target
        and candidate_environment == target
    )


def plan_outcome(first: Mapping[str, Any], second: Mapping[str, Any]) -> str:
    return "NO_CHANGE" if dict(first) == dict(second) else "CHANGE"
