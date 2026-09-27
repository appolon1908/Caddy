from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_candidate_has_exact_identity_and_no_unknown_dirty_class() -> None:
    candidate = read("docs/mission6-release-candidate.md")
    assert "1f72905471645d490e7bd4ddf20a11d846df1446" in candidate
    assert "e75e85f529ee1b8c0aa31441ccdfb5c3f0e31245d0681006be6dad0bcdc21196" in candidate
    assert "UNKNOWN\n\nNone" in candidate
    assert "INTENDED M1-M5" in candidate


def test_required_m6_artifacts_exist() -> None:
    for path in (
        "docs/mission6-release-candidate.md",
        "docs/mission6-production-certification.md",
        "docs/mission6-evidence-matrix.md",
        "docs/caddy-release-seal.md",
    ):
        assert (ROOT / path).is_file()


def test_native_validation_uses_immutable_pinned_caddy_image() -> None:
    ci = read("scripts/validate-ci.sh")
    assert "docker.io/library/caddy@sha256:" in ci
    assert "caddy adapt --config /srv/Caddyfile" in ci
    assert "caddy validate --config /srv/Caddyfile" in ci


def test_source_gates_are_green_and_runtime_is_not_falsely_certified() -> None:
    certification = read("docs/mission6-production-certification.md")
    assert "Repository validator | PASS" in certification
    assert "Full source regression | PASS, 88 passed" in certification
    assert "`BLOCKED`" in certification
    assert "M6-RUNTIME-001" in certification


def test_no_production_release_seal_is_issued() -> None:
    seal = read("docs/caddy-release-seal.md")
    assert "NOT SEALED" in seal
    assert "RELEASE VERDICT: NO-GO" in seal
    assert "no deployment was performed" in read("docs/mission6-evidence-matrix.md")


def test_runtime_only_requirements_are_explicitly_blocked() -> None:
    matrix = read("docs/mission6-evidence-matrix.md")
    for requirement in (
        "TLS runtime",
        "Known-host and unknown-host routing",
        "Caddy -> Kong runtime boundary",
        "Readback and drift",
        "Reload, rollback, restart",
    ):
        assert requirement in matrix
    assert matrix.count("| BLOCKED |") >= 10


def test_architecture_bypass_scan_remains_enforced() -> None:
    api = read("sites/api.codestra.co.caddy")
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in api
    assert "codestra-middleware-integration-api-1" not in api
    assert "header_up Authorization" not in api
    assert "admin 127.0.0.1:2019" in read("Caddyfile")
