"""Canonical release certificate identities must match the exact gated ref."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/reusable-codestra-deploy-readiness.yml"
CANONICAL = "https://github.com/appolon1908/Caddy/.github/workflows/reusable-codestra-deploy-readiness.yml@"
VERIFY_CASES = ("verify", "verify-attestation:0", "verify-attestation:1", "verify-blob")


def release_step(name):
    # These tests need only the two literal Bash run blocks, avoiding an extra
    # YAML dependency in the existing pytest-only validation environment.
    source = WORKFLOW.read_text().split("  immutable-candidate:\n", 1)[1]
    block = source.split("      - name: " + name + "\n", 1)[1].split("\n      - name:", 1)[0]
    return {"run": textwrap.dedent(block.split("        run: |\n", 1)[1])}


def verification_arguments(tmp_path, case, ref="refs/heads/main"):
    """Run the real identity assignments and Cosign invocation with a recorder.

    The recorder replaces only the signing service/crypto process boundary;
    these tests do not create certificates, sign artifacts or contact Sigstore.
    """
    source = release_step("Build once, scan, publish, sign, and attest")["run"]
    assignments = [line.strip() for line in source.splitlines() if re.match(
        r"\s*(identity_pattern|caller_identity|called_identity_pattern)=", line,
    )]
    verb, _, occurrence = case.partition(":")
    commands = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith(f'"$RUNNER_TEMP/cosign" {verb} '):
            command = [line.strip()]
            while command[-1].endswith("\\"):
                index += 1
                command.append(lines[index].strip())
            commands.append("\n".join(command))
    command = commands[int(occurrence or 0)]
    recorder = tmp_path / "cosign"
    recorder.write_text(f"#!{sys.executable}\n" +
                        "import json,os,sys\nfrom pathlib import Path\n"
                        "Path(os.environ['RECORDED_ARGS']).write_text(json.dumps(sys.argv[1:]))\n")
    recorder.chmod(0o755)
    (tmp_path / "evidence").mkdir(exist_ok=True)
    environment = {"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(tmp_path),
                   "GITHUB_REPOSITORY": "appolon1908/Caddy", "GITHUB_REF": ref,
                   "RECORDED_ARGS": str(tmp_path / "args.json")}
    script = "\n".join(["set -euo pipefail", *assignments,
                         "subject=ghcr.io/example/caddy@sha256:synthetic",
                         "manifest=evidence/source-release-manifest.json", command])
    result = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=environment,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads((tmp_path / "args.json").read_text())


@pytest.mark.parametrize("case", VERIFY_CASES)
@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/heads/staging", "refs/heads/production"])
def test_actual_verification_accepts_only_its_current_canonical_workflow_ref(tmp_path, case, ref):
    arguments = verification_arguments(tmp_path, case, ref)
    pattern = arguments[arguments.index("--certificate-identity-regexp") + 1]
    # Cosign's regex match searches; the expression itself must anchor the SAN.
    assert re.search(pattern, CANONICAL + ref)
    assert arguments[arguments.index("--certificate-oidc-issuer") + 1] == "https://token.actions.githubusercontent.com"
    if case == "verify-blob":
        assert arguments[arguments.index("--bundle") + 1] == "evidence/source-release-manifest.sigstore.json"
        assert arguments[-1] == "evidence/source-release-manifest.json"


@pytest.mark.parametrize("case", VERIFY_CASES)
@pytest.mark.parametrize("identity", [
    "https://github.com/ingtrader21-spec/Caddy/.github/workflows/reusable-codestra-deploy-readiness.yml@refs/heads/main",
    "https://github.com/ingtrader21-spec/Infustruction-repo/.github/workflows/reusable-codestra-deploy-readiness.yml@refs/heads/main",
    "https://github.com/foreign/Caddy/.github/workflows/reusable-codestra-deploy-readiness.yml@refs/heads/main",
    "https://github.com/appolon1908/Other/.github/workflows/reusable-codestra-deploy-readiness.yml@refs/heads/main",
    CANONICAL + "refs/heads/staging",
    CANONICAL + "refs/heads/main-extra",
    CANONICAL + "refs/tags/main",
    "untrusted-prefix/" + CANONICAL + "refs/heads/main",
    "https://github.com/appolon1908/Caddy/.github/workflows/codestra-deploy-readiness.yml@refs/heads/main",
    "https://githubXcom/appolon1908/Caddy/Xgithub/workflows/reusable-codestra-deploy-readinessXyml@refs/heads/main",
])
def test_actual_verification_rejects_foreign_old_or_mismatched_identity(tmp_path, case, identity):
    arguments = verification_arguments(tmp_path, case)
    pattern = arguments[arguments.index("--certificate-identity-regexp") + 1]
    assert re.search(pattern, identity) is None


@pytest.mark.parametrize(("repository", "ref", "accepted"), [
    ("appolon1908/Caddy", "refs/heads/main", True),
    ("appolon1908/Caddy", "refs/heads/staging", True),
    ("appolon1908/Caddy", "refs/heads/production", True),
    ("ingtrader21-spec/Caddy", "refs/heads/main", False),
    ("appolon1908/Other", "refs/heads/main", False),
    ("foreign/Caddy", "refs/heads/main", False),
    ("appolon1908/Caddy", "refs/heads/atomic/test", False),
    ("appolon1908/Caddy", "refs/tags/main", False),
])
def test_release_authority_refuses_foreign_callers_and_unprotected_refs(repository, ref, accepted):
    source = release_step("Restrict release authority")["run"]
    source = source.replace("${{ inputs.operation }}", "verify")
    result = subprocess.run(["bash", "-c", source],
                            env={"PATH": os.defpath, "GITHUB_REPOSITORY": repository, "GITHUB_REF": ref},
                            capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted
