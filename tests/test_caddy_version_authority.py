"""One Caddy version authority binds the build, CI, the rehearsal and the runtime."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import caddy_version  # noqa: E402

AUTHORITY = caddy_version.authority()
# Retired authorities: Caddy v2.10.0 (official image), and v2.11.4 (source build).
RETIRED = ("v2.10.0", "2.10.0", "ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c",
           "e2eee6a7fce366321294c9c2a79f3146891dcbdf", "docker.io/library/caddy")
ACTIVE_ROOTS = ("Caddyfile", "Dockerfile", ".github", "build-tools", "config", "deploy", "scripts", "sites",
                "snippets", "tests", "postman", "contracts", "generated", "monitoring-integration.v1.json")


def test_authority_is_complete_and_digest_pinned():
    assert re.fullmatch(r"v2\.11\.\d+", AUTHORITY["version"])
    assert AUTHORITY["source"]["tag"] == AUTHORITY["version"]
    assert re.fullmatch(r"[0-9a-f]{40}", AUTHORITY["source"]["commit"])
    assert re.fullmatch(r"[0-9a-f]{128}", AUTHORITY["release_binary"]["sha512"])
    assert AUTHORITY["version"].lstrip("v") in AUTHORITY["release_binary"]["url"]
    assert re.fullmatch(r"[0-9a-f]{64}", AUTHORITY["upstream_sbom"]["sha256"])
    for name in ("runtime_base_image", "rehearsal_base_image"):
        assert re.fullmatch(r"gcr\.io/distroless/static-debian13:[a-z-]+@sha256:[0-9a-f]{64}", AUTHORITY[name]), name
    assert AUTHORITY["source"]["module_overrides"] == []


def test_build_ci_and_image_consume_the_authority():
    build = (ROOT / "scripts" / "build-release-inputs.sh").read_text(encoding="utf-8")
    assert 'caddy_version.py" field source.commit' in build and 'caddy_version.py" field version' in build
    assert "go get" not in build
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.splitlines()[2] == "FROM " + AUTHORITY["runtime_base_image"]
    ci = (ROOT / "scripts" / "validate-ci.sh").read_text(encoding="utf-8")
    assert "caddy_version.py field runtime_base_image" in ci and "caddy_version.py fetch" in ci
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for version in re.findall(r"go-version:\s*'?([0-9.]+)", workflow.read_text(encoding="utf-8")):
            assert version == AUTHORITY["source"]["go_toolchain"], workflow.name


def test_no_active_file_carries_a_retired_caddy_authority():
    offenders = []
    for root in ACTIVE_ROOTS:
        path = ROOT / root
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        for file in files:
            if file.name == Path(__file__).name or file.suffix in {".pyc", ".png"}:
                continue
            text = file.read_text(encoding="utf-8", errors="ignore")
            offenders += [f"{file.relative_to(ROOT)}:{token}" for token in RETIRED if token in text]
    assert offenders == []


def test_certified_binary_is_the_authority_version():
    binary = os.environ.get("CADDY_BIN")
    if not binary:
        pytest.skip("CADDY_BIN is not set")
    reported = subprocess.run([binary, "version"], capture_output=True, text=True, check=True).stdout.split()[0]
    assert reported == AUTHORITY["version"]
