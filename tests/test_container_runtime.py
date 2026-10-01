"""The canonical production runtime: one immutable, signed, non-root container.

These checks bind the Dockerfile, the Compose runtime, the read-only validator
and the release hash tool to the same deployable tree, so none can drift alone.
"""
import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stage_image_config  # noqa: E402

COMPOSE = (ROOT / "deploy" / "compose.runtime.yaml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PLACEHOLDER = re.compile(r"\{\$([A-Z0-9_]+)(:[^}]*)?\}")


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def staged_required(tmp_path):
    tree = tmp_path / "etc-caddy"
    files = stage_image_config.stage(tree)
    source = "\n".join((tree / name).read_text(encoding="utf-8") for name in files)
    return {name for name, default in PLACEHOLDER.findall(source) if not default}


def test_image_ships_only_the_staged_tree_as_non_root():
    assert re.search(r"(?m)^FROM gcr\.io/distroless/static-debian13:nonroot@sha256:[0-9a-f]{64}$", DOCKERFILE)
    assert "COPY --chown=65532:65532 build/etc-caddy/ /etc/caddy/" in DOCKERFILE
    assert DOCKERFILE.rstrip().splitlines()[-3] == "USER 65532:65532"
    assert 'RUN ["/usr/bin/codestra-set-bind-capability"]' in DOCKERFILE
    assert "sites-pending" not in DOCKERFILE and "config/" not in DOCKERFILE.split("COPY", 1)[1]


def test_staged_tree_is_exactly_the_deployable_configuration(tmp_path):
    files = stage_image_config.stage(tmp_path / "etc-caddy")
    expected = ["Caddyfile", *(f"snippets/{p.name}" for p in sorted((ROOT / "snippets").glob("*.caddy"))),
                *(f"sites/{p.name}" for p in sorted((ROOT / "sites").glob("*.caddy")))]
    assert files == expected
    hashing = load("hash_config_tree")
    first = hashing.config_tree_hash(tmp_path / "etc-caddy")
    stage_image_config.stage(tmp_path / "again")
    assert hashing.config_tree_hash(tmp_path / "again") == first


def test_compose_requires_every_runtime_value_the_image_reads(tmp_path):
    required = staged_required(tmp_path)
    declared = set(re.findall(r'(?m)^      (CADDY_[A-Z0-9_]+): "\$\{\1:\?set \1\}"$', COMPOSE))
    assert declared == required
    for identity in ("CADDY_RELEASE_SHA", "CADDY_CONFIGURATION_SHA256"):
        assert re.search(rf"(?m)^      {identity}: ", COMPOSE)


def test_compose_runtime_is_immutable_private_and_least_privileged():
    validator = load("caddy_readonly_validator")
    assert f'image: "{validator.EXPECTED_IMAGE_REPOSITORY}@sha256:${{CADDY_IMAGE_SHA256:?' in COMPOSE
    assert "container_name: codestra-caddy" in COMPOSE and validator.CONTAINER == "codestra-caddy"
    for token in ("read_only: true", 'user: "65532:65532"', "cap_drop:\n      - ALL", "cap_add:\n      - NET_BIND_SERVICE",
                  "no-new-privileges:true", "network_mode: host",
                  '["CMD", "/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]'):
        assert token in COMPOSE, token
    for label in (validator.SOURCE_LABEL, validator.DIGEST_LABEL, validator.CONFIG_LABEL, validator.RELEASE_LABEL):
        assert f"      {label}: " in COMPOSE
    socket_mount = "      - type: bind\n        source: /run/caddy\n        target: /run/caddy\n        bind:\n          create_host_path: false\n"
    assert socket_mount in COMPOSE
    assert "/run/caddy:uid" not in COMPOSE
    assert (ROOT / "deploy" / "tmpfiles.d" / "codestra-caddy.conf").read_text(encoding="utf-8").splitlines()[-1] == "d /run/caddy 0700 65532 65532 -"
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert f"admin unix/{validator.ADMIN_SOCKET}" in caddyfile
    for private in ("/etc/caddy/private/klyrow-events", "/etc/codestra/pki/middleware-private-ingress"):
        assert f"        source: {private}\n        target: {private}\n        read_only: true" in COMPOSE
        assert private in (ROOT / "sites" / ("klyrow-events.private.caddy" if "klyrow" in private else "middleware-private.caddy")).read_text(encoding="utf-8")


def test_rollback_baseline_is_an_immutable_signed_image():
    import json
    baseline = json.loads((ROOT / "config" / "release-baseline.v1.json").read_text(encoding="utf-8"))
    validator = load("caddy_readonly_validator")
    assert baseline["mutable"] is False
    assert re.fullmatch(rf"{re.escape(validator.EXPECTED_IMAGE_REPOSITORY)}@sha256:[0-9a-f]{{64}}", baseline["image"])


def test_compose_renders_with_the_runtime_examples(tmp_path):
    docker = shutil.which("docker")
    if not docker or subprocess.run([docker, "compose", "version"], capture_output=True, timeout=30).returncode:
        pytest.skip("requires docker compose")
    env = dict(line.split("=", 1) for line in (ROOT / "config" / "runtime-values.example").read_text(encoding="utf-8").splitlines()
               if line and not line.startswith("#") and "=" in line)
    env.update(CADDY_IMAGE_SHA256="0" * 64, CADDY_REVIEWED_SHA="a" * 40, CADDY_CONFIG_SHA256="b" * 64, CADDY_RELEASE_ID="test")
    import os
    result = subprocess.run([docker, "compose", "-f", str(ROOT / "deploy" / "compose.runtime.yaml"), "config", "--quiet"],
                            env={**os.environ, **env}, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    missing = dict(env)
    missing.pop("CADDY_KONG_UPSTREAM")
    result = subprocess.run([docker, "compose", "-f", str(ROOT / "deploy" / "compose.runtime.yaml"), "config", "--quiet"],
                            env={k: v for k, v in os.environ.items() if k != "CADDY_KONG_UPSTREAM"} | missing,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode != 0 and "CADDY_KONG_UPSTREAM" in result.stderr
