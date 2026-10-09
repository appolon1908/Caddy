"""Disposable rehearsal of the controlled release against real Docker and Compose.

Tiny images built from the version authority's verified release binary on the
pinned distroless base stand in for releases; one Compose project with a
unique name and 64 MiB containers stands in for the production runtime.
Nothing here touches the canonical container.
"""
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import caddy_version  # noqa: E402
from caddy_container_release import ContainerRelease, Release, ReleaseError, Runtime  # noqa: E402

CADDYFILES = {
    "good": '{\n\tadmin off\n}\n:8080 {\n\trespond /health "ok" 200\n\trespond 404\n}\n',
    "unhealthy": '{\n\tadmin off\n}\n:8080 {\n\trespond /health "down" 503\n\trespond 404\n}\n',
    "invalid": "{\n\tadmin off\n}\n:8080 {\n\trespond /health\n",
}
# Same healthy configuration, distinct image: a genuine next release.
CADDYFILES["next"] = CADDYFILES["good"]
COMPOSE = """services:
  caddy:
    container_name: ${REHEARSAL_CONTAINER:?}
    image: "sha256:${CADDY_IMAGE_SHA256:?}"
    user: "65532:65532"
    read_only: true
    mem_limit: 64m
    labels:
      io.codestra.caddy.source.sha: "${CADDY_REVIEWED_SHA:?}"
      io.codestra.caddy.config.sha256: "${CADDY_CONFIG_SHA256:?}"
      io.codestra.caddy.release.id: "${CADDY_RELEASE_ID:?}"
    environment:
      XDG_DATA_HOME: /data
      XDG_CONFIG_HOME: /config
    tmpfs:
      - /data:uid=65532,gid=65532
      - /config:uid=65532,gid=65532
      - /tmp:uid=65532,gid=65532
    healthcheck:
      test: ["CMD", "/busybox/wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health"]
      interval: 1s
      timeout: 2s
      retries: 2
      start_period: 1s
"""


@pytest.fixture(scope="module")
def rehearsal(tmp_path_factory):
    docker = shutil.which("docker")
    binary = Path(os.environ.get("CADDY_RELEASE_BIN", ""))
    base = caddy_version.field("rehearsal_base_image")

    def run(*args, **kwargs):
        return subprocess.run([docker, *args], capture_output=True, text=True, timeout=180, **kwargs)

    if not docker or not binary.is_file() or run("compose", "version").returncode:
        pytest.skip("requires Docker, Compose and CADDY_RELEASE_BIN (the verified Linux release binary)")
    work = tmp_path_factory.mktemp("rehearsal")
    runtime = work / "runtime"
    runtime.mkdir()
    shutil.copy(binary, runtime / "caddy")
    (runtime / "Dockerfile").write_text(f"FROM {base}\nCOPY --chmod=0755 caddy /usr/bin/caddy\nUSER 65532:65532\n"
                                        'ENTRYPOINT ["/usr/bin/caddy"]\n'
                                        'CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]\n',
                                        encoding="utf-8", newline="\n")
    # BuildKit resolves FROM by name, never by a bare local image ID.
    pinned = f"codestra-caddy-rehearsal-runtime:{uuid.uuid4().hex[:12]}"
    built = run("build", "-q", "-t", pinned, str(runtime))
    assert built.returncode == 0, built.stderr
    version = run("run", "--rm", "--network", "none", pinned, "version")
    assert version.stdout.split()[0] == caddy_version.field("version"), version.stdout
    images = {}
    for name, caddyfile in CADDYFILES.items():
        context = work / name
        context.mkdir()
        (context / "Caddyfile").write_text(caddyfile, encoding="utf-8", newline="\n")
        (context / "Dockerfile").write_text(f"FROM {pinned}\nCOPY Caddyfile /etc/caddy/Caddyfile\n"
                                            f'LABEL io.codestra.rehearsal="{name}"\n', encoding="utf-8", newline="\n")
        built = run("build", "-q", str(context))
        assert built.returncode == 0, built.stderr
        images[name] = built.stdout.strip()
    compose = work / "compose.yaml"
    compose.write_text(COMPOSE, encoding="utf-8", newline="\n")
    env_file = work / "release.env"
    env_file.write_text("", encoding="utf-8")
    container = f"caddy-release-rehearsal-{uuid.uuid4().hex[:8]}"
    environment = {"REHEARSAL_CONTAINER": container, "COMPOSE_PROJECT_NAME": container}
    os.environ.update(environment)
    tool = ContainerRelease(env_file=env_file, runtime=Runtime(compose=compose, container=container,
                                                                image_repository="", private_mounts=()),
                            health_timeout=60)
    releases = {name: Release(digest, "a" * 40, "b" * 64, f"rehearsal-{name}") for name, digest in images.items()}
    try:
        tool.switch(releases["good"])
        tool.await_healthy(releases["good"])
        yield tool, releases, run
    finally:
        run("compose", "-f", str(compose), "--env-file", str(env_file), "down", "--timeout", "1")
        for digest in [*images.values(), pinned]:
            run("image", "rm", "-f", digest)
        for name in environment:
            os.environ.pop(name, None)


def test_invalid_candidate_never_becomes_authoritative(rehearsal):
    tool, releases, _ = rehearsal
    with pytest.raises(ReleaseError, match="docker run failed"):
        tool.release(releases["invalid"], apply=True)
    assert tool.current().digest == releases["good"].digest


def test_unhealthy_candidate_is_rolled_back_automatically(rehearsal):
    tool, releases, _ = rehearsal
    evidence = tool.release(releases["unhealthy"], apply=True)
    assert evidence["status"] == "ROLLED_BACK", evidence
    assert tool.current() == releases["good"]


def test_plan_validates_without_switching(rehearsal):
    tool, releases, _ = rehearsal
    assert tool.release(releases["next"], apply=False)["status"] == "PLANNED"
    assert tool.current().digest == releases["good"].digest


def test_healthy_candidate_is_released_and_the_previous_image_is_kept(rehearsal):
    tool, releases, run = rehearsal
    evidence = tool.release(releases["next"], apply=True)
    assert evidence["status"] == "RELEASED", evidence
    assert tool.current() == releases["next"]
    assert run("image", "inspect", releases["good"].digest).returncode == 0
    assert tool.release(releases["next"], apply=True)["status"] == "NO_CHANGE"
