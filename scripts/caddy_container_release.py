#!/usr/bin/env python3
"""Controlled release and rollback of the immutable production Caddy container.

Operator tool for the canonical runtime (deploy/compose.runtime.yaml). Without
--apply it only plans. With --apply it:

1. records the running release (digest and identity labels);
2. validates the candidate image offline (no network, read-only, non-root)
   against the real runtime values and private certificate mounts;
3. switches the Compose digest and waits for the container to be healthy;
4. on any failure after the switch, restores the recorded release and waits
   for it to be healthy again, reporting a failed rollback separately.

It never pulls, builds or prunes: the candidate must already be present by
digest, and the previous image stays on the host for rollback.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
LABELS = {
    "source": "io.codestra.caddy.source.sha",
    "config": "io.codestra.caddy.config.sha256",
    "release": "io.codestra.caddy.release.id",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class Runtime:
    """Where a release runs. An empty image repository addresses local images by ID (rehearsals only)."""

    compose: Path = ROOT / "deploy" / "compose.runtime.yaml"
    container: str = "codestra-caddy"
    image_repository: str = "ghcr.io/appolon1908-hue/codestra-caddy"
    private_mounts: tuple[str, ...] = ("/etc/caddy/private/klyrow-events", "/etc/codestra/pki/middleware-private-ingress")

    def image(self, digest: str) -> str:
        return f"{self.image_repository}@{digest}" if self.image_repository else digest

    def digest_of(self, image: str) -> str | None:
        prefix = f"{self.image_repository}@" if self.image_repository else ""
        digest = image[len(prefix):] if image.startswith(prefix) else ""
        return digest if DIGEST.fullmatch(digest) else None


CANONICAL = Runtime()


class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class Release:
    digest: str
    source_sha: str
    config_sha256: str
    release_id: str

    def compose_environment(self) -> dict[str, str]:
        return {
            "CADDY_IMAGE_SHA256": self.digest.removeprefix("sha256:"),
            "CADDY_REVIEWED_SHA": self.source_sha,
            "CADDY_CONFIG_SHA256": self.config_sha256,
            "CADDY_RELEASE_ID": self.release_id,
        }


Runner = Callable[[Sequence[str], dict[str, str] | None], subprocess.CompletedProcess]


def _run(argv: Sequence[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged = {**os.environ, **env} if env else None
    return subprocess.run(list(argv), env=merged, capture_output=True, text=True, timeout=300, check=False)


class ContainerRelease:
    def __init__(self, *, env_file: Path, runtime: Runtime = CANONICAL, docker: str = "docker", runner: Runner = _run,
                 sleep: Callable[[float], None] = time.sleep, health_timeout: float = 120.0) -> None:
        self.env_file = env_file
        self.runtime = runtime
        self.docker = docker
        self.runner = runner
        self.sleep = sleep
        self.health_timeout = health_timeout

    def _call(self, argv: Sequence[str], env: dict[str, str] | None = None) -> str:
        result = self.runner(argv, env)
        if result.returncode:
            raise ReleaseError(f"{Path(argv[0]).name} {argv[1]} failed")
        return result.stdout

    def current(self) -> Release:
        inspected = json.loads(self._call([self.docker, "inspect", self.runtime.container]))[0]
        config = inspected.get("Config") or {}
        digest = self.runtime.digest_of(config.get("Image") or "")
        if not digest:
            raise ReleaseError("running container is not an immutable canonical release")
        labels = config.get("Labels") or {}
        return Release(digest, labels.get(LABELS["source"], ""),
                       labels.get(LABELS["config"], ""), labels.get(LABELS["release"], ""))

    def validate_offline(self, candidate: Release) -> None:
        argv = [self.docker, "run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532",
                "--env-file", str(self.env_file), "--env", "XDG_DATA_HOME=/data", "--env", "XDG_CONFIG_HOME=/config"]
        for path in ("/data", "/config", "/run/caddy", "/var/log/caddy", "/tmp"):
            argv += ["--tmpfs", f"{path}:uid=65532,gid=65532,mode=0700"]
        for path in self.runtime.private_mounts:
            argv += ["--mount", f"type=bind,src={path},dst={path},readonly"]
        argv += ["--entrypoint", "/usr/bin/caddy", self.runtime.image(candidate.digest), "validate", "--config", "/etc/caddy/Caddyfile",
                 "--adapter", "caddyfile"]
        self._call(argv)

    def switch(self, release: Release) -> None:
        self._call([self.docker, "compose", "-f", str(self.runtime.compose), "--env-file", str(self.env_file), "up", "-d",
                    "--no-build", "--pull", "never", "caddy"], release.compose_environment())

    def await_healthy(self, release: Release) -> None:
        deadline = self.health_timeout
        while deadline > 0:
            inspected = json.loads(self._call([self.docker, "inspect", self.runtime.container]))[0]
            state = inspected.get("State") or {}
            image = (inspected.get("Config") or {}).get("Image")
            expected = self.runtime.image(release.digest)
            if image == expected and (state.get("Health") or {}).get("Status") == "healthy":
                return
            if image == expected and state.get("Running") is False:
                break
            self.sleep(5)
            deadline -= 5
        raise ReleaseError("container did not become healthy")

    def release(self, candidate: Release, *, apply: bool) -> dict[str, object]:
        previous = self.current()
        evidence: dict[str, object] = {"schema": "codestra.caddy-container-release.v1",
                                       "previous": previous.digest, "candidate": candidate.digest,
                                       "mutation_performed": False}
        if candidate.digest == previous.digest:
            return {**evidence, "status": "NO_CHANGE"}
        self.validate_offline(candidate)
        evidence["candidate_validation"] = "PASS"
        if not apply:
            return {**evidence, "status": "PLANNED"}
        evidence["mutation_performed"] = True
        try:
            self.switch(candidate)
            self.await_healthy(candidate)
            return {**evidence, "status": "RELEASED"}
        except ReleaseError as failure:
            evidence["failure"] = str(failure)
        try:
            self.switch(previous)
            self.await_healthy(previous)
            return {**evidence, "status": "ROLLED_BACK"}
        except ReleaseError as failure:
            return {**evidence, "status": "ROLLBACK_FAILED", "rollback_failure": str(failure)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if not DIGEST.fullmatch(args.candidate_digest) or not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) \
            or not re.fullmatch(r"[0-9a-f]{64}", args.config_sha256) or not args.release_id:
        print("CADDY_CONTAINER_RELEASE=FAIL:invalid_identity", file=sys.stderr)
        return 2
    candidate = Release(args.candidate_digest, args.source_sha, args.config_sha256, args.release_id)
    try:
        evidence = ContainerRelease(env_file=args.env_file).release(candidate, apply=args.apply)
    except (ReleaseError, json.JSONDecodeError, IndexError) as exc:
        print(f"CADDY_CONTAINER_RELEASE=FAIL:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(evidence, sort_keys=True))
    return {"RELEASED": 0, "NO_CHANGE": 0, "PLANNED": 0, "ROLLED_BACK": 1}.get(str(evidence["status"]), 3)


if __name__ == "__main__":
    raise SystemExit(main())
