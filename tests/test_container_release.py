"""Controlled release and rollback of the immutable container, against a scripted Docker."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from caddy_container_release import CONTAINER, ContainerRelease, Release, ReleaseError, main  # noqa: E402

OLD = Release("sha256:" + "1" * 64, "a" * 40, "b" * 64, "release-old")
NEW = Release("sha256:" + "2" * 64, "c" * 40, "d" * 64, "release-new")


class FakeDocker:
    """Models the one container: which image runs and whether it turns healthy."""

    def __init__(self, *, valid=(OLD.digest, NEW.digest), healthy=(OLD.digest, NEW.digest)):
        self.running = OLD
        self.valid = set(valid)
        self.healthy = set(healthy)
        self.calls = []

    def __call__(self, argv, env=None):
        self.calls.append((list(argv), dict(env or {})))
        verb = argv[1]
        if verb == "inspect":
            labels = {"io.codestra.caddy.source.sha": self.running.source_sha,
                      "io.codestra.caddy.config.sha256": self.running.config_sha256,
                      "io.codestra.caddy.release.id": self.running.release_id}
            healthy = self.running.digest in self.healthy
            state = {"Running": healthy, "Health": {"Status": "healthy" if healthy else "unhealthy"}}
            payload = [{"Config": {"Image": self.running.image, "Labels": labels}, "State": state}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        if verb == "run":
            digest = next(arg for arg in argv if "@sha256:" in arg).split("@", 1)[1]
            return subprocess.CompletedProcess(argv, 0 if digest in self.valid else 1, "", "invalid")
        if verb == "compose":
            self.running = Release("sha256:" + env["CADDY_IMAGE_SHA256"], env["CADDY_REVIEWED_SHA"],
                                   env["CADDY_CONFIG_SHA256"], env["CADDY_RELEASE_ID"])
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    def verbs(self):
        return [call[0][1] for call in self.calls]


def release(fake, candidate=NEW, apply=True):
    tool = ContainerRelease(env_file=Path("/etc/codestra/caddy.env"), runner=fake, sleep=lambda _: None,
                            health_timeout=15)
    return tool.release(candidate, apply=apply)


def test_plan_validates_offline_and_never_mutates():
    fake = FakeDocker()
    evidence = release(fake, apply=False)
    assert evidence["status"] == "PLANNED" and evidence["mutation_performed"] is False
    assert "compose" not in fake.verbs() and fake.running == OLD
    offline = next(argv for argv, _ in fake.calls if argv[1] == "run")
    for token in ("--rm", "--read-only", "--user"):
        assert token in offline
    assert offline[offline.index("--network") + 1] == "none"
    assert not any(verb in fake.verbs() for verb in ("pull", "build", "rmi", "prune"))


def test_healthy_candidate_is_released_with_its_identity_labels():
    fake = FakeDocker()
    evidence = release(fake)
    assert evidence["status"] == "RELEASED" and fake.running == NEW
    compose = next((argv, env) for argv, env in fake.calls if argv[1] == "compose")
    assert compose[1]["CADDY_RELEASE_ID"] == "release-new"
    assert "--pull" in compose[0] and compose[0][compose[0].index("--pull") + 1] == "never"


def test_invalid_candidate_fails_closed_before_any_switch():
    fake = FakeDocker(valid=(OLD.digest,))
    with pytest.raises(ReleaseError, match="docker run failed"):
        release(fake)
    assert "compose" not in fake.verbs() and fake.running == OLD


def test_unhealthy_candidate_rolls_back_to_the_recorded_release():
    fake = FakeDocker(healthy=(OLD.digest,))
    evidence = release(fake)
    assert evidence["status"] == "ROLLED_BACK" and fake.running == OLD
    restored = [env for argv, env in fake.calls if argv[1] == "compose"][-1]
    assert restored["CADDY_RELEASE_ID"] == "release-old" and restored["CADDY_REVIEWED_SHA"] == OLD.source_sha


def test_failed_rollback_is_reported_separately():
    fake = FakeDocker(healthy=())
    evidence = release(fake)
    assert evidence["status"] == "ROLLBACK_FAILED" and "rollback_failure" in evidence


def test_same_digest_is_a_no_change():
    fake = FakeDocker()
    assert release(fake, candidate=OLD)["status"] == "NO_CHANGE"
    assert fake.verbs() == ["inspect"]


def test_cli_rejects_mutable_or_malformed_identity(capsys):
    assert main(["--env-file", "x", "--candidate-digest", "latest", "--source-sha", "a" * 40,
                 "--config-sha256", "b" * 64, "--release-id", "r"]) == 2
    assert "invalid_identity" in capsys.readouterr().err
    assert CONTAINER == "codestra-caddy"
