from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from caddy_candidate import CandidateBuildError, CandidateBuilder
from caddy_runtime_readback import extract_runtime_inventory


def fake_runner(config: dict, *, returncode: int = 0, stderr: str = ""):
    def run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["caddy"],
            returncode=returncode,
            stdout=json.dumps(config),
            stderr=stderr,
        )
    return run


def test_candidate_builder_writes_deterministic_runtime_json(tmp_path: Path):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("example.invalid { respond 200 }\n")
    output = tmp_path / "candidate.json"
    config = {"apps": {"http": {"servers": {"srv0": {}}}}}
    builder = CandidateBuilder(caddyfile=caddyfile, output=output, runner=fake_runner(config))
    first = builder.build()
    second = builder.build(check=True)
    assert first["candidate_sha256"] == second["candidate_sha256"]
    assert json.loads(output.read_text()) == config
    assert first["mutation_performed"] is False


def test_candidate_builder_detects_drift(tmp_path: Path):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("x\n")
    output = tmp_path / "candidate.json"
    output.write_text(json.dumps({"old": True}))
    builder = CandidateBuilder(caddyfile=caddyfile, output=output, runner=fake_runner({"new": True}))
    with pytest.raises(CandidateBuildError, match="drift"):
        builder.build(check=True)


def test_candidate_builder_reports_adapter_failure(tmp_path: Path):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("x\n")
    builder = CandidateBuilder(
        caddyfile=caddyfile,
        output=tmp_path / "candidate.json",
        runner=fake_runner({}, returncode=1, stderr="bad config"),
    )
    with pytest.raises(CandidateBuildError, match="bad config"):
        builder.build()


def test_runtime_inventory_extracts_paths_hosts_and_upstreams():
    config = {
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "routes": [
                            {
                                "match": [{"host": ["api.codestra.co"], "path": ["/platform/v1/*"]}],
                                "handle": [
                                    {
                                        "handler": "reverse_proxy",
                                        "upstreams": [{"dial": "127.0.0.1:8000"}],
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        }
    }
    inventory = extract_runtime_inventory(config)
    assert inventory["hosts"] == ["api.codestra.co"]
    assert inventory["paths"] == ["/platform/v1/*"]
    assert inventory["upstreams"] == ["127.0.0.1:8000"]


def test_control_service_drift_in_sync_and_drifted(tmp_path: Path):
    from caddy_control_api import ControlService
    from caddy_execution_store import ExecutionStore
    from caddy_runtime_readback import CaddyRuntime

    class Transport:
        def __init__(self, config):
            self.config = config
        def __call__(self, method, url, body, content_type):
            if method == "GET" and url.endswith("/config/"):
                return 200, json.dumps(self.config).encode()
            return 404, b"{}"

    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(json.dumps({"same": True}))
    service = ControlService(
        runtime=CaddyRuntime(transport=Transport({"same": True})),
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=candidate_path,
        candidate_builder=CandidateBuilder(
            caddyfile=tmp_path / "Caddyfile",
            output=candidate_path,
            runner=fake_runner({"same": True}),
        ),
    )
    assert service.drift()["state"] == "IN_SYNC"

    service.runtime = CaddyRuntime(transport=Transport({"different": True}))
    assert service.drift()["state"] == "DRIFTED"


def test_control_service_runtime_inventory(tmp_path: Path):
    from caddy_control_api import ControlService
    from caddy_execution_store import ExecutionStore
    from caddy_runtime_readback import CaddyRuntime

    config = {
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "routes": [{
                            "match": [{"host": ["api.codestra.co"], "path": ["/v2/automation/*"]}],
                            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8000"}]}],
                        }]
                    }
                }
            }
        }
    }

    def transport(method, url, body, content_type):
        return 200, json.dumps(config).encode()

    service = ControlService(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=tmp_path / "candidate.json",
    )
    assert service.runtime_routes()["paths"] == ["/v2/automation/*"]
    assert service.runtime_upstreams()["upstreams"] == ["127.0.0.1:8000"]
