from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from caddy_activation import ActivationError, ActivationManager
from caddy_control_api import ControlService
from caddy_execution_store import ExecutionStore, ExecutionStoreError
from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError, sha256_json


class FakeTransport:
    def __init__(self, config: dict, *, mismatch_after_load: bool = False) -> None:
        self.config = config
        self.mismatch_after_load = mismatch_after_load
        self.calls = []

    def __call__(self, method: str, url: str, body: bytes | None, content_type: str | None):
        self.calls.append((method, url, content_type))
        if method == "GET" and url.endswith("/config/"):
            return 200, json.dumps(self.config).encode()
        if method == "POST" and url.endswith("/adapt"):
            return 200, b"{}"
        if method == "POST" and url.endswith("/load"):
            incoming = json.loads((body or b"{}").decode())
            self.config = {"mismatch": True} if self.mismatch_after_load else incoming
            return 200, b""
        return 404, b"{}"


def candidate(tmp_path: Path, value: dict, source_sha: str = "source-a") -> Path:
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    meta = {
        "schema": "codestra.caddy.runtime-candidate-metadata.v1",
        "candidate_sha256": sha256_json(value),
        "source_sha": source_sha,
    }
    path.with_suffix(path.suffix + ".meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return path


def test_runtime_requires_loopback_admin_api():
    with pytest.raises(RuntimeReadbackError, match="loopback"):
        CaddyRuntime("http://caddy.internal:2019")


def test_runtime_status_hashes_live_config():
    transport = FakeTransport({"apps": {"http": {"servers": {"srv0": {}}}}})
    status = CaddyRuntime(transport=transport).status()
    assert status["admin_api"] == "AVAILABLE"
    assert status["server_count"] == 1
    assert status["config_sha256"] == sha256_json(transport.config)


def test_execution_store_round_trip_and_corruption(tmp_path: Path):
    store = ExecutionStore(tmp_path / "evidence")
    store.put("abc", {"status": "COMPLETED"})
    assert store.get("abc")["status"] == "COMPLETED"
    (tmp_path / "evidence" / "abc.json").write_text("{bad", encoding="utf-8")
    with pytest.raises(ExecutionStoreError, match="corrupt"):
        store.get("abc")


def test_dry_run_detects_change_without_mutation(tmp_path: Path):
    transport = FakeTransport({"old": True})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {"new": True}),
        mutation_enabled=False,
    )
    result = manager.dry_run()
    assert result["status"] == "CHANGE"
    assert result["mutation_performed"] is False
    assert all(call[0] != "POST" for call in transport.calls)


def test_apply_disabled_by_default(tmp_path: Path):
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=FakeTransport({})),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {}),
        mutation_enabled=False,
    )
    with pytest.raises(ActivationError, match="disabled"):
        manager.apply(idempotency_key="same")


def test_apply_readback_and_idempotency(tmp_path: Path):
    transport = FakeTransport({"old": True})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {"new": True}),
        mutation_enabled=True,
    )
    first = manager.apply(idempotency_key="same")
    second = manager.apply(idempotency_key="same")
    assert first["status"] == "COMPLETED"
    assert second["execution_id"] == first["execution_id"]
    assert sum(1 for call in transport.calls if call[0] == "POST" and call[1].endswith("/load")) == 1


def test_idempotency_conflict_fails_closed(tmp_path: Path):
    transport = FakeTransport({"old": True})
    path = candidate(tmp_path, {"one": 1})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=path,
        mutation_enabled=True,
    )
    manager.apply(idempotency_key="same")
    path.write_text(json.dumps({"two": 2}), encoding="utf-8")
    with pytest.raises(ActivationError, match="different candidate"):
        manager.apply(idempotency_key="same")


def test_readback_mismatch_triggers_rollback(tmp_path: Path):
    original = {"old": True}
    transport = FakeTransport(original.copy(), mismatch_after_load=True)
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {"new": True}),
        mutation_enabled=True,
    )
    with pytest.raises(ActivationError, match="readback"):
        manager.apply(idempotency_key="mismatch")
    record = manager.store.get(manager.store.list_ids()[0])
    assert record["rollback_status"] in {"ROLLED_BACK", "ROLLBACK_FAILED"}


def test_manual_rollback_restores_pre_state(tmp_path: Path):
    transport = FakeTransport({"old": True})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {"new": True}),
        mutation_enabled=True,
    )
    record = manager.apply(idempotency_key="apply")
    transport.config = {"unexpected": True}
    restored = manager.rollback(record["execution_id"])
    assert restored["rollback_status"] == "ROLLED_BACK"
    assert transport.config == {"old": True}


def _control_service(tmp_path: Path, *, mutation_enabled=True):
    transport = FakeTransport({"old": True})
    runtime = CaddyRuntime(transport=transport)
    path = candidate(tmp_path, {"new": True})
    service = ControlService(
        runtime=runtime,
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=path,
        source_sha_provider=lambda: "source-a",
        mutation_enabled=mutation_enabled,
    )
    return service, transport

def test_control_service_telemetry_and_execution_list(tmp_path):
    service, transport = _control_service(tmp_path)
    service.activation_dry_run()
    listing = service.executions()
    telemetry = service.telemetry()
    assert listing["schema"] == "codestra.caddy.execution-list.v1"
    assert len(listing["executions"]) == 1
    assert telemetry["execution_records"] == 1
    assert telemetry["counters"]["ACTIVATION_DRY_RUN:CHANGE"] == 1

def test_reconcile_plan_never_mutates_runtime(tmp_path):
    service, transport = _control_service(tmp_path)
    before = len([x for x in transport.calls if x[0] == "POST"])
    result = service.reconcile(mode="plan", idempotency_key="")
    assert result["status"] == "PLANNED"
    after = len([x for x in transport.calls if x[0] == "POST"])
    assert after == before

def test_reconcile_apply_requires_idempotency_key(tmp_path):
    service, transport = _control_service(tmp_path)
    with pytest.raises(ActivationError, match="idempotency"):
        service.reconcile(mode="apply", idempotency_key="")


def test_apply_rejects_stale_source_sha_before_load(tmp_path: Path):
    transport = FakeTransport({"old": True})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-b",
        candidate_path=candidate(tmp_path, {"new": True}, source_sha="source-a"),
        mutation_enabled=True,
    )
    with pytest.raises(ActivationError, match="different source SHA"):
        manager.apply(idempotency_key="stale-source")
    assert not any(method == "POST" and url.endswith("/load") for method, url, _ in transport.calls)

def test_apply_validates_candidate_before_load(tmp_path: Path):
    transport = FakeTransport({"old": True})
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=candidate(tmp_path, {"new": True}),
        mutation_enabled=True,
    )
    manager.apply(idempotency_key="validated")
    posts = [url for method, url, _ in transport.calls if method == "POST"]
    assert posts.index("http://127.0.0.1:2019/adapt") < posts.index("http://127.0.0.1:2019/load")

def test_apply_rejects_candidate_digest_tamper(tmp_path: Path):
    transport = FakeTransport({"old": True})
    path = candidate(tmp_path, {"new": True})
    path.write_text(json.dumps({"tampered": True}), encoding="utf-8")
    manager = ActivationManager(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        source_sha_provider=lambda: "source-a",
        candidate_path=path,
        mutation_enabled=True,
    )
    with pytest.raises(ActivationError, match="digest"):
        manager.apply(idempotency_key="tampered")


def test_control_service_preflight_reports_exact_source_and_candidate(tmp_path):
    service, transport = _control_service(tmp_path)
    result = service.activation_preflight()
    assert result["valid"] is True
    assert result["source_sha"] == "source-a"
    assert result["current_source_sha"] == "source-a"
    assert len(result["candidate_sha256"]) == 64
    assert any(method == "POST" and url.endswith("/adapt") for method, url, _ in transport.calls)

def test_control_service_preflight_rejects_stale_plan(tmp_path):
    transport = FakeTransport({"old": True})
    path = candidate(tmp_path, {"new": True}, source_sha="old-source")
    service = ControlService(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=path,
        source_sha_provider=lambda: "new-source",
        mutation_enabled=True,
    )
    with pytest.raises(ActivationError, match="different source SHA"):
        service.activation_preflight()
    assert not any(method == "POST" and url.endswith("/load") for method, url, _ in transport.calls)

def test_control_api_source_exposes_preflight_endpoint():
    source=(ROOT/"scripts"/"caddy_control_api.py").read_text(encoding="utf-8")
    assert '"/platform/v1/caddy/activation/preflight"' in source

def test_reexecute_completed_activation_returns_original_receipt_without_side_effect(tmp_path: Path):
    service, transport = _control_service(tmp_path)
    first = service.activation_apply("cmd-reexecute-001")
    loads_after_first = sum(1 for method, url, _ in transport.calls if method == "POST" and url.endswith("/load"))
    second = service.activation_apply("cmd-reexecute-001")
    loads_after_second = sum(1 for method, url, _ in transport.calls if method == "POST" and url.endswith("/load"))
    assert second == first
    assert second["status"] == "COMPLETED"
    assert loads_after_first == 1
    assert loads_after_second == loads_after_first


def test_reexecute_key_is_fenced_to_original_candidate(tmp_path: Path):
    transport = FakeTransport({"old": True})
    path = candidate(tmp_path, {"version": 1})
    service = ControlService(
        runtime=CaddyRuntime(transport=transport),
        store=ExecutionStore(tmp_path / "evidence"),
        candidate_path=path,
        source_sha_provider=lambda: "source-a",
        mutation_enabled=True,
    )
    service.activation_apply("cmd-reexecute-fenced")
    path.write_text(json.dumps({"version": 2}), encoding="utf-8")
    path.with_suffix(path.suffix + ".meta.json").write_text(
        json.dumps({"schema": "codestra.caddy.runtime-candidate-metadata.v1", "candidate_sha256": sha256_json({"version": 2}), "source_sha": "source-a"}),
        encoding="utf-8",
    )
    with pytest.raises(ActivationError, match="different candidate"):
        service.activation_apply("cmd-reexecute-fenced")
    assert sum(1 for method, url, _ in transport.calls if method == "POST" and url.endswith("/load")) == 1


def test_reconcile_no_change_is_fenced_from_activation(tmp_path: Path):
    service, transport = _control_service(tmp_path)
    service.activation_apply("seed-in-sync")
    before_loads = sum(1 for method, url, _ in transport.calls if method == "POST" and url.endswith("/load"))
    result = service.reconcile(mode="apply", idempotency_key="reconcile-no-change")
    after_loads = sum(1 for method, url, _ in transport.calls if method == "POST" and url.endswith("/load"))
    assert result["status"] == "NO_CHANGE"
    assert result["drift"]["state"] == "IN_SYNC"
    assert after_loads == before_loads


def test_execution_audit_preserves_candidate_source_preflight_and_readback(tmp_path: Path):
    service, _ = _control_service(tmp_path)
    record = service.activation_apply("audit-contract")
    stored = service.execution(record["execution_id"])
    assert stored["idempotency_key"] == "audit-contract"
    assert stored["preflight_validated"] is True
    assert stored["source_sha"] == "source-a"
    assert len(stored["candidate_sha256"]) == 64
    assert len(stored["canonical_candidate_sha256"]) == 64
    assert stored["result_state_sha256"] == stored["canonical_candidate_sha256"]
    assert stored["rollback_status"] == "NOT_REQUIRED"
    assert stored["readback_verified"] is True
    assert stored["readback_verified"] is True
