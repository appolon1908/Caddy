#!/usr/bin/env python3
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from caddy_coordination import RuntimeCoordinator, CoordinationError
from caddy_execution_store import ExecutionStore, ExecutionStoreError
from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError, canonical_json, sha256_json


class ActivationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ActivationManager:
    def __init__(
        self,
        *,
        runtime: CaddyRuntime,
        store: ExecutionStore,
        candidate_path: Path,
        candidate_metadata_path: Path | None = None,
        source_sha_provider=None,
        mutation_enabled: bool | None = None,
        coordinator: RuntimeCoordinator | None = None,
    ) -> None:
        self.runtime = runtime
        self.coordinator = coordinator or RuntimeCoordinator()
        self.store = store
        self.candidate_path = candidate_path
        self.candidate_metadata_path = candidate_metadata_path or candidate_path.with_suffix(candidate_path.suffix + ".meta.json")
        self.source_sha_provider = source_sha_provider
        self.mutation_enabled = (
            os.environ.get("CADDY_CONTROL_MUTATION_ENABLED") == "explicit-test-only"
            if mutation_enabled is None
            else mutation_enabled
        )

    def _candidate(self) -> tuple[str, dict[str, Any]]:
        if not self.candidate_path.exists():
            raise ActivationError("CANDIDATE_MISSING", "candidate Caddy JSON config is missing")
        try:
            raw = self.candidate_path.read_text(encoding="utf-8")
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ActivationError("CANDIDATE_INVALID", "candidate Caddy JSON config is invalid") from exc
        if not isinstance(value, dict):
            raise ActivationError("CANDIDATE_INVALID", "candidate Caddy JSON config must be an object")
        return sha256_text(raw), value

    def _source_sha(self) -> str | None:
        return self.source_sha_provider() if self.source_sha_provider else None

    def _metadata(self):
        if not self.candidate_metadata_path.exists():
            raise ActivationError("CANDIDATE_METADATA_MISSING", "candidate metadata is missing")
        try:
            meta = json.loads(self.candidate_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ActivationError("CANDIDATE_METADATA_INVALID", "candidate metadata is invalid") from exc
        if not isinstance(meta, dict):
            raise ActivationError("CANDIDATE_METADATA_INVALID", "candidate metadata must be an object")
        return meta

    def _preflight(self, candidate_sha: str, candidate: dict[str, Any]) -> dict[str, Any]:
        meta = self._metadata()
        if meta.get("candidate_sha256") != sha256_json(candidate):
            raise ActivationError("CANDIDATE_DIGEST_STALE", "candidate digest no longer matches metadata")
        source_sha = self._source_sha()
        if source_sha and meta.get("source_sha") != source_sha:
            raise ActivationError("SOURCE_SHA_STALE", "candidate was built from a different source SHA")
        self.runtime.validate_json(candidate)
        return meta

    def dry_run(self) -> dict[str, Any]:
        execution_id = str(uuid.uuid4())
        candidate_sha, candidate = self._candidate()
        self._preflight(candidate_sha, candidate)
        try:
            live = self.runtime.config()
            live_sha = sha256_json(live)
            status = "NO_CHANGE" if canonical_json(live) == canonical_json(candidate) else "CHANGE"
            error = None
        except RuntimeReadbackError as exc:
            live_sha = None
            status = "UNKNOWN"
            error = {"code": exc.code, "message": str(exc)}
        record = {
            "kind": "ACTIVATION_DRY_RUN",
            "status": status,
            "candidate_sha256": candidate_sha,
            "pre_state_sha256": live_sha,
            "mutation_performed": False,
            "created_at": utc_now(),
            "error": error,
        }
        self.store.put(execution_id, record)
        return {"execution_id": execution_id, **record}

    @contextmanager
    def _mutation_lock(self):
        try:
            lock = self.coordinator.acquire()
        except CoordinationError as exc:
            raise ActivationError("ACTIVATION_IN_PROGRESS", "Caddy mutation is already in progress") from exc
        try:
            yield
        finally:
            self.coordinator.release(lock)

    def _health(self):
        try:
            self.runtime.check_health()
        except RuntimeReadbackError as exc:
            raise ActivationError(exc.code, str(exc)) from exc

    def _record(self, execution_id, record):
        # Write the shared ledger first, so a crash cannot permit a repeated load.
        self.coordinator.record(execution_id, record, "json")
        self.store.put(execution_id, record)

    def apply(self, *, idempotency_key: str, expected_active_digest: str | None = None) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        with self._mutation_lock():
            return self._apply_locked(idempotency_key=idempotency_key,
                                      expected_active_digest=expected_active_digest)

    def _apply_locked(self, *, idempotency_key: str, expected_active_digest: str | None = None) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ActivationError("IDEMPOTENCY_KEY_INVALID", "valid idempotency key is required")

        candidate_sha, candidate = self._candidate()
        source_sha = self._source_sha()
        if source_sha is None:
            source_sha = self._metadata().get("source_sha")
        try:
            prior = self.coordinator.prior(idempotency_key, "json", candidate_sha, source_sha)
        except CoordinationError as exc:
            raise ActivationError("IDEMPOTENCY_CONFLICT", str(exc)) from exc
        if prior:
            prior.pop("engine", None)
            return prior
        for existing_id in self.store.list_ids():
            try:
                existing = self.store.get(existing_id)
            except ExecutionStoreError as exc:
                raise ActivationError("AUDIT_CORRUPT", str(exc)) from exc
            if existing.get("idempotency_key") == idempotency_key:
                if existing.get("candidate_sha256") != candidate_sha:
                    raise ActivationError("IDEMPOTENCY_CONFLICT", "idempotency key was used with a different candidate")
                if existing.get("status") == "COMPLETED":
                    return existing
                if existing.get("status") == "FAILED":
                    error=existing.get("error") or {}
                    raise ActivationError(error.get("code","ACTIVATION_FAILED"),error.get("message","prior activation failed"))
                raise ActivationError("IDEMPOTENCY_INDETERMINATE", "prior activation with this idempotency key is not terminal")
        try:
            self.coordinator.ensure_idle()
        except CoordinationError as exc:
            raise ActivationError("RECOVERY_REQUIRED", str(exc)) from exc
        metadata = self._preflight(candidate_sha, candidate)

        execution_id = str(uuid.uuid4())
        pre_config = self.runtime.config()
        pre_sha = sha256_json(pre_config)
        if expected_active_digest and pre_sha != expected_active_digest:
            raise ActivationError("STALE_PLAN", "runtime changed since the approved plan")
        self._health()
        # Never adopt out-of-band or interrupted runtime state as accepted.
        try:
            self.coordinator.baseline(pre_config)
        except CoordinationError as exc:
            raise ActivationError("RESTART_STATE_DRIFT", str(exc)) from exc
        record = {
            "kind": "ACTIVATION_APPLY",
            "status": "RUNNING",
            "candidate_sha256": candidate_sha,
            "canonical_candidate_sha256": sha256_json(candidate),
            "source_sha": metadata.get("source_sha"),
            "preflight_validated": True,
            "pre_state_sha256": pre_sha,
            "pre_state": pre_config,
            "idempotency_key": idempotency_key,
            "mutation_performed": False,
            "created_at": utc_now(),
        }
        self._record(execution_id, record)

        try:
            self.runtime.load_json(candidate)
            readback = self.runtime.config()
            result_sha = sha256_json(readback)
            if canonical_json(readback) != canonical_json(candidate):
                raise ActivationError("READBACK_MISMATCH", "runtime readback does not match candidate")
            self._health()
            self.coordinator.persist(candidate)
            record.update(
                {
                    "status": "COMPLETED",
                    "health_verified": True,
                    "restart_config_sha256": result_sha,
                    "result_state_sha256": result_sha,
                    "rollback_status": "NOT_REQUIRED",
                    "readback_verified": True,
                    "mutation_performed": True,
                    "completed_at": utc_now(),
                }
            )
            self._record(execution_id, record)
            return self.store.get(execution_id)
        except Exception as exc:
            rollback_status = "NOT_ATTEMPTED"
            rollback_error = None
            try:
                self.runtime.load_json(pre_config)
                restored = self.runtime.config()
                if canonical_json(restored) != canonical_json(pre_config):
                    raise ActivationError("ROLLBACK_READBACK_MISMATCH", "rollback readback does not match pre-state")
                self._health()
                self.coordinator.persist(pre_config)
                rollback_status = "ROLLED_BACK"
            except Exception as rollback_exc:
                rollback_status = "ROLLBACK_FAILED"
                rollback_error = str(rollback_exc)
            record.update(
                {
                    "status": "FAILED",
                    "error": {"code": getattr(exc, "code", "ACTIVATION_FAILED"), "message": str(exc)},
                    "rollback_status": rollback_status,
                    "rollback_error": rollback_error,
                    "completed_at": utc_now(),
                    "mutation_performed": True,
                }
            )
            self._record(execution_id, record)
            raise ActivationError(record["error"]["code"], record["error"]["message"]) from exc

    def rollback(self, execution_id: str) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        with self._mutation_lock():
            return self._rollback_locked(execution_id)

    def _rollback_locked(self, execution_id: str) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        try:
            self.coordinator.ensure_idle()
        except CoordinationError as exc:
            raise ActivationError("RECOVERY_REQUIRED", str(exc)) from exc
        record = self.execution(execution_id)
        pre_state = record.get("pre_state")
        if not isinstance(pre_state, dict):
            raise ActivationError("ROLLBACK_STATE_MISSING", "execution has no restorable pre-state")
        expected_current = record.get("result_state_sha256")
        if record.get("status") != "COMPLETED" or not expected_current:
            raise ActivationError("ROLLBACK_EXECUTION_NOT_COMPLETED", "only a completed activation can be rolled back")
        current_sha = sha256_json(self.runtime.config())
        if current_sha != expected_current:
            raise ActivationError("STALE_ROLLBACK_RUNTIME_ADVANCED", "runtime no longer matches the selected execution result")
        self.runtime.validate_json(pre_state)
        journal_id = str(uuid.uuid4())
        journal = {"kind": "ACTIVATION_ROLLBACK", "status": "RUNNING",
                   "rollback_of": execution_id, "pre_state": self.runtime.config(),
                   "target_state_sha256": sha256_json(pre_state),
                   "mutation_performed": False, "created_at": utc_now()}
        self._record(journal_id, journal)
        record.update(rollback_status="RUNNING")
        self._record(execution_id, record)
        try:
            self.runtime.load_json(pre_state)
            restored = self.runtime.config()
            if canonical_json(restored) != canonical_json(pre_state):
                raise ActivationError("ROLLBACK_READBACK_MISMATCH", "rollback readback does not match pre-state")
            self._health()
            self.coordinator.persist(pre_state)
        except Exception as exc:
            record.update({"rollback_status": "ROLLBACK_FAILED", "rollback_error": str(exc),
                           "rollback_completed_at": utc_now()})
            self._record(execution_id, record)
            journal.update(status="FAILED", error={"code": getattr(exc, "code", "ROLLBACK_FAILED"),
                           "message": str(exc)}, mutation_performed=True, rollback_status="ROLLBACK_FAILED")
            self._record(journal_id, journal)
            raise ActivationError(getattr(exc, "code", "ROLLBACK_FAILED"), str(exc)) from exc
        record.update({"rollback_status": "ROLLED_BACK", "rollback_completed_at": utc_now(),
                       "rollback_state_sha256": sha256_json(restored),
                       "rollback_readback_verified": True, "rollback_health_verified": True})
        self._record(execution_id, record)
        journal.update(status="COMPLETED", mutation_performed=True, health_verified=True,
                       result_state_sha256=sha256_json(restored), completed_at=utc_now())
        self._record(journal_id, journal)
        return self.store.get(execution_id)

    def execution(self, execution_id):
        try:
            record = self.coordinator.ledger.get(execution_id)
        except ExecutionStoreError as exc:
            if str(exc) != "execution_not_found":
                raise
            return self.store.get(execution_id)
        if record.get("engine") != "json":
            raise ExecutionStoreError("execution_not_found")
        record.pop("engine", None)
        return record
