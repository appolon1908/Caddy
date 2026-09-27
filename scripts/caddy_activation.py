#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    ) -> None:
        self.runtime = runtime
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

    def _preflight(self, candidate_sha: str, candidate: dict[str, Any]) -> dict[str, Any]:
        if not self.candidate_metadata_path.exists():
            raise ActivationError("CANDIDATE_METADATA_MISSING", "candidate metadata is missing")
        try:
            meta = json.loads(self.candidate_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ActivationError("CANDIDATE_METADATA_INVALID", "candidate metadata is invalid") from exc
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

    def apply(self, *, idempotency_key: str) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ActivationError("IDEMPOTENCY_KEY_INVALID", "valid idempotency key is required")

        candidate_sha, candidate = self._candidate()
        for existing_id in self.store.list_ids():
            try:
                existing = self.store.get(existing_id)
            except ExecutionStoreError:
                continue
            if existing.get("idempotency_key") == idempotency_key:
                if existing.get("candidate_sha256") != candidate_sha:
                    raise ActivationError("IDEMPOTENCY_CONFLICT", "idempotency key was used with a different candidate")
                return existing
        metadata = self._preflight(candidate_sha, candidate)

        execution_id = str(uuid.uuid4())
        pre_config = self.runtime.config()
        pre_sha = sha256_json(pre_config)
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
        self.store.put(execution_id, record)

        try:
            self.runtime.load_json(candidate)
            readback = self.runtime.config()
            result_sha = sha256_json(readback)
            if canonical_json(readback) != canonical_json(candidate):
                raise ActivationError("READBACK_MISMATCH", "runtime readback does not match candidate")
            record.update(
                {
                    "status": "COMPLETED",
                    "result_state_sha256": result_sha,
                    "rollback_status": "NOT_REQUIRED",
                    "readback_verified": True,
                    "mutation_performed": True,
                    "rollback_status": "NOT_REQUIRED",
                    "readback_verified": True,
                    "completed_at": utc_now(),
                }
            )
            self.store.put(execution_id, record)
            return self.store.get(execution_id)
        except Exception as exc:
            rollback_status = "NOT_ATTEMPTED"
            rollback_error = None
            try:
                self.runtime.load_json(pre_config)
                restored = self.runtime.config()
                if canonical_json(restored) != canonical_json(pre_config):
                    raise ActivationError("ROLLBACK_READBACK_MISMATCH", "rollback readback does not match pre-state")
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
            self.store.put(execution_id, record)
            raise ActivationError(record["error"]["code"], record["error"]["message"]) from exc

    def rollback(self, execution_id: str) -> dict[str, Any]:
        if not self.mutation_enabled:
            raise ActivationError("ACTIVATION_DISABLED", "Caddy runtime activation is disabled")
        record = self.store.get(execution_id)
        pre_state = record.get("pre_state")
        if not isinstance(pre_state, dict):
            raise ActivationError("ROLLBACK_STATE_MISSING", "execution has no restorable pre-state")
        self.runtime.validate_json(pre_state)
        self.runtime.load_json(pre_state)
        restored = self.runtime.config()
        if canonical_json(restored) != canonical_json(pre_state):
            raise ActivationError("ROLLBACK_READBACK_MISMATCH", "rollback readback does not match pre-state")
        record.update({"rollback_status": "ROLLED_BACK", "rollback_completed_at": utc_now(), "rollback_state_sha256": sha256_json(restored), "rollback_readback_verified": True})
        self.store.put(execution_id, record)
        return self.store.get(execution_id)
