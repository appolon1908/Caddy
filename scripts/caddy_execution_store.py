#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ExecutionStoreError(RuntimeError):
    pass


class ExecutionStore:
    def __init__(self, root: Path, *, max_records: int = 200) -> None:
        self.root = root
        self.max_records = max_records
        if max_records < 1:
            raise ValueError("max_records must be positive")

    def _path(self, execution_id: str) -> Path:
        if not ID_RE.fullmatch(execution_id):
            raise ExecutionStoreError("invalid_execution_id")
        return self.root / f"{execution_id}.json"

    def _atomic_write(self, path: Path, payload: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        fd, temp_name = tempfile.mkstemp(prefix=".execution.", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def put(self, execution_id: str, payload: dict[str, Any]) -> None:
        path = self._path(execution_id)
        document = {
            "schema": "codestra.caddy.execution-record.v1",
            "execution_id": execution_id,
            **payload,
        }
        self._atomic_write(path, document)
        self._prune()

    def get(self, execution_id: str) -> dict[str, Any]:
        path = self._path(execution_id)
        if not path.exists():
            raise ExecutionStoreError("execution_not_found")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExecutionStoreError("execution_record_corrupt") from exc
        if value.get("schema") != "codestra.caddy.execution-record.v1":
            raise ExecutionStoreError("execution_record_schema_invalid")
        if value.get("execution_id") != execution_id:
            raise ExecutionStoreError("execution_record_id_mismatch")
        return value

    def list_ids(self) -> list[str]:
        if not self.root.exists():
            return []
        rows = sorted(
            (path for path in self.root.glob("*.json") if path.is_file()),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        return [path.stem for path in rows]

    def _prune(self) -> None:
        ids = self.list_ids()
        for execution_id in ids[self.max_records :]:
            self._path(execution_id).unlink(missing_ok=True)
