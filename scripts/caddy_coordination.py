"""One private lock, restart authority and durable receipt ledger for both engines."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from pathlib import Path

from caddy_execution_store import ExecutionStore


class CoordinationError(RuntimeError):
    pass


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, sort_keys=True, ensure_ascii=False)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class RuntimeCoordinator:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(os.environ.get(
            'CADDY_CONTROL_STATE_DIR',
            str(Path.home() / '.local/state/codestra-caddy-control/runtime'),
        ))
        self.active_path = self.root / 'active.json'
        self.ledger = ExecutionStore(self.root / 'executions')

    def acquire(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = (self.root / 'mutation.lock').open('a')
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise CoordinationError('activation_in_progress') from exc
        return handle

    @staticmethod
    def release(handle):
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()

    def persist(self, config: dict) -> None:
        atomic_json(self.active_path, config)

    def ensure_idle(self):
        for execution_id in self.ledger.list_ids():
            record = self.ledger.get(execution_id)
            if record.get("status") == "RUNNING":
                raise CoordinationError("recovery_required: interrupted runtime operation")

    def baseline(self, config):
        if self.active_path.exists():
            try:
                accepted = json.loads(self.active_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise CoordinationError("restart authority is unreadable") from exc
            if accepted != config:
                raise CoordinationError("runtime differs from accepted restart authority")
        else:
            self.persist(config)

    def recover_interrupted(self, config):
        # Called only under the startup lock after exact readback and functional
        # health. Recovery restores the last accepted checkpoint, never guesses.
        if json.loads(self.active_path.read_text(encoding="utf-8")) != config:
            raise CoordinationError("restart authority changed during recovery")
        for execution_id in self.ledger.list_ids():
            record = self.ledger.get(execution_id)
            if record.get("status") != "RUNNING":
                continue
            record.update(status="FAILED", outcome="INTERRUPTED_RESTART_RESTORED",
                          rollback_status="RESTART_RESTORED",
                          error={"code": "OPERATION_INTERRUPTED", "message": "accepted restart checkpoint restored"},
                          recovery_health_verified=True)
            self.ledger.put(execution_id, record)
            rollback_of = record.get("rollback_of")
            if rollback_of and record.get("engine") == "json":
                original = self.ledger.get(rollback_of)
                original.update(rollback_status="INTERRUPTED_RESTART_RESTORED")
                self.ledger.put(rollback_of, original)

    def prior(self, key: str, engine: str, candidate_sha: str, source_sha=None):
        # Mutating receipts are never pruned. A corrupt ledger fails closed.
        for execution_id in self.ledger.list_ids():
            row = self.ledger.get(execution_id)
            if row.get('idempotency_key') != key:
                continue
            if (row.get('engine') != engine or row.get('candidate_sha256') != candidate_sha
                    or row.get('source_sha') != source_sha):
                raise CoordinationError('idempotency_conflict: different candidate or engine')
            if row.get('status') != 'COMPLETED':
                raise CoordinationError('idempotency_' + str(row.get('status', 'indeterminate')).lower())
            return row
        return None

    def record(self, execution_id: str, record: dict, engine: str):
        self.ledger.put(execution_id, {**record, 'engine': engine,
                                     'schema': 'codestra.caddy.execution-record.v1'})
