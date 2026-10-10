#!/usr/bin/env python3
"""Durable fail-closed Caddy apply/readback/rollback runtime."""
from __future__ import annotations
import urllib.parse
import hashlib, json, os, shutil, subprocess, tempfile, urllib.request, uuid
from caddy_coordination import RuntimeCoordinator, CoordinationError, atomic_json
from caddy_runtime_readback import functional_health
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

class RuntimeApplyError(RuntimeError): pass

@dataclass(frozen=True)
class CommandResult:
    returncode:int; stdout:str=""; stderr:str=""

@dataclass(frozen=True)
class RuntimePaths:
    live_config:Path; state_dir:Path

def sha256_bytes(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def sha256_file(path:Path)->str: return sha256_bytes(path.read_bytes())

def _runner(argv:Sequence[str])->CommandResult:
    cp=subprocess.run(list(argv),capture_output=True,text=True,timeout=30,check=False)
    return CommandResult(cp.returncode,cp.stdout,cp.stderr)

def _health(url:str,timeout:float)->bool:
    return functional_health(url, timeout)

def _runtime_get(url:str,timeout:float)->bytes:
    with urllib.request.urlopen(url,timeout=timeout) as r: return r.read()

class CaddyRuntime:
    def __init__(self,paths:RuntimePaths,*,caddy_bin="caddy",admin_url="127.0.0.1:2019",
                 health_urls:tuple[str,...]|None=None,runner:Callable[[Sequence[str]],CommandResult]=_runner,
                 health_check:Callable[[str,float],bool]=_health,
                 runtime_get:Callable[[str,float],bytes]=_runtime_get, mutation_enabled:bool=False,
                 coordinator:RuntimeCoordinator|None=None)->None:
        parsed = urllib.parse.urlsplit(admin_url if "://" in admin_url else "http://" + admin_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise RuntimeApplyError("admin_url_must_be_loopback")
        self.coordinator = coordinator or RuntimeCoordinator()
        self.paths=paths; self.caddy_bin=caddy_bin; self.admin_url=parsed.netloc
        self.admin_base=parsed.scheme + "://" + parsed.netloc
        self.mutation_enabled=mutation_enabled is True
        self.health_urls=tuple(health_urls if health_urls is not None else os.environ.get("CADDY_ACTIVATION_HEALTH_URLS", "").split())
        self.runner=runner; self.health_check=health_check; self.runtime_get=runtime_get

    def _run(self,argv,step):
        r=self.runner(argv)
        if r.returncode: raise RuntimeApplyError(f"{step}_failed: {(r.stderr or r.stdout).strip()[:500] or r.returncode}")
        return r

    def adapt(self,candidate:Path)->bytes:
        if not candidate.is_file() or not candidate.stat().st_size: raise RuntimeApplyError("candidate_missing_or_empty")
        r=self._run((self.caddy_bin,"adapt","--config",str(candidate),"--adapter","caddyfile","--pretty"),"adapt")
        data=r.stdout.encode()
        if not data.strip(): raise RuntimeApplyError("adapt_empty")
        return data

    def validate(self,candidate:Path)->bytes:
        adapted=self.adapt(candidate)
        self._run((self.caddy_bin,"validate","--config",str(candidate),"--adapter","caddyfile"),"validate")
        return adapted

    def active_readback(self)->dict:
        raw=self.runtime_get(self.admin_base+"/config/",3.0)
        try: canonical=json.dumps(json.loads(raw),sort_keys=True,separators=(",",":")).encode()
        except Exception as exc: raise RuntimeApplyError("runtime_readback_invalid_json") from exc
        return {"active_runtime_sha256":sha256_bytes(canonical),"active_runtime_bytes":len(canonical)}

    def _reload(self,config:Path):
        self._run((self.caddy_bin,"reload","--config",str(config),"--adapter","caddyfile","--address",self.admin_url),"reload")

    def _health(self):
        if not self.health_urls:
            raise RuntimeApplyError("activation_health_not_configured")
        failed=[u for u in self.health_urls if not self.health_check(u,3.0)]
        if failed: raise RuntimeApplyError("health_failed: "+",".join(failed))

    def _install(self,source:Path):
        live=self.paths.live_config; live.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix=f".{live.name}.",dir=str(live.parent))
        try:
            with os.fdopen(fd,"wb") as out,source.open("rb") as src:
                shutil.copyfileobj(src,out); out.flush(); os.fsync(out.fileno())
            os.chmod(tmp,source.stat().st_mode&0o777); os.replace(tmp,live)
        finally:
            try: os.unlink(tmp)
            except FileNotFoundError: pass

    def _history(self, record: dict):
        # Shared ledger is authoritative for retries, including RUNNING receipts.
        self.coordinator.record(record["execution_id"], record, "file")
        directory = self.paths.state_dir
        atomic_json(directory / "executions" / f"{record['execution_id']}.json", record)
        atomic_json(directory / "last-activation.json", record)

    def history(self) -> list[dict]:
        directory = self.paths.state_dir / "executions"
        if not directory.exists():
            return []
        paths = sorted(directory.glob("*.json"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
        return [json.loads(path.read_text()) for path in paths]

    def _lock(self):
        try:
            return self.coordinator.acquire()
        except CoordinationError as exc:
            raise RuntimeApplyError(str(exc)) from exc

    def _config(self):
        value = json.loads(self.runtime_get(self.admin_base + "/config/", 3.0))
        if not isinstance(value, dict):
            raise RuntimeApplyError("runtime_readback_invalid_json")
        return value

    def _restore_json(self, config):
        # Recovery is independent of imports, environment substitution, and the
        # presence of an older source file. This is the exact captured pre-state.
        atomic_json(self.paths.state_dir / "recovery.json", config)
        self._run((self.caddy_bin, "reload", "--config",
                   str(self.paths.state_dir / "recovery.json"), "--address", self.admin_url), "rollback")
        if self._config() != config:
            raise RuntimeApplyError("rollback_runtime_digest_mismatch")
        self._health()
        self.coordinator.persist(config)

    def apply(self, candidate: Path, *, source_sha: str, candidate_digest: str,
              expected_active_digest: str | None = None, idempotency_key: str | None = None) -> dict:
        if not self.mutation_enabled:
            raise RuntimeApplyError("activation_disabled")
        if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
            raise RuntimeApplyError("invalid_source_sha")
        lock = self._lock()
        try:
            candidate = candidate.resolve()
            if not candidate.is_file() or not candidate.stat().st_size:
                raise RuntimeApplyError("candidate_missing_or_empty")
            actual = sha256_file(candidate)
            if actual != candidate_digest:
                raise RuntimeApplyError("candidate_digest_mismatch")
            if idempotency_key:
                if len(idempotency_key) > 128:
                    raise RuntimeApplyError("idempotency_key_invalid")
                try:
                    prior = self.coordinator.prior(idempotency_key, "file", actual, source_sha)
                except CoordinationError as exc:
                    raise RuntimeApplyError(str(exc)) from exc
                if prior:
                    prior.pop("engine", None)
                    prior["schema"] = "codestra.caddy.execution.v2"
                    return prior
                # Preserve retry fencing for installations with legacy history.
                for old in self.history():
                    if old.get("idempotency_key") == idempotency_key:
                        if old.get("source_sha") != source_sha or old.get("candidate_sha256") != actual:
                            raise RuntimeApplyError("idempotency_key_conflict")
                        if old.get("outcome") != "APPLIED":
                            raise RuntimeApplyError("idempotency_failed")
                        return old
            try:
                self.coordinator.ensure_idle()
            except CoordinationError as exc:
                raise RuntimeApplyError(str(exc)) from exc
            adapted = self.validate(candidate)
            desired = json.loads(adapted)
            pre_config = self._config()
            pre_digest = sha256_bytes(json.dumps(pre_config, sort_keys=True, separators=(",", ":")).encode())
            if expected_active_digest and pre_digest != expected_active_digest:
                raise RuntimeApplyError("stale_plan_active_runtime_changed")
            self._health()
            try:
                self.coordinator.baseline(pre_config)
            except CoordinationError as exc:
                raise RuntimeApplyError(str(exc)) from exc
            live = self.paths.live_config
            previous = live.is_file()
            previous_sha = sha256_file(live) if previous else None
            backup = self.paths.state_dir / "last-known-good.caddy"
            self.paths.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if previous:
                shutil.copy2(live, backup)
            expected_runtime = sha256_bytes(json.dumps(desired, sort_keys=True, separators=(",", ":")).encode())
            record = {"schema": "codestra.caddy.execution.v2", "execution_id": str(uuid.uuid4()),
                      "kind": "APPLY", "status": "RUNNING", "outcome": "RUNNING",
                      "source_sha": source_sha, "candidate_sha256": actual,
                      "adapted_sha256": expected_runtime, "previous_file_sha256": previous_sha,
                      "pre_state": pre_config, "idempotency_key": idempotency_key, "runtime_mutated": False}
            self._history(record)
            try:
                if sha256_file(candidate) != actual:
                    raise RuntimeApplyError("candidate_changed_during_validation")
                self._install(candidate)
                self._reload(live)
                active = self.active_readback()
                if active["active_runtime_sha256"] != expected_runtime:
                    raise RuntimeApplyError("active_runtime_digest_mismatch")
                self._health()
                self.coordinator.persist(desired)
                record.update(status="COMPLETED", outcome="APPLIED", runtime_mutated=True,
                              health_verified=True, restart_config_sha256=expected_runtime, **active)
                self._history(record)
                return record
            except Exception as exc:
                rollback_error = None
                try:
                    if previous:
                        self._install(backup)
                    elif live.exists():
                        live.unlink()
                    self._restore_json(pre_config)
                    outcome = "ROLLED_BACK"
                except Exception as recovery_exc:
                    outcome = "ROLLBACK_FAILED"
                    rollback_error = str(recovery_exc)
                record.update(kind="AUTO_ROLLBACK", status="FAILED", outcome=outcome,
                              error=str(exc), rollback_error=rollback_error, runtime_mutated=True)
                self._history(record)
                raise RuntimeApplyError(f"activation_failed_{outcome.lower()}: {exc}") from exc
        finally:
            self.coordinator.release(lock)

    def rollback(self, *, expected_active_digest: str | None = None,
                 execution_id: str | None = None) -> dict:
        if not self.mutation_enabled:
            raise RuntimeApplyError("activation_disabled")
        lock = self._lock()
        try:
            try:
                self.coordinator.ensure_idle()
            except CoordinationError as exc:
                raise RuntimeApplyError(str(exc)) from exc
            if execution_id is None:
                for identifier in self.coordinator.ledger.list_ids():
                    row = self.coordinator.ledger.get(identifier)
                    if (row.get("engine") == "file" and row.get("kind") == "APPLY"
                            and row.get("outcome") == "APPLIED" and row.get("status") == "COMPLETED"):
                        execution_id = identifier
                        break
            if execution_id is None:
                raise RuntimeApplyError("rollback_execution_required: no retained successful activation")
            return self._rollback_execution(execution_id, expected_active_digest)
        finally:
            self.coordinator.release(lock)

    def _rollback_execution(self, execution_id, expected_active_digest):
        original = self.coordinator.ledger.get(execution_id)
        if (original.get("engine") != "file" or original.get("outcome") != "APPLIED"
                or original.get("status") != "COMPLETED"):
            raise RuntimeApplyError("rollback_execution_not_completed")
        before = self.active_readback()
        current = before["active_runtime_sha256"]
        if (current != original.get("active_runtime_sha256")
                or (expected_active_digest and current != expected_active_digest)):
            raise RuntimeApplyError("stale_rollback_active_runtime_changed")
        pre_state = original.get("pre_state")
        if not isinstance(pre_state, dict):
            raise RuntimeApplyError("rollback_state_missing")
        if not self.health_urls:
            raise RuntimeApplyError("activation_health_not_configured")
        record = {"schema": "codestra.caddy.execution.v2", "execution_id": str(uuid.uuid4()),
                  "kind": "MANUAL_ROLLBACK", "status": "RUNNING", "outcome": "RUNNING",
                  "rollback_of": execution_id, "pre_state": self._config(), "runtime_mutated": False}
        self._history(record)
        try:
            self._restore_json(pre_state)
            record.update(status="COMPLETED", outcome="ROLLED_BACK", runtime_mutated=True,
                          health_verified=True, **self.active_readback())
        except Exception as exc:
            record.update(status="FAILED", outcome="ROLLBACK_FAILED", error=str(exc), runtime_mutated=True)
            self._history(record)
            raise RuntimeApplyError(f"rollback_failed: {exc}") from exc
        self._history(record)
        return record
