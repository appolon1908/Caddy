#!/usr/bin/env python3
"""Durable fail-closed Caddy apply/readback/rollback runtime."""
from __future__ import annotations
import fcntl, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.request, uuid
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
    try:
        with urllib.request.urlopen(url,timeout=timeout) as r: return 200<=r.status<400
    except Exception: return False

def _runtime_get(url:str,timeout:float)->bytes:
    with urllib.request.urlopen(url,timeout=timeout) as r: return r.read()

class CaddyRuntime:
    def __init__(self,paths:RuntimePaths,*,caddy_bin="caddy",admin_url="127.0.0.1:2019",
                 health_urls:tuple[str,...]=(),runner:Callable[[Sequence[str]],CommandResult]=_runner,
                 health_check:Callable[[str,float],bool]=_health,
                 runtime_get:Callable[[str,float],bytes]=_runtime_get)->None:
        self.paths=paths; self.caddy_bin=caddy_bin; self.admin_url=admin_url.removeprefix("http://").removeprefix("https://").rstrip("/")
        self.health_urls=health_urls; self.runner=runner; self.health_check=health_check; self.runtime_get=runtime_get

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
        raw=self.runtime_get("http://"+self.admin_url+"/config/",3.0)
        try: canonical=json.dumps(json.loads(raw),sort_keys=True,separators=(",",":")).encode()
        except Exception as exc: raise RuntimeApplyError("runtime_readback_invalid_json") from exc
        return {"active_runtime_sha256":sha256_bytes(canonical),"active_runtime_bytes":len(canonical)}

    def _reload(self,config:Path):
        self._run((self.caddy_bin,"reload","--config",str(config),"--adapter","caddyfile","--address",self.admin_url),"reload")

    def _health(self):
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

    def _history(self,e:dict):
        d=self.paths.state_dir; d.mkdir(parents=True,exist_ok=True)
        (d/"executions").mkdir(exist_ok=True)
        body=json.dumps(e,sort_keys=True,indent=2)+"\n"
        (d/"executions"/f"{e['execution_id']}.json").write_text(body)
        (d/"last-activation.json").write_text(body)

    def history(self)->list[dict]:
        d=self.paths.state_dir/"executions"
        if not d.exists(): return []
        return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"),reverse=True)]

    def _lock(self):
        self.paths.state_dir.mkdir(parents=True,exist_ok=True)
        fh=(self.paths.state_dir/"apply.lock").open("a+")
        try: fcntl.flock(fh,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            fh.close(); raise RuntimeApplyError("apply_in_progress")
        return fh

    def apply(self,candidate:Path,*,source_sha:str,candidate_digest:str,expected_active_digest:str|None=None,idempotency_key:str|None=None)->dict:
        if len(source_sha)!=40 or any(c not in "0123456789abcdef" for c in source_sha): raise RuntimeApplyError("invalid_source_sha")
        lock=self._lock()
        try:
            execution_id=str(uuid.uuid4()); candidate=candidate.resolve()
            if not candidate.is_file() or not candidate.stat().st_size: raise RuntimeApplyError("candidate_missing_or_empty")
            actual=sha256_file(candidate)
            if actual!=candidate_digest: raise RuntimeApplyError("candidate_digest_mismatch")
            adapted=self.validate(candidate)
            active_before=self.active_readback()
            if expected_active_digest and active_before["active_runtime_sha256"]!=expected_active_digest:
                raise RuntimeApplyError("stale_plan_active_runtime_changed")
            if idempotency_key:
                for old in self.history():
                    if old.get("idempotency_key")==idempotency_key:
                        if old.get("source_sha")!=source_sha or old.get("candidate_sha256")!=actual:
                            raise RuntimeApplyError("idempotency_key_conflict")
                        return old
            live=self.paths.live_config; previous=live.is_file(); previous_sha=sha256_file(live) if previous else None
            backup=self.paths.state_dir/"last-known-good.caddy"
            if previous: shutil.copy2(live,backup)
            expected_runtime=sha256_bytes(json.dumps(json.loads(adapted),sort_keys=True,separators=(",",":")).encode())
            installed=False
            try:
                self._install(candidate); installed=True; self._reload(live)
                active=self.active_readback()
                if active["active_runtime_sha256"]!=expected_runtime: raise RuntimeApplyError("active_runtime_digest_mismatch")
                self._health()
                e={"schema":"codestra.caddy.execution.v2","execution_id":execution_id,"kind":"APPLY","outcome":"APPLIED",
                   "source_sha":source_sha,"candidate_sha256":actual,"adapted_sha256":expected_runtime,
                   "previous_file_sha256":previous_sha,**active,"idempotency_key":idempotency_key,"runtime_mutated":True}
                self._history(e); return e
            except Exception as exc:
                if installed and previous and backup.is_file():
                    self._install(backup); restored_adapted=self.validate(live); self._reload(live); self._health()
                    rb=self.active_readback()
                    expected_rb=sha256_bytes(json.dumps(json.loads(restored_adapted),sort_keys=True,separators=(",",":")).encode())
                    if rb["active_runtime_sha256"]!=expected_rb: raise RuntimeApplyError(f"rollback_runtime_digest_mismatch_after:{exc}")
                    e={"schema":"codestra.caddy.execution.v2","execution_id":execution_id,"kind":"AUTO_ROLLBACK","outcome":"ROLLED_BACK",
                       "source_sha":source_sha,"candidate_sha256":actual,"previous_file_sha256":previous_sha,**rb,"error":str(exc),
                       "idempotency_key":idempotency_key,"runtime_mutated":True}
                    self._history(e)
                raise RuntimeApplyError(f"activation_failed_rolled_back: {exc}") from exc
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN); lock.close()

    def rollback(self,*,expected_active_digest:str|None=None)->dict:
        lock=self._lock()
        try:
            backup=self.paths.state_dir/"last-known-good.caddy"
            if not backup.is_file(): raise RuntimeApplyError("no_last_known_good")
            before=self.active_readback()
            if expected_active_digest and before["active_runtime_sha256"]!=expected_active_digest:
                raise RuntimeApplyError("stale_rollback_active_runtime_changed")
            execution_id=str(uuid.uuid4()); adapted=self.validate(backup); self._install(backup); self._reload(self.paths.live_config); self._health()
            active=self.active_readback()
            expected=sha256_bytes(json.dumps(json.loads(adapted),sort_keys=True,separators=(",",":")).encode())
            if active["active_runtime_sha256"]!=expected: raise RuntimeApplyError("rollback_active_runtime_digest_mismatch")
            e={"schema":"codestra.caddy.execution.v2","execution_id":execution_id,"kind":"MANUAL_ROLLBACK","outcome":"ROLLED_BACK",**active,"runtime_mutated":True}
            self._history(e); return e
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN); lock.close()
