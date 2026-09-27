from __future__ import annotations
import json,sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"scripts"))
from caddy_runtime import CaddyRuntime,CommandResult,RuntimeApplyError,RuntimePaths,sha256_file

SOURCE="a"*40
def runtime(tmp_path, runner, health=lambda _u,_t:True):
    live=tmp_path/"live"/"Caddyfile"; state=tmp_path/"state"; active={"value":b'{"apps":{"http":{"servers":{}}}}'}
    def get(_url,_timeout): return active["value"]
    rt=CaddyRuntime(RuntimePaths(live,state),runner=runner,health_check=health,health_urls=("http://127.0.0.1/health",),runtime_get=get)
    return rt,live,state,active
def runner_for(active,fail_reload=False):
    reloads=0
    def run(argv):
        nonlocal reloads
        if argv[1]=="adapt":
            text=Path(argv[argv.index("--config")+1]).read_text()
            return CommandResult(0,json.dumps({"config":text}))
        if argv[1]=="reload":
            reloads+=1
            if fail_reload and reloads==1:return CommandResult(1,stderr="reload rejected")
            text=Path(argv[argv.index("--config")+1]).read_text()
            active["value"]=json.dumps({"config":text}).encode()
        return CommandResult(0)
    return run

def test_apply_adapt_validate_reload_active_readback_history(tmp_path):
    active={"value":b'{"config":"old\\n"}'}
    rt,live,state,_=runtime(tmp_path,lambda a:CommandResult(0))
    rt.runtime_get=lambda *_:active["value"]; rt.runner=runner_for(active)
    live.parent.mkdir(); live.write_text("old\n"); c=tmp_path/"candidate"; c.write_text("new\n")
    r=rt.apply(c,source_sha=SOURCE,candidate_digest=sha256_file(c),expected_active_digest=rt.active_readback()["active_runtime_sha256"],idempotency_key="k1")
    assert r["outcome"]=="APPLIED" and r["execution_id"]
    assert len(rt.history())==1

def test_stale_plan_rejected_before_mutation(tmp_path):
    active={"value":b'{"config":"old\\n"}'}; rt,live,_,_=runtime(tmp_path,lambda a:CommandResult(0)); rt.runtime_get=lambda *_:active["value"]; rt.runner=runner_for(active)
    live.parent.mkdir(); live.write_text("old\n"); c=tmp_path/"c"; c.write_text("new\n")
    with pytest.raises(RuntimeApplyError,match="stale_plan"): rt.apply(c,source_sha=SOURCE,candidate_digest=sha256_file(c),expected_active_digest="0"*64)
    assert live.read_text()=="old\n"

def test_candidate_digest_and_source_sha_are_required(tmp_path):
    rt,live,_,_=runtime(tmp_path,lambda a:CommandResult(0)); c=tmp_path/"c"; c.write_text("new")
    with pytest.raises(RuntimeApplyError,match="invalid_source_sha"): rt.apply(c,source_sha="short",candidate_digest=sha256_file(c))
    with pytest.raises(RuntimeApplyError,match="candidate_digest_mismatch"): rt.apply(c,source_sha=SOURCE,candidate_digest="0"*64)

def test_idempotency_replays_same_execution(tmp_path):
    active={"value":b'{"config":"old\\n"}'}; rt,live,_,_=runtime(tmp_path,lambda a:CommandResult(0)); rt.runtime_get=lambda *_:active["value"]; rt.runner=runner_for(active)
    live.parent.mkdir(); live.write_text("old\n"); c=tmp_path/"c"; c.write_text("new\n")
    first=rt.apply(c,source_sha=SOURCE,candidate_digest=sha256_file(c),idempotency_key="same")
    second=rt.apply(c,source_sha=SOURCE,candidate_digest=sha256_file(c),idempotency_key="same")
    assert second["execution_id"]==first["execution_id"]

def test_reload_failure_rolls_back_and_verifies_active_runtime(tmp_path):
    active={"value":b'{"config":"old\\n"}'}; rt,live,state,_=runtime(tmp_path,lambda a:CommandResult(0)); rt.runtime_get=lambda *_:active["value"]; rt.runner=runner_for(active,True)
    live.parent.mkdir(); live.write_text("old\n"); c=tmp_path/"c"; c.write_text("new\n")
    with pytest.raises(RuntimeApplyError,match="rolled_back"): rt.apply(c,source_sha=SOURCE,candidate_digest=sha256_file(c))
    assert live.read_text()=="old\n"; assert rt.history()[0]["kind"]=="AUTO_ROLLBACK"

def test_manual_rollback_has_history_and_active_digest(tmp_path):
    active={"value":b'{"config":"old\\n"}'}; rt,live,state,_=runtime(tmp_path,lambda a:CommandResult(0)); rt.runtime_get=lambda *_:active["value"]; rt.runner=runner_for(active)
    live.parent.mkdir(); live.write_text("old\n"); state.mkdir(); (state/"last-known-good.caddy").write_text("known-good\n")
    r=rt.rollback(expected_active_digest=rt.active_readback()["active_runtime_sha256"])
    assert r["kind"]=="MANUAL_ROLLBACK" and r["active_runtime_sha256"]
    assert live.read_text()=="known-good\n"
