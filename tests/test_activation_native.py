"""Certify lifecycle against the pinned binary on disposable loopback listeners."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from caddy_activation import ActivationError, ActivationManager
from caddy_execution_store import ExecutionStore
from caddy_runtime import CaddyRuntime as FileRuntime, RuntimePaths, RuntimeApplyError, sha256_file
from caddy_runtime_readback import CaddyRuntime, sha256_json


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_ready(process, runtime, log, startup_path=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(log.read_text())
        try:
            runtime.config()
            runtime.check_health()
            if startup_path is not None:
                if not startup_path.exists():
                    time.sleep(.03)
                    continue
                startup = json.loads(startup_path.read_text())
                if startup.get("supervisor_pid") != process.pid:
                    time.sleep(.03)
                    continue
            return
        except Exception:
            time.sleep(.03)
    pytest.fail('Caddy readiness timed out: ' + log.read_text())


@pytest.mark.parametrize('engine', ['json', 'file'])
def test_real_apply_restart_failed_health_recovery_and_rollback(tmp_path, monkeypatch, engine):
    binary = os.environ.get('CADDY_BIN') or shutil.which('caddy')
    if not binary:
        pytest.skip('requires pinned CADDY_BIN')
    monkeypatch.setenv('CADDY_BIN', binary)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    edge, admin = port(), port()
    def source(message, healthy=True):
        return (f'{{\n admin 127.0.0.1:{admin}\n auto_https off\n persist_config off\n}}\n'
                f'http://127.0.0.1:{edge} {{\n respond /ready "ready" {200 if healthy else 503}\n'
                f' respond "{message}"\n}}\n')
    live = tmp_path / 'live.caddy'
    live.write_text(source('old'))
    path = tmp_path / 'candidate.caddy'
    path.write_text(source('new'))
    health = f'http://127.0.0.1:{edge}/ready'
    runtime = CaddyRuntime(f'http://127.0.0.1:{admin}', health_urls=(health,))
    logfile = tmp_path / 'native.log'
    log = logfile.open('w')
    process = subprocess.Popen([binary, 'run', '--config', str(live), '--adapter', 'caddyfile'],
                               stdout=log, stderr=log)
    mgr = None
    file_runtime = FileRuntime(RuntimePaths(live, tmp_path / 'file-state'), caddy_bin=binary,
        admin_url=f'127.0.0.1:{admin}', health_urls=(health,), mutation_enabled=True)
    json_path = tmp_path / 'candidate.json'
    def json_candidate():
        result = subprocess.run([binary, 'adapt', '--config', str(path), '--adapter', 'caddyfile'],
                                capture_output=True, text=True, timeout=10, check=True)
        value = json.loads(result.stdout)
        json_path.write_text(json.dumps(value))
        json_path.with_suffix('.json.meta.json').write_text(json.dumps({
            'candidate_sha256': sha256_json(value), 'source_sha': 'a' * 40}))
    def body():
        with urllib.request.urlopen(f'http://127.0.0.1:{edge}/', timeout=3) as response:
            return response.read()
    try:
        wait_ready(process, runtime, logfile)
        before = runtime.config()
        if engine == 'json':
            json_candidate()
            mgr = ActivationManager(runtime=runtime, store=ExecutionStore(tmp_path / 'history', max_records=1),
                candidate_path=json_path, source_sha_provider=lambda: 'a' * 40, mutation_enabled=True)
            receipt = mgr.apply(idempotency_key='native-apply', expected_active_digest=sha256_json(before))
            coordinator = mgr.coordinator
        else:
            receipt = file_runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                idempotency_key='native-apply', expected_active_digest=sha256_json(before))
            coordinator = file_runtime.coordinator
        assert receipt['health_verified'] is True
        assert body() == b'new'
        accepted = runtime.config()
        assert json.loads(coordinator.active_path.read_text()) == accepted
        process.terminate()
        process.wait(timeout=5)
        # Restart through the supported launcher, with autosave explicitly disabled.
        process = subprocess.Popen([sys.executable, str(ROOT / 'scripts/caddy_restart.py'),
            '--caddy-bin', binary, '--admin-api', runtime.base_url, '--health-url', health],
            stdout=log, stderr=log)
        wait_ready(process, runtime, logfile, coordinator.root / "startup.json")
        assert runtime.config() == accepted
        assert body() == b'new'
        # A valid but unhealthy candidate must restore the healthy accepted state.
        path.write_text(source('unhealthy', False))
        if engine == 'json':
            json_candidate()
            with pytest.raises(ActivationError, match='health'):
                mgr.apply(idempotency_key='native-unhealthy')
        else:
            with pytest.raises(RuntimeApplyError, match='rolled_back'):
                file_runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                                   idempotency_key='native-unhealthy')
        assert runtime.config() == accepted
        assert json.loads(coordinator.active_path.read_text()) == accepted
        # Original rollback remains available even after a later failed apply.
        if engine == 'json':
            mgr.rollback(receipt['execution_id'])
        else:
            # File rollback uses a named execution's exact pre-state, not a mutable singleton backup.
            file_runtime.rollback(execution_id=receipt['execution_id'],
                                  expected_active_digest=sha256_json(accepted))
        assert runtime.config() == before
        assert body() == b'old'
        process.terminate()
        process.wait(timeout=5)
        process = subprocess.Popen([sys.executable, str(ROOT / 'scripts/caddy_restart.py'),
            '--caddy-bin', binary, '--admin-api', runtime.base_url, '--health-url', health],
            stdout=log, stderr=log)
        wait_ready(process, runtime, logfile, coordinator.root / "startup.json")
        assert runtime.config() == before
        assert body() == b'old'
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        log.close()


@pytest.mark.parametrize('engine', ['json', 'file'])
@pytest.mark.parametrize('phase', ['apply', 'rollback'])
def test_killed_controller_is_fenced_until_checked_restart(tmp_path, monkeypatch, engine, phase):
    binary = os.environ.get('CADDY_BIN') or shutil.which('caddy')
    if not binary:
        pytest.skip('requires pinned CADDY_BIN')
    monkeypatch.setenv('CADDY_BIN', binary)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    edge, admin = port(), port()
    def source(message):
        return (f'{{\n admin 127.0.0.1:{admin}\n auto_https off\n persist_config off\n}}\n'
                f'http://127.0.0.1:{edge} {{\n respond /ready "ready"\n respond "{message}"\n}}\n')
    live = tmp_path / 'live.caddy'
    live.write_text(source('old'))
    candidate = tmp_path / 'next.caddy'
    candidate.write_text(source('new'))
    json_path = tmp_path / 'candidate.json'
    adapted = subprocess.run([binary, 'adapt', '--config', str(candidate), '--adapter', 'caddyfile'],
                             text=True, capture_output=True, check=True, timeout=10)
    json_path.write_text(adapted.stdout)
    json_path.with_suffix('.json.meta.json').write_text(json.dumps({
        'candidate_sha256': sha256_json(json.loads(adapted.stdout)), 'source_sha': 'a' * 40}))
    health = f'http://127.0.0.1:{edge}/ready'
    runtime = CaddyRuntime(f'http://127.0.0.1:{admin}', health_urls=(health,))
    mgr = ActivationManager(runtime=runtime, store=ExecutionStore(tmp_path / 'history'),
                            candidate_path=json_path, source_sha_provider=lambda: 'a' * 40, mutation_enabled=True)
    file_runtime = FileRuntime(RuntimePaths(live, tmp_path / 'file-state'), caddy_bin=binary,
                              admin_url=f'127.0.0.1:{admin}', health_urls=(health,), mutation_enabled=True)
    marker = tmp_path / 'load-done'
    logfile = tmp_path / 'crash.log'
    log = logfile.open('w')
    process = subprocess.Popen([binary, 'run', '--config', str(live), '--adapter', 'caddyfile'],
                               stdout=log, stderr=log)
    controller = None
    try:
        wait_ready(process, runtime, logfile)
        initial = runtime.config()
        if phase == 'rollback':
            if engine == 'json':
                receipt = mgr.apply(idempotency_key='completed')
            else:
                receipt = file_runtime.apply(candidate, source_sha='a' * 40,
                    candidate_digest=sha256_file(candidate), idempotency_key='completed')
            execution_id = receipt['execution_id']
        else:
            execution_id = ''
        expected_restart = runtime.config()
        worker = tmp_path / 'controller.py'
        worker.write_text('''import sys, json, threading, subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from caddy_activation import ActivationManager
from caddy_execution_store import ExecutionStore
from caddy_runtime import CaddyRuntime as FileRuntime, RuntimePaths, CommandResult, sha256_file
from caddy_runtime_readback import CaddyRuntime
_, _, directory, binary, admin_url, health, engine, phase, execution_id = sys.argv
root = Path(directory)
def paused():
    (root / 'load-done').write_text('loaded')
    threading.Event().wait()
class PausedRuntime(CaddyRuntime):
    def load_json(self, config):
        super().load_json(config)
        paused()
def paused_runner(argv):
    cp = subprocess.run(argv, text=True, capture_output=True, timeout=10)
    if argv[1] == 'reload' and cp.returncode == 0:
        paused()
    return CommandResult(cp.returncode, cp.stdout, cp.stderr)
if engine == 'json':
    manager = ActivationManager(runtime=PausedRuntime(admin_url, health_urls=(health,)),
        store=ExecutionStore(root / 'history'), candidate_path=root / 'candidate.json',
        source_sha_provider=lambda: 'a' * 40, mutation_enabled=True)
    if phase == 'apply': manager.apply(idempotency_key='crashed')
    else: manager.rollback(execution_id)
else:
    runtime = FileRuntime(RuntimePaths(root / 'live.caddy', root / 'file-state'),
        caddy_bin=binary, admin_url=admin_url, health_urls=(health,), runner=paused_runner, mutation_enabled=True)
    if phase == 'apply': runtime.apply(root / 'next.caddy', source_sha='a' * 40,
        candidate_digest=sha256_file(root / 'next.caddy'), idempotency_key='crashed')
    else: runtime.rollback(execution_id=execution_id)
''')
        controller = subprocess.Popen([sys.executable, str(worker), str(ROOT / 'scripts'),
            str(tmp_path), binary, runtime.base_url, health, engine, phase, execution_id], stdout=log, stderr=log)
        deadline = time.monotonic() + 8
        while not marker.exists() and time.monotonic() < deadline:
            if controller.poll() is not None:
                pytest.fail(logfile.read_text())
            time.sleep(.03)
        assert marker.exists(), logfile.read_text()
        controller.kill()
        controller.wait(timeout=5)
        assert runtime.config() != expected_restart
        with pytest.raises(ActivationError, match='recovery'):
            mgr.apply(idempotency_key='other-command')
        with pytest.raises(RuntimeApplyError, match='recovery'):
            file_runtime.apply(candidate, source_sha='a' * 40,
                candidate_digest=sha256_file(candidate), idempotency_key='other-engine')
        assert json.loads(mgr.coordinator.active_path.read_text()) == expected_restart
        process.terminate()
        process.wait(timeout=5)
        process = subprocess.Popen([sys.executable, str(ROOT / 'scripts/caddy_restart.py'),
            '--caddy-bin', binary, '--admin-api', runtime.base_url, '--health-url', health], stdout=log, stderr=log)
        wait_ready(process, runtime, logfile, mgr.coordinator.root / 'startup.json')
        assert runtime.config() == expected_restart
        mgr.coordinator.ensure_idle()
        records = [mgr.coordinator.ledger.get(i) for i in mgr.coordinator.ledger.list_ids()]
        assert any(row.get('outcome') == 'INTERRUPTED_RESTART_RESTORED' for row in records)
        # A recovered interrupted apply retains a failed key, never re-executes.
        if phase == 'apply' and engine == 'json':
            with pytest.raises(ActivationError, match='idempotency'):
                mgr.apply(idempotency_key='crashed')
        assert initial != json.loads(json_path.read_text())
    finally:
        if controller is not None and controller.poll() is None:
            controller.kill()
            controller.wait(timeout=5)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        log.close()
