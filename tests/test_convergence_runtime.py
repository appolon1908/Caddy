from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from caddy_runtime import CaddyRuntime, RuntimePaths, RuntimeApplyError
from caddy_route_compiler import load_authority, compile_caddy, RouteAuthorityError


def test_file_runtime_mutations_disabled_by_default(tmp_path):
    runtime = CaddyRuntime(RuntimePaths(tmp_path / 'live', tmp_path / 'state'))
    with pytest.raises(RuntimeApplyError, match='activation_disabled'):
        runtime.apply(tmp_path / 'candidate', source_sha='a' * 40, candidate_digest='b' * 64)
    with pytest.raises(RuntimeApplyError, match='activation_disabled'):
        runtime.rollback()
    assert not (tmp_path / 'state').exists()


@pytest.mark.parametrize('url', ['0.0.0.0:2019', 'https://public.example:2019', 'http://127.0.0.1:2019@evil.example', '127.0.0.1:2019/config/'])
def test_file_runtime_rejects_non_private_or_ambiguous_admin(tmp_path, url):
    with pytest.raises((RuntimeApplyError, ValueError), match='admin'):
        CaddyRuntime(RuntimePaths(tmp_path / 'live', tmp_path / 'state'), admin_url=url)


@pytest.mark.parametrize(('field', 'value'), [('host', 'api.example {\n respond 200\n}'), ('path', '/ok\n respond 200'), ('body_limit', '10MB\n respond 200')])
def test_route_authority_rejects_caddyfile_injection(field, value):
    authority = load_authority(ROOT / "tests/fixtures/caddy-route-authority.v1.json")
    route = authority['routes'][0]
    if field == 'path':
        route.pop('path_prefix', None)
    route[field] = value
    with pytest.raises(RouteAuthorityError):
        compile_caddy(authority)


def test_json_runtime_validates_modules_without_mutation():
    import os, shutil
    from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError
    if not (os.environ.get('CADDY_BIN') or shutil.which('caddy')):
        pytest.skip('requires CADDY_BIN')
    runtime = CaddyRuntime(transport=lambda *_: (200, b'{}'))
    with pytest.raises(RuntimeReadbackError, match='validation'):
        runtime.validate_json({'apps': {'nonexistent_app': {}}})


def test_concurrent_control_mutations_are_serialized(tmp_path):
    import json, threading
    from concurrent.futures import ThreadPoolExecutor
    from caddy_activation import ActivationManager, ActivationError
    from caddy_execution_store import ExecutionStore
    from caddy_runtime_readback import sha256_json
    entered, release = threading.Event(), threading.Event()
    class Runtime:
        loads = 0
        validations = 0
        current = {}
        def config(self): return self.current
        def validate_json(self, config):
            self.validations += 1
            if self.validations == 1:
                entered.set()
                assert release.wait(5)
        def check_health(self): pass
        def load_json(self, config):
            self.loads += 1
            self.current = config
    runtime = Runtime()
    path = tmp_path / 'candidate.json'; path.write_text('{"new":true}')
    path.with_suffix('.json.meta.json').write_text(json.dumps({'candidate_sha256': sha256_json({'new': True})}))
    manager = ActivationManager(runtime=runtime, store=ExecutionStore(tmp_path / 'history'), candidate_path=path, mutation_enabled=True)
    with ThreadPoolExecutor() as pool:
        first = pool.submit(manager.apply, idempotency_key='same')
        assert entered.wait(3)
        try:
            with pytest.raises(ActivationError, match='in progress'):
                manager.apply(idempotency_key='same')
        finally:
            release.set()
        first.result()
    assert runtime.loads == 1
    assert manager.apply(idempotency_key='same')['status'] == 'COMPLETED'
    assert runtime.loads == 1


def test_native_validator_failure_does_not_mutate_runtime(tmp_path):
    import os, shutil
    from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError
    if not (os.environ.get('CADDY_BIN') or shutil.which('caddy')):
        pytest.skip('requires CADDY_BIN')
    blocked_parent = tmp_path / 'not-a-directory'; blocked_parent.write_text('file')
    config = {'logging': {'logs': {'default': {'writer': {'output': 'file', 'filename': str(blocked_parent / 'access.log')}}}}}
    calls = []
    runtime = CaddyRuntime(transport=lambda *args: calls.append(args))
    with pytest.raises(RuntimeReadbackError, match='validation'):
        runtime.validate_json(config)
    assert calls == []


def test_control_source_identity_refuses_dirty_authority(tmp_path, monkeypatch):
    import subprocess
    import caddy_control_api
    from caddy_activation import ActivationError
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    for key, value in [('user.email', 'test@example.invalid'), ('user.name', 'Test')]:
        subprocess.run(['git', '-C', str(tmp_path), 'config', key, value], check=True)
    (tmp_path / 'Caddyfile').write_text('initial')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'commit', '-qm', 'initial'], check=True)
    monkeypatch.setattr(caddy_control_api, 'ROOT', tmp_path)
    assert len(caddy_control_api.ControlService._git_source_sha()) == 40
    (tmp_path / 'Caddyfile').write_text('changed')
    with pytest.raises(ActivationError, match='dirty'):
        caddy_control_api.ControlService._git_source_sha()
