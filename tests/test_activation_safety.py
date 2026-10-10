"""Regression coverage for activation lifecycle, durable state and coordination."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from caddy_activation import ActivationError, ActivationManager
from caddy_execution_store import ExecutionStore
from caddy_runtime import CaddyRuntime as FileRuntime, RuntimePaths, RuntimeApplyError
from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError, sha256_json


class Runtime:
    def __init__(self):
        self.current = {'version': 0}
        self.loads = []
        self.probes = []
        self.fail_version = None
    def config(self):
        return self.current
    def validate_json(self, value):
        pass
    def load_json(self, value):
        self.loads.append(value)
        self.current = value
    def check_health(self):
        self.probes.append(self.current['version'])
        if self.current['version'] == self.fail_version:
            raise RuntimeReadbackError('HEALTH_FAILED', 'functional health failed')


def manager(tmp_path, runtime=None, max_records=2):
    path = tmp_path / 'candidate.json'
    path.write_text(json.dumps({'version': 1}))
    path.with_suffix('.json.meta.json').write_text(json.dumps({
        'candidate_sha256': sha256_json({'version': 1}), 'source_sha': 'a' * 40,
    }))
    runtime = runtime or Runtime()
    return ActivationManager(runtime=runtime, candidate_path=path,
        source_sha_provider=lambda: 'a' * 40,
        store=ExecutionStore(tmp_path / 'evidence', max_records=max_records),
        mutation_enabled=True), runtime


def test_activation_checks_functional_health_before_and_after_load(tmp_path):
    mgr, rt = manager(tmp_path)
    receipt = mgr.apply(idempotency_key='health')
    assert rt.probes == [0, 1]
    assert receipt['health_verified'] is True


def test_unhealthy_candidate_restores_runtime_and_restart_authority(tmp_path):
    mgr, rt = manager(tmp_path)
    rt.fail_version = 1
    with pytest.raises(ActivationError, match='health'):
        mgr.apply(idempotency_key='unhealthy')
    assert rt.current == {'version': 0}
    assert rt.probes == [0, 1, 0]
    assert json.loads(mgr.coordinator.active_path.read_text()) == rt.current
    record = mgr.store.get(mgr.store.list_ids()[0])
    assert record['status'] == 'FAILED'
    assert record['rollback_status'] == 'ROLLED_BACK'


def test_unhealthy_pre_state_prevents_any_load(tmp_path):
    mgr, rt = manager(tmp_path)
    rt.fail_version = 0
    with pytest.raises(ActivationError, match='health'):
        mgr.apply(idempotency_key='bad-baseline')
    assert rt.loads == []


def test_runtime_activation_rejects_missing_health_configuration():
    runtime = CaddyRuntime()
    with pytest.raises(RuntimeReadbackError, match='health'):
        runtime.check_health()


def test_restart_authority_tracks_apply_and_manual_rollback(tmp_path):
    mgr, rt = manager(tmp_path)
    record = mgr.apply(idempotency_key='persist')
    assert json.loads(mgr.coordinator.active_path.read_text()) == {'version': 1}
    mgr.rollback(record['execution_id'])
    assert json.loads(mgr.coordinator.active_path.read_text()) == {'version': 0}
    assert rt.probes[-1] == 0


def test_failed_json_rollback_restores_healthy_current_config(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='rollback-recovery')
    rt.fail_version = 0
    with pytest.raises(ActivationError):
        mgr.rollback(first['execution_id'])
    assert rt.current == {'version': 1}
    assert json.loads(mgr.coordinator.active_path.read_text()) == rt.current
    assert mgr.execution(first['execution_id'])['rollback_recovery_verified'] is True


def test_json_rollback_rejects_live_state_older_than_checkpoint(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='checkpoint-fence')
    mgr.coordinator.persist({'version': 2})
    count = len(rt.loads)
    with pytest.raises(ActivationError, match='restart authority'):
        mgr.rollback(first['execution_id'])
    assert len(rt.loads) == count


def test_failed_file_rollback_restores_healthy_current_config(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='rollback-recovery')
    accepted = value['current'].copy()
    runtime.health_check = lambda *_: value['current'] == accepted
    with pytest.raises(RuntimeApplyError):
        runtime.rollback(execution_id=first['execution_id'])
    assert value['current'] == accepted
    assert json.loads(runtime.coordinator.active_path.read_text()) == accepted


def test_file_rollback_rejects_live_state_older_than_checkpoint(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='checkpoint-fence')
    accepted = value['current'].copy()
    runtime.coordinator.persist({'config': 'later accepted'})
    with pytest.raises(RuntimeApplyError, match='restart authority'):
        runtime.rollback(execution_id=first['execution_id'])
    assert value['current'] == accepted


def test_json_rollback_failed_recovery_fences_further_mutation(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='double-failure')
    def fail_load(value):
        rt.current = value
        raise RuntimeError('admin unavailable after load')
    rt.load_json = fail_load
    with pytest.raises(ActivationError):
        mgr.rollback(first['execution_id'])
    with pytest.raises(ActivationError, match='recovery'):
        mgr.apply(idempotency_key='must-be-fenced')
    assert json.loads(mgr.coordinator.active_path.read_text()) == {'version': 1}


def test_json_rollback_can_recover_an_unhealthy_current_config(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='unhealthy-current')
    rt.fail_version = 1
    mgr.rollback(first['execution_id'])
    assert rt.current == {'version': 0}


def test_file_rollback_can_recover_an_unhealthy_current_config(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='unhealthy-current')
    runtime.health_check = lambda *_: value['current'] == {'config': 'old'}
    runtime.rollback(execution_id=first['execution_id'])
    assert value['current'] == {'config': 'old'}


def test_file_rollback_failed_recovery_fences_further_mutation(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='double-failure')
    runtime._restore_json = lambda *_: (_ for _ in ()).throw(RuntimeError('admin unavailable'))
    with pytest.raises(RuntimeApplyError):
        runtime.rollback(execution_id=first['execution_id'])
    with pytest.raises(RuntimeApplyError, match='recovery'):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='must-be-fenced')


def test_completed_idempotency_survives_dry_run_retention_churn(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='forever')
    for _ in range(8):
        mgr.dry_run()
    second = mgr.apply(idempotency_key='forever')
    assert second == first
    assert len(rt.loads) == 1
    assert mgr.store.get(first['execution_id'])['pre_state'] == {'version': 0}


def test_failed_idempotency_survives_retention_churn(tmp_path):
    mgr, rt = manager(tmp_path)
    rt.fail_version = 1
    with pytest.raises(ActivationError):
        mgr.apply(idempotency_key='failed')
    for _ in range(8):
        mgr.dry_run()
    rt.fail_version = None
    loads = len(rt.loads)
    with pytest.raises(ActivationError):
        mgr.apply(idempotency_key='failed')
    assert len(rt.loads) == loads


def test_json_apply_fences_expected_pre_state(tmp_path):
    mgr, rt = manager(tmp_path)
    with pytest.raises(ActivationError, match='runtime changed'):
        mgr.apply(idempotency_key='stale', expected_active_digest='0' * 64)
    assert rt.loads == []


def test_engines_share_lock_even_with_different_evidence_directories(tmp_path):
    mgr, _ = manager(tmp_path)
    file_runtime = FileRuntime(RuntimePaths(tmp_path / 'live', tmp_path / 'file-state'),
                               mutation_enabled=True)
    with mgr._mutation_lock():
        with pytest.raises(RuntimeApplyError, match='in_progress'):
            file_runtime.apply(tmp_path / 'missing', source_sha='a' * 40,
                               candidate_digest='b' * 64)


def test_json_lock_blocks_file_rollback(tmp_path):
    mgr, _ = manager(tmp_path)
    file_runtime = FileRuntime(RuntimePaths(tmp_path / 'live', tmp_path / 'file-state'),
                               mutation_enabled=True)
    with mgr._mutation_lock():
        with pytest.raises(RuntimeApplyError, match='in_progress'):
            file_runtime.rollback()


def test_dry_run_rejects_stale_metadata(tmp_path):
    mgr, rt = manager(tmp_path)
    mgr.candidate_metadata_path.write_text('{}')
    with pytest.raises(ActivationError, match='digest'):
        mgr.dry_run()
    assert rt.loads == []


def test_rollback_failure_is_audited(tmp_path):
    mgr, rt = manager(tmp_path)
    record = mgr.apply(idempotency_key='rollback-failure')
    rt.fail_version = 0
    with pytest.raises(ActivationError, match='health'):
        mgr.rollback(record['execution_id'])
    stored = mgr.store.get(record['execution_id'])
    assert stored['rollback_status'] == 'ROLLBACK_FAILED'
    assert stored['rollback_error']


def file_engine(tmp_path, *, fail_candidate=False):
    from caddy_runtime import CommandResult
    live = tmp_path / 'live.caddy'
    live.write_text('old')
    value = {'current': {'config': 'old'}}
    def run(argv):
        path = Path(argv[argv.index('--config') + 1])
        if argv[1] == 'adapt':
            return CommandResult(0, json.dumps({'config': path.read_text()}))
        if argv[1] == 'reload':
            value['current'] = ({'config': path.read_text()} if '--adapter' in argv
                                else json.loads(path.read_text()))
        return CommandResult(0)
    runtime = FileRuntime(RuntimePaths(live, tmp_path / 'file-state'), mutation_enabled=True,
        runner=run, runtime_get=lambda *_: json.dumps(value['current']).encode(),
        health_urls=('http://127.0.0.1/health',),
        health_check=lambda *_: not (fail_candidate and value['current'] == {'config': 'new'}))
    candidate = tmp_path / 'new.caddy'
    candidate.write_text('new')
    return runtime, candidate, value


def test_file_engine_persists_restart_config(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                  idempotency_key='file')
    assert json.loads(runtime.coordinator.active_path.read_text()) == value['current']


def test_file_engine_restores_initial_runtime_even_without_previous_file(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path, fail_candidate=True)
    runtime.paths.live_config.unlink()
    with pytest.raises(RuntimeApplyError, match='rolled_back'):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='file-failure')
    assert value['current'] == {'config': 'old'}
    assert runtime.history()[0]['outcome'] == 'ROLLED_BACK'
    assert json.loads(runtime.coordinator.active_path.read_text()) == value['current']


def test_file_failed_retry_never_returns_success_or_reloads(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path, fail_candidate=True)
    with pytest.raises(RuntimeApplyError):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='retry-file-failure')
    runtime.health_check = lambda *_: True
    with pytest.raises(RuntimeApplyError, match='idempotency'):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='retry-file-failure')
    assert value['current'] == {'config': 'old'}


def test_idempotency_key_cannot_cross_engines(tmp_path):
    from caddy_runtime import sha256_file
    mgr, _ = manager(tmp_path)
    mgr.apply(idempotency_key='shared-command')
    runtime, path, value = file_engine(tmp_path)
    with pytest.raises(RuntimeApplyError, match='idempotency_conflict'):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='shared-command')
    assert value['current'] == {'config': 'old'}


def test_file_mutation_rejects_missing_health_configuration(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    runtime.health_urls = ()
    with pytest.raises(RuntimeApplyError, match='health'):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path))
    assert value['current'] == {'config': 'old'}


def test_file_lock_blocks_json_engine(tmp_path):
    mgr, rt = manager(tmp_path)
    runtime, _, _ = file_engine(tmp_path)
    lock = runtime._lock()
    try:
        with pytest.raises(ActivationError, match='in progress'):
            mgr.apply(idempotency_key='blocked')
    finally:
        runtime.coordinator.release(lock)
    assert rt.loads == []


def test_file_named_rollback_survives_later_failed_apply(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='first')
    path.write_text('broken')
    runtime.health_check = lambda *_: value['current'] != {'config': 'broken'}
    with pytest.raises(RuntimeApplyError):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                      idempotency_key='second')
    runtime.rollback(execution_id=first['execution_id'])
    assert value['current'] == {'config': 'old'}


def test_file_named_rollback_rejects_advanced_runtime(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    first = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                          idempotency_key='first')
    value['current'] = {'config': 'externally changed'}
    with pytest.raises(RuntimeApplyError, match='stale_rollback'):
        runtime.rollback(execution_id=first['execution_id'])
    assert value['current'] == {'config': 'externally changed'}


def test_unresolved_operation_fences_different_commands_and_engine(tmp_path):
    mgr, rt = manager(tmp_path)
    def interrupted_load(value):
        rt.current = value
        raise KeyboardInterrupt('simulated controller crash after load')
    rt.load_json = interrupted_load
    with pytest.raises(KeyboardInterrupt):
        mgr.apply(idempotency_key='interrupted')
    rt.load_json = lambda value: setattr(rt, 'current', value)
    with pytest.raises(ActivationError, match='recovery'):
        mgr.apply(idempotency_key='different-command')
    file_runtime, path, _ = file_engine(tmp_path)
    from caddy_runtime import sha256_file
    with pytest.raises(RuntimeApplyError, match='recovery'):
        file_runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                           idempotency_key='different-engine')
    assert json.loads(mgr.coordinator.active_path.read_text()) == {'version': 0}


def test_json_manual_rollback_journals_before_loading(tmp_path):
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='initial')
    def interrupted_load(value):
        rt.current = value
        raise KeyboardInterrupt('simulated rollback controller crash')
    rt.load_json = interrupted_load
    with pytest.raises(KeyboardInterrupt):
        mgr.rollback(first['execution_id'])
    pending = [mgr.coordinator.ledger.get(i) for i in mgr.coordinator.ledger.list_ids()
               if mgr.coordinator.ledger.get(i)['status'] == 'RUNNING']
    assert len(pending) == 1
    assert pending[0]['kind'] == 'ACTIVATION_ROLLBACK'
    assert pending[0]['rollback_of'] == first['execution_id']
    assert pending[0]['pre_state'] == {'version': 1}


def test_idempotency_works_without_source_provider(tmp_path):
    mgr, rt = manager(tmp_path)
    mgr.source_sha_provider = None
    first = mgr.apply(idempotency_key='metadata-source')
    second = mgr.apply(idempotency_key='metadata-source')
    assert first == second
    assert len(rt.loads) == 1


def test_out_of_band_drift_does_not_replace_restart_authority(tmp_path):
    mgr, rt = manager(tmp_path)
    mgr.apply(idempotency_key='initial')
    rt.current = {'version': 999}
    with pytest.raises(ActivationError, match='restart'):
        mgr.apply(idempotency_key='drift')
    assert json.loads(mgr.coordinator.active_path.read_text()) == {'version': 1}


def test_unnamed_file_rollback_uses_successful_receipt_not_overwritten_backup(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path), idempotency_key='first')
    path.write_text('bad')
    runtime.health_check = lambda *_: value['current'] != {'config': 'bad'}
    with pytest.raises(RuntimeApplyError):
        runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path), idempotency_key='failed')
    runtime.rollback()
    assert value['current'] == {'config': 'old'}


def test_file_rollback_cannot_overwrite_later_json_activation(tmp_path):
    from caddy_runtime import sha256_file
    runtime, path, value = file_engine(tmp_path)
    runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path), idempotency_key='file-first')
    mgr, rt = manager(tmp_path)
    rt.current = value['current']
    rt.check_health = lambda: None
    mgr.apply(idempotency_key='json-second')
    value['current'] = rt.current
    with pytest.raises(RuntimeApplyError, match='stale_rollback'):
        runtime.rollback()
    assert value['current'] == {'version': 1}


def test_control_audit_reads_shared_recovery_over_stale_mirror(tmp_path):
    from caddy_control_api import ControlService
    mgr, rt = manager(tmp_path)
    first = mgr.apply(idempotency_key='original')
    shared = mgr.coordinator.ledger.get(first['execution_id'])
    shared['rollback_status'] = 'INTERRUPTED_RESTART_RESTORED'
    mgr.coordinator.ledger.put(first['execution_id'], shared)
    service = ControlService(runtime=rt, store=mgr.store,
                             source_sha_provider=lambda: 'a' * 40, mutation_enabled=False)
    assert service.execution(first['execution_id'])['rollback_status'] == 'INTERRUPTED_RESTART_RESTORED'
    rows = service.executions()['executions']
    assert len(rows) == 1
    assert rows[0]['rollback_status'] == 'INTERRUPTED_RESTART_RESTORED'


def test_control_audit_includes_file_engine_receipts(tmp_path):
    from caddy_runtime import sha256_file
    from caddy_control_api import ControlService
    runtime, path, _ = file_engine(tmp_path)
    receipt = runtime.apply(path, source_sha='a' * 40, candidate_digest=sha256_file(path),
                            idempotency_key='file-audit')
    service = ControlService(store=ExecutionStore(tmp_path / 'observations'), mutation_enabled=False)
    assert service.execution(receipt['execution_id'])['engine'] == 'file'
    assert service.executions()['executions'][0]['status'] == 'COMPLETED'
