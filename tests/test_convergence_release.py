import json, subprocess, sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def repository(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    for k, v in [('user.email', 'test@example.invalid'), ('user.name', 'Test')]:
        subprocess.run(['git', '-C', str(root), 'config', k, v], check=True)
    (root / 'Caddyfile').write_text('{ admin 127.0.0.1:2019 }\n')
    for cmd in [['add', '.'], ['commit', '-qm', 'baseline']]:
        subprocess.run(['git', '-C', str(root), *cmd], check=True)
    return root


def test_release_binds_source_configuration_and_rollback_and_rejects_tampering(tmp_path):
    from caddy_release import build_release, verify_release, ReleaseError
    root = repository(tmp_path)
    out = tmp_path / 'release'
    manifest = build_release(root, out, 'HEAD')
    assert len(manifest['source_sha']) == 40
    assert len(manifest['configuration_sha256']) == 64
    assert manifest['production_apply_authorized'] is False
    assert manifest['signing_status'] == 'REQUIRES_PROTECTED_CI'
    verify_release(out, expected_source_sha=manifest['source_sha'])
    with pytest.raises(ReleaseError, match='stale'):
        verify_release(out, expected_source_sha='0' * 40)
    with (out / 'rollback.tar').open('ab') as f:
        f.write(b'tamper')
    with pytest.raises(ReleaseError, match='digest'):
        verify_release(out, expected_source_sha=manifest['source_sha'])


def test_release_refuses_dirty_or_existing_output(tmp_path):
    from caddy_release import build_release, ReleaseError
    root = repository(tmp_path)
    (root / 'Caddyfile').write_text('modified')
    with pytest.raises(ReleaseError, match='dirty'):
        build_release(root, tmp_path / 'release', 'HEAD')
    assert not (tmp_path / 'release').exists()


def test_release_verifier_rejects_arbitrary_bundle_paths(tmp_path):
    from caddy_release import build_release, verify_release, ReleaseError
    root = repository(tmp_path)
    out = tmp_path / 'release'
    m = build_release(root, out, 'HEAD')
    m['artifacts']['../outside'] = '0' * 64
    (out / 'manifest.json').write_text(json.dumps(m))
    with pytest.raises(ReleaseError, match='artifact'):
        verify_release(out, expected_source_sha=m['source_sha'])


def test_release_verifier_rejects_manifest_image_substitution(tmp_path):
    from caddy_release import build_release, verify_release, ReleaseError
    root = repository(tmp_path)
    out = tmp_path / 'release'
    m = build_release(root, out, 'HEAD')
    m['image_reference'] = 'unreviewed:latest'
    (out / 'manifest.json').write_text(json.dumps(m))
    with pytest.raises(ReleaseError, match='image'):
        verify_release(out, expected_source_sha=m['source_sha'])
