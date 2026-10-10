import pytest


@pytest.fixture(autouse=True)
def isolated_coordination_state(tmp_path, monkeypatch):
    # Both engines share a state directory within each test, never the real runtime.
    monkeypatch.setenv('CADDY_CONTROL_STATE_DIR', str(tmp_path / 'coordination'))
    monkeypatch.delenv('CADDY_ACTIVATION_HEALTH_URLS', raising=False)
