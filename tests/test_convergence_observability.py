from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_every_public_site_uses_structured_edge_context():
    for path in (ROOT / 'sites').glob('*.caddy'):
        source = path.read_text()
        assert source.count('import edge_observability') == source.count('import security_headers')
    snippet = (ROOT / 'snippets/edge_observability.caddy').read_text()
    for field in ('route_id', 'upstream', 'request_id', 'correlation_id', 'configuration_digest', 'release_sha'):
        assert 'log_append ' + field in snippet
    assert 'request>headers>Authorization delete' in (ROOT / 'sites/api.codestra.co.caddy').read_text()


def test_metrics_only_on_loopback_admin_without_host_cardinality():
    source = (ROOT / 'Caddyfile').read_text()
    assert '\tmetrics\n' in source
    assert 'per_host' not in source
    assert 'admin 127.0.0.1:2019' in source
    for path in (ROOT / 'sites').glob('*.caddy'):
        assert '\n\tmetrics' not in path.read_text()
