"""Private endpoints must fail closed on every public host, including bare roots."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_generator_preserves_private_root_and_subtree_denials():
    spec = importlib.util.spec_from_file_location('edge_generator', ROOT / 'scripts/generate_middleware_edge_contract.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rendered, _ = module.render()
    assert set(json.loads(rendered)['privateOnlyPaths']) == {
        '/metrics', '/metrics/*', '/internal', '/internal/*'
    }


def test_all_public_hosts_deny_private_paths_before_upstream():
    from test_caddy_adapted_routes import real_adapted_document, load_module
    import pytest
    document = real_adapted_document()
    if document is None:
        pytest.skip('requires CADDY_ADAPTED_JSON or CADDY_BIN')
    resolver = load_module()
    hosts = {host for server in document['apps']['http']['servers'].values()
             for route in server.get('routes', []) for matcher in route.get('match', [])
             for host in matcher.get('host', [])}
    assert hosts
    for host in hosts:
        for path in ('/metrics', '/metrics/', '/metrics/nested', '/internal', '/internal/', '/internal/nested'):
            for method in ('GET', 'POST', 'OPTIONS'):
                result = resolver.resolve_request(document, method, path, host)
                assert result.response_status == 404 and result.upstream is None, (host, method, path, result)
