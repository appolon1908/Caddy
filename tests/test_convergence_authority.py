from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import caddy_route_compiler as compiler
from caddy_control_api import ControlService


def test_production_compiler_and_control_readback_use_deployed_authority():
    assert compiler.DEFAULT_AUTHORITY == ROOT / 'config/caddy-kong-contract.v1.json'
    generated = compiler.compile_caddy(compiler.load_authority())
    assert generated == (ROOT / 'sites/api.codestra.co.caddy').read_text()
    routes = ControlService().routes()['routes']
    assert any(row['path'] == '/platform/v1/kernel/describe' for row in routes)
    assert any(row['path'] == '/ws/agent' for row in routes)
    assert any(row['path'] == '*' and row['upstream_ref'] == 'NONE' for row in routes)


def test_compiled_authority_has_route_observability_and_no_unknown_upstream():
    generated = compiler.compile_caddy(compiler.load_authority())
    assert 'vars edge_route_id edge.canonical.get' in generated
    assert 'vars edge_route_id edge.kong.mcr-plan' in generated
    assert 'respond 404' in generated
    assert 'CADDY_LEGACY_API_UPSTREAM' not in generated


def test_inventory_keeps_exact_kong_matchers_exact():
    rows = ControlService().routes()['routes']
    public = [row for row in rows if row['upstream_ref'] == 'CADDY_KONG_UPSTREAM']
    assert not any(row['methods'] == ['ANY'] for row in public)
    assert not any(row['path'].endswith('*') and not row['handler_id'].startswith('edge.kong.') for row in public)
    assert any(row['path'] == '/api/v1/automation/policy-check' and row['methods'] == ['POST'] for row in public)
    denied = [row for row in rows if row['path'] == '/api/v1/integration/campaign-actions']
    assert denied and all(row['upstream_ref'] == 'NONE' for row in denied)
