"""Loopback-only native Caddy certification; upstream is a synthetic Kong stand-in."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from caddy_candidate import CandidateBuilder
from caddy_control_api import ControlService, Handler
from caddy_execution_store import ExecutionStore
from caddy_runtime_readback import CaddyRuntime


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def test_native_edge_http_streaming_headers_metrics_reload_rollback_and_postman(tmp_path, monkeypatch):
    binary = os.environ.get('CADDY_BIN') or shutil.which('caddy')
    if not binary:
        pytest.skip('requires pinned CADDY_BIN')
    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            seen.append(dict(self.headers))
            if self.path == '/ws/agent':
                key = self.headers['Sec-WebSocket-Key']
                accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101)
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()
                return
            body = b'data: TEST_SYN\n\n' if self.path == '/platform/v1/activity' else b'{}'
            self.send_response(200 if self.path == '/platform/v1/activity' else 401)
            self.send_header('Content-Type', 'text/event-stream' if self.path == '/platform/v1/activity' else 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.do_GET()

    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    edge_port, admin_port = free_port(), free_port()
    monkeypatch.setenv('CADDY_KONG_UPSTREAM', f'127.0.0.1:{upstream.server_port}')
    monkeypatch.setenv('CADDY_REALTIME_UPSTREAM', f'127.0.0.1:{upstream.server_port}')
    monkeypatch.setenv('CADDY_LOG_DIR', str(tmp_path / 'logs'))
    monkeypatch.setenv('CADDY_RELEASE_SHA', 'a' * 40)
    monkeypatch.setenv('CADDY_CONFIGURATION_SHA256', 'b' * 64)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.setenv('PATH', str(Path(binary).parent) + ':' + os.environ['PATH'])
    shutil.copytree(ROOT / 'snippets', tmp_path / 'snippets')
    api = (ROOT / 'sites/api.codestra.co.caddy').read_text().replace('api.codestra.co {', f'http://127.0.0.1:{edge_port} {{')
    (tmp_path / 'api.caddy').write_text(api)
    caddyfile = tmp_path / 'Caddyfile'
    caddyfile.write_text(f'{{\n admin 127.0.0.1:{admin_port}\n auto_https off\n persist_config off\n metrics\n order route before handle\n servers {{\n  idle_timeout 2s\n }}\n}}\nimport snippets/*.caddy\nimport api.caddy\n')
    candidate = tmp_path / 'candidate.json'
    builder = CandidateBuilder(caddyfile=caddyfile, output=candidate, source_sha_provider=lambda: 'a' * 40)
    original_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        builder.build()
    finally:
        os.chdir(original_cwd)
    log = (tmp_path / 'process.log').open('w')
    process = subprocess.Popen([binary, 'run', '--config', str(candidate)], stdout=log, stderr=log)
    service = ControlService(runtime=CaddyRuntime(f'http://127.0.0.1:{admin_port}'), store=ExecutionStore(tmp_path / 'history'), candidate_path=candidate, candidate_builder=builder, source_sha_provider=lambda: 'a' * 40, mutation_enabled=False)
    class TestHandler(Handler):
        pass
    TestHandler.service = service
    control = ThreadingHTTPServer(('127.0.0.1', 0), TestHandler)
    threading.Thread(target=control.serve_forever, daemon=True).start()
    try:
        for _ in range(100):
            try:
                service.runtime.config()
                break
            except Exception:
                if process.poll() is not None:
                    pytest.fail((tmp_path / 'process.log').read_text())
                time.sleep(.05)
        else:
            pytest.fail('native Caddy did not start')
        def request(path, headers=None, method='GET'):
            conn = http.client.HTTPConnection('127.0.0.1', edge_port, timeout=5)
            conn.request(method, path, headers=headers or {})
            r = conn.getresponse()
            result = r.status, dict(r.getheaders()), r.read()
            conn.close()
            return result
        for path in ['/metrics', '/metrics/subpath', '/internal', '/internal/v1/database/health', '/__unknown__', '/api/v1/events/telnexa']:
            assert request(path)[0] == 404
        headers = {'Authorization': 'Bearer TEST_SYN_REDACT', 'Cookie': 'TEST_SYN_COOKIE', 'X-Admin': 'yes', 'X-User-ID': 'forged', 'X-Correlation-ID': 'TEST_SYN_CORRELATION', 'traceparent': '00-' + '1' * 32 + '-' + '2' * 16 + '-01', 'Idempotency-Key': 'TEST_SYN_IDEMPOTENCY', 'Forwarded': 'for=8.8.8.8', 'X-Forwarded-For': '8.8.8.8'}
        assert request('/platform/v1/kernel/describe?token=TEST_SYN_QUERY_SECRET', headers)[0] == 401
        forwarded = {k.lower(): v for k, v in seen[-1].items()}
        for name in ['x-admin', 'x-user-id', 'forwarded']:
            assert name not in forwarded
        for name in ['authorization', 'x-correlation-id', 'traceparent', 'idempotency-key']:
            assert forwarded[name] == next(v for k, v in headers.items() if k.lower() == name)
        assert forwarded['x-forwarded-for'] == '127.0.0.1'
        assert request('/platform/v1/activity')[2] == b'data: TEST_SYN\n\n'
        assert request('/api/v1/odoo/events', method='POST')[0] == 401
        assert request('/ws/agent', {'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': base64.b64encode(b'0123456789abcdef').decode()})[0] == 101
        admin = http.client.HTTPConnection('127.0.0.1', admin_port, timeout=5)
        admin.request('GET', '/metrics')
        metrics = admin.getresponse()
        assert metrics.status == 200
        metric_text = metrics.read().decode()
        assert 'TEST_SYN_CORRELATION' not in metric_text and 'TEST_SYN_QUERY_SECRET' not in metric_text
        admin.close()
        newman = shutil.which('newman')
        assert newman, 'Newman is required for full local certification'
        report = tmp_path / 'newman.json'
        run = subprocess.run([newman, 'run', str(ROOT / 'postman/Caddy-V3-Edge-Certification.postman_collection.json'), '--env-var', f'base_url=http://127.0.0.1:{edge_port}', '--env-var', f'caddy_control_url=http://127.0.0.1:{control.server_port}', '--timeout-request', '10000', '--reporters', 'cli,json', '--reporter-json-export', str(report)], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
        assert run.returncode == 0, run.stdout + run.stderr
        # Exercise apply/rollback only on this disposable native instance.
        before = service.runtime.config()
        changed = json.loads(candidate.read_text())
        changed['apps']['http']['servers'][next(iter(changed['apps']['http']['servers']))]['read_header_timeout'] = 10_000_000_000
        candidate.write_text(json.dumps(changed))
        from caddy_runtime_readback import sha256_json
        meta_path = candidate.with_suffix('.json.meta.json')
        meta = json.loads(meta_path.read_text()); meta['candidate_sha256'] = sha256_json(changed)
        meta_path.write_text(json.dumps(meta))
        service.activation.mutation_enabled = True
        execution = service.activation_apply('TEST_SYN_LOCAL_APPLY')
        assert execution['readback_verified'] is True
        service.activation_rollback(execution['execution_id'])
        assert service.runtime.config() == before
        upstream.shutdown(); upstream.server_close()
        assert request('/platform/v1/kernel/describe')[0] == 502
        assert request('/metrics')[0] == 404
        process.terminate(); process.wait(timeout=5)
        logs = (tmp_path / 'logs/api-codestra-co-access.log').read_text()
        for secret in ['TEST_SYN_REDACT', 'TEST_SYN_COOKIE', 'TEST_SYN_QUERY_SECRET']:
            assert secret not in logs
        rows = [json.loads(line) for line in logs.splitlines()]
        assert any(r.get('route_id') == 'edge.canonical.get' for r in rows)
        for row in rows:
            assert row['release_sha'] == 'a' * 40
            assert row['configuration_digest'] == 'b' * 64
            assert 'status' in row and 'duration' in row and 'request_id' in row
    finally:
        if process.poll() is None:
            process.terminate(); process.wait(timeout=5)
        control.shutdown(); control.server_close()
        upstream.shutdown(); upstream.server_close()
        log.close()
