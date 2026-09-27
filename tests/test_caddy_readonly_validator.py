import importlib.util
import json
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "caddy_readonly_validator.py"
SPEC = importlib.util.spec_from_file_location("caddy_readonly_validator", MODULE_PATH)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(validator)


class ReadonlyValidatorTests(unittest.TestCase):
    def test_all_credential_redactions_are_required(self):
        source = "\n".join(validator.REQUIRED_REDACTIONS)
        validator.require_redaction(source)
        for token in validator.REQUIRED_REDACTIONS:
            with self.assertRaises(validator.ValidationError):
                validator.require_redaction(source.replace(token, ""))

    def test_summary_contains_structure_but_not_values(self):
        raw = {
            "host": "api.codestra.co",
            "path": "/v1/*",
            "dial": "kong:8000",
            "headers": {"Authorization": ["secret-value"]},
            "read_timeout": "30s",
            "client_authentication": {"trusted_ca_certs": ["secret-ca"]},
        }
        result = validator.sanitized_summary(raw)
        rendered = repr(result)
        self.assertIn("api.codestra.co", rendered)
        self.assertIn("kong:8000", rendered)
        self.assertIn("Authorization", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("secret-ca", rendered)
        self.assertTrue(result["mtls_policy_present"])

    def test_unsafe_upstream_is_rejected(self):
        for dial in ("user:password@host:443", "host:443?token=value", "https://host:443"):
            with self.assertRaises(validator.ValidationError):
                validator.sanitized_summary({"dial": dial})

    def test_each_adapted_access_log_requires_all_credential_redactions(self):
        fields = {
            "request>headers>Authorization": {"filter": "delete"},
            "request>headers>Apikey": {"filter": "delete"},
            "request>headers>X-Api-Key": {"filter": "delete"},
            "request>uri": {
                "filter": "query",
                "actions": [{"type": "delete", "parameter": name} for name in (
                    "apikey", "api_key", "access_token", "refresh_token", "id_token",
                    "client_secret", "password", "secret", "token")],
            },
        }
        for name in ("request>headers>Proxy-Authorization", "request>headers>Cookie", "resp_headers>Set-Cookie"):
            fields[name] = {"filter": "delete"}
        adapted = {"logging": {"logs": {"default": {}, "api": {"encoder": {"fields": fields}}}}}
        validator.require_adapted_redaction(adapted)
        for key in tuple(fields):
            broken = {**fields}
            broken.pop(key)
            candidate = {"logging": {"logs": {"api": {"encoder": {"fields": broken}}}}}
            with self.assertRaises(validator.ValidationError):
                validator.require_adapted_redaction(candidate)

    def test_every_placeholder_in_the_repository_source_is_required(self):
        paths = [ROOT / "Caddyfile"]
        for pattern in ("sites/*.caddy", "snippets/*.caddy"):
            paths.extend(sorted(ROOT.glob(pattern)))
        source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        required = validator.required_runtime_variables(source)
        self.assertLessEqual(validator.RUNTIME_VARIABLES, required)
        for name in (
            "CADDY_GRAFANA_UPSTREAM",
            "CADDY_SUPERSET_UPSTREAM",
            "CADDY_OPENBAO_UPSTREAM",
            "CADDY_OPENBAO_ALLOWED_CIDRS",
            "CADDY_KYYOW_APP_UPSTREAM",
            "CADDY_KYYOW_STATUS_UPSTREAM",
        ):
            self.assertIn(name, required)
        # The CI gate adapts with exactly this set; it must cover the source.
        ci = (ROOT / "scripts" / "validate-ci.sh").read_text(encoding="utf-8")
        for name in required:
            self.assertIn(f"-e {name}=", ci.replace("-e '", "-e "))

    def test_placeholder_with_default_is_optional(self):
        required = validator.required_runtime_variables("{$OPTIONAL:fallback} {$NEEDED}")
        self.assertIn("NEEDED", required)
        self.assertNotIn("OPTIONAL", required)

    def test_reverse_proxy_without_upstream_is_rejected(self):
        # Shape Caddy adapts to when an upstream placeholder is unset.
        validator.require_proxy_upstreams(
            {"routes": [{"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "kong:8000"}]}]}]}
        )
        for broken in (
            {"handler": "reverse_proxy"},
            {"handler": "reverse_proxy", "upstreams": None},
            {"handler": "reverse_proxy", "upstreams": [{"dial": ""}]},
        ):
            with self.assertRaises(validator.ValidationError):
                validator.require_proxy_upstreams({"routes": [{"handle": [broken]}]})


    @staticmethod
    def coverage_document(logger_names, hosts=("api.codestra.co",), logs=None):
        return {
            "logging": {"logs": logs if logs is not None else {
                "default": {"exclude": ["http.log.access.log0"]},
                "log0": {"include": ["http.log.access.log0"]},
            }},
            "apps": {"http": {"servers": {"srv0": {
                "routes": [{"match": [{"host": list(hosts)}]}],
                "logs": {"logger_names": logger_names},
            }}}},
        }

    def test_every_served_host_requires_a_dedicated_access_log(self):
        validator.require_access_log_coverage(self.coverage_document({"api.codestra.co": ["log0"]}))
        # Caddy <2.8 adapted a single logger name as a string.
        validator.require_access_log_coverage(self.coverage_document({"api.codestra.co": "log0"}))
        for broken in (
            # Second host has no log block: its entries go to the unfiltered default logger.
            self.coverage_document({"api.codestra.co": ["log0"]}, hosts=("api.codestra.co", "status.kyyow.com")),
            self.coverage_document({}),
            self.coverage_document({"api.codestra.co": []}),
            self.coverage_document({"api.codestra.co": ["default"]}),
            self.coverage_document({"api.codestra.co": ["log9"]}),
            self.coverage_document({"api.codestra.co": ["log0"]}, logs={"log0": {"include": ["http.log.access.log1"]}}),
        ):
            with self.assertRaises(validator.ValidationError):
                validator.require_access_log_coverage(broken)
        with self.assertRaises(validator.ValidationError):
            validator.require_access_log_coverage({"apps": {"http": {"servers": {}}}})

    def test_every_repository_site_meets_the_access_log_redaction_floor(self):
        site_address = re.compile(r"(?m)^\S.*\{\s*$")
        for path in sorted((ROOT / "sites").glob("*.caddy")):
            source = path.read_text(encoding="utf-8")
            sites = site_address.split(source)[1:]
            self.assertTrue(sites, path.name)
            for index, block in enumerate(sites):
                with self.subTest(site=f"{path.name}#{index}"):
                    log = block[block.index("\tlog {"):]
                    for token in (
                        "request>headers>Authorization delete",
                        "request>headers>Apikey delete",
                        "request>headers>X-Api-Key delete",
                        "request>uri query {",
                        "delete apikey",
                    ):
                        self.assertIn(token, log)

    @unittest.skipUnless(
        os.environ.get("CADDY_ADAPTED_JSON"), "set CADDY_ADAPTED_JSON (scripts/validate-ci.sh does)"
    )
    def test_adapted_repository_config_passes_the_readback_checks(self):
        adapted = json.loads(Path(os.environ["CADDY_ADAPTED_JSON"]).read_text(encoding="utf-8"))
        validator.require_adapted_redaction(adapted)
        validator.require_access_log_coverage(adapted)
        validator.require_proxy_upstreams(adapted)
        validator.require_transport_security(adapted)
        validator.sanitized_summary(adapted)

        # Every upstream of the Kong-fronted hosts, including the realtime and
        # legacy fallback proxies, deletes the contracted client identity list.
        contract = json.loads((ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8"))
        required = set(contract["identityHeaders"]["deletedBeforeKong"])
        proxies = []

        def collect(value):
            if isinstance(value, dict):
                if value.get("handler") == "reverse_proxy":
                    proxies.append(value)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        for server in adapted["apps"]["http"]["servers"].values():
            for route in server.get("routes") or []:
                hosts = {h for m in route.get("match") or [] for h in m.get("host") or []}
                if hosts & {"api.codestra.co", "automation.codestra.co"}:
                    collect(route)
        self.assertGreaterEqual(len(proxies), 7)
        for proxy in proxies:
            deleted = set(((proxy.get("headers") or {}).get("request") or {}).get("delete") or [])
            self.assertEqual(required - deleted, set(), proxy["upstreams"])

if __name__ == "__main__":
    unittest.main()


def test_readback_rejects_disk_active_drift_and_returns_only_digest():
    desired = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"]}}}}}
    assert re.fullmatch(r"[0-9a-f]{64}", validator.require_served_config(desired, desired))
    for active in ({}, {"apps": {}}, [], None):
        with __import__('pytest').raises(validator.ValidationError):
            validator.require_served_config(desired, active)


def test_fixed_admin_readback_does_not_follow_redirect_or_emit_body(monkeypatch):
    import io
    import pytest

    class Response(io.BytesIO):
        status = 302

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 2019, 5)
        def request(self, method, path):
            assert (method, path) == ("GET", "/config/")
        def getresponse(self):
            return Response(b'secret-body')
        def close(self):
            pass

    monkeypatch.setattr(validator.http.client, "HTTPConnection", Connection)
    with pytest.raises(validator.ValidationError) as caught:
        validator.active_configuration()
    assert "secret-body" not in str(caught.value)


def test_full_credential_floor_is_required_in_adapted_logs():
    import pytest
    fields = {
        f"request>headers>{name}": {"filter": "delete"}
        for name in ("Authorization", "Apikey", "X-Api-Key")
    }
    fields["request>uri"] = {"filter": "query", "actions": [{"type": "delete", "parameter": "apikey"}]}
    with pytest.raises(validator.ValidationError):
        validator.require_adapted_redaction({"logging": {"logs": {"access": {"encoder": {"fields": fields}}}}})


def test_transport_policy_rejects_public_admin_and_disabled_tls():
    import copy
    import pytest
    good = {"admin": {"listen": "127.0.0.1:2019"}, "apps": {"http": {"servers": {"srv0": {"listen": [":443"]}}}}}
    validator.require_transport_security(good)
    for address in (":2019", "0.0.0.0:2019", "[::]:2019"):
        broken = copy.deepcopy(good)
        broken['admin']['listen'] = address
        with pytest.raises(validator.ValidationError):
            validator.require_transport_security(broken)
    for policy in ({'automatic_https': {'disable': True}},
                   {'automatic_https': {'disable_redirects': True}},
                   {'tls_connection_policies': [{'protocol_min': 'tls1.0'}]},
                   {'routes': [{'handle': [{'handler': 'reverse_proxy', 'transport': {'tls': {'insecure_skip_verify': True}}}]}]}):
        broken = copy.deepcopy(good)
        broken['apps']['http']['servers']['srv0'].update(policy)
        with pytest.raises(validator.ValidationError):
            validator.require_transport_security(broken)


def test_main_does_not_report_success_when_served_configuration_drifts(monkeypatch, capsys):
    import pytest
    fields = {name: {'filter': 'delete'} for name in (
        'request>headers>Authorization', 'request>headers>Apikey', 'request>headers>X-Api-Key',
        'request>headers>Proxy-Authorization', 'request>headers>Cookie', 'resp_headers>Set-Cookie')}
    fields['request>uri'] = {'filter': 'query', 'actions': [
        {'type': 'delete', 'parameter': name} for name in (
            'apikey', 'api_key', 'access_token', 'refresh_token', 'id_token',
            'client_secret', 'password', 'secret', 'token')]}
    desired = {
        'admin': {'listen': '127.0.0.1:2019'},
        'logging': {'logs': {'log0': {'include': ['http.log.access.log0'], 'encoder': {'fields': fields}}}},
        'apps': {'http': {'servers': {'srv0': {
            'listen': [':443'], 'logs': {'logger_names': {'api.codestra.co': ['log0']}},
            'routes': [{'match': [{'host': ['api.codestra.co']}], 'handle': [
                {'handler': 'reverse_proxy', 'upstreams': [{'dial': 'kong:8000'}]}]}]
        }}}}}
    monkeypatch.setattr(validator.sys, 'argv', ['validator'])
    monkeypatch.setattr(validator, 'canonical_source', lambda: ('\n'.join(validator.REQUIRED_REDACTIONS), 'source-digest'))
    monkeypatch.setattr(validator, 'runtime_environment', lambda required: {})
    def run(command, environment=None):
        if command[1] == 'adapt':
            return json.dumps(desired)
        if command[1] == 'is-active':
            return 'active'
        assert command[1] == 'validate'
        return ''
    monkeypatch.setattr(validator, 'run_fixed', run)
    monkeypatch.setattr(validator, 'active_configuration', lambda: {'old': 'secret-runtime-value'})
    with pytest.raises(validator.ValidationError, match='served configuration differs'):
        validator.main()
    assert capsys.readouterr().out == ''
    monkeypatch.setattr(validator, 'active_configuration', lambda: desired)
    assert validator.main() == 0
    evidence = json.loads(capsys.readouterr().out)
    assert evidence['served_config_matches_disk'] is True
    assert evidence['config_validation'] == 'PASS'
