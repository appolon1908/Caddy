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
            "CADDY_KEYCLOAK_UPSTREAM",
            "CADDY_VICIDIAL_SOURCE_CIDRS",
            "CADDY_PRIVATE_INGRESS_BIND",
        ):
            self.assertIn(name, required)
        # Kyyow stays in sites-pending/ until DNS exists, so it is not deployed.
        self.assertNotIn("CADDY_KYYOW_APP_UPSTREAM", required)
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
        # Every exact-method contract group, Kong-owned route, the realtime and
        # the editor proxy is checked; no prefix fallback remains.
        self.assertEqual(len(proxies), len({row["method"] for row in contract["serviceJwtRouteContract"]["routes"]})
                         + len(contract["kongOwnedRoutes"]) + 2)
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
        def __init__(self, path, timeout):
            assert (path, timeout) == ("/run/caddy/admin.sock", 5)
        def request(self, method, path):
            assert (method, path) == ("GET", "/config/")
        def getresponse(self):
            return Response(b'secret-body')
        def close(self):
            pass

    monkeypatch.setattr(validator, "AdminSocketConnection", Connection)
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
    good = {"admin": {"listen": validator.ADMIN_ADDRESS}, "apps": {"http": {"servers": {"srv0": {"listen": [":443"]}}}}}
    validator.require_transport_security(good)
    for address in (":2019", "0.0.0.0:2019", "[::]:2019", "127.0.0.1:2019", "unix//tmp/admin.sock"):
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


DIGEST = "sha256:" + "d" * 64
IMAGE = validator.EXPECTED_IMAGE_REPOSITORY + "@" + DIGEST
SOURCE = "a" * 40


def container_fixture(config_sha="c" * 64, **overrides):
    labels = {
        validator.SOURCE_LABEL: SOURCE,
        validator.DIGEST_LABEL: DIGEST,
        validator.CONFIG_LABEL: config_sha,
        validator.RELEASE_LABEL: "release-1",
    }
    container = {
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Config": {"Image": IMAGE, "Labels": labels, "Env": [
            "CADDY_PUBLIC_BIND=203.0.113.10", "CADDY_PRIVATE_METRICS_BIND=10.40.0.1",
            "CADDY_PRIVATE_INGRESS_BIND=10.40.0.1", "CADDY_KONG_UPSTREAM=127.0.0.1:8000",
            "CADDY_EDITOR_ADMIN_CIDRS=192.0.2.0/24", "CADDY_N8N_EDITOR_MAX_REQUEST_BODY=16777216",
            "CADDY_REALTIME_UPSTREAM=127.0.0.1:18102", "CADDY_N8N_EDITOR_HOST=n8n-editor.invalid",
            "CADDY_N8N_OAUTH2_PROXY_UPSTREAM=127.0.0.1:4180"]},
    }
    image = {
        "RepoDigests": [IMAGE],
        "Config": {"User": validator.RUNTIME_USER, "Labels": {
            "org.opencontainers.image.source": "https://github.com/appolon1908/Caddy",
            "org.opencontainers.image.revision": SOURCE,
            validator.CONFIG_LABEL: config_sha,
        }},
    }
    for path, value in overrides.items():
        target, *keys = path.split(".")
        node = container if target == "container" else image
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return container, image


def test_container_identity_requires_the_signed_non_root_release():
    import pytest
    container, image = container_fixture()
    assert validator.require_container_identity(container, image)["image_digest"] == DIGEST
    for override in (
        {"container.State.Health": {"Status": "unhealthy"}},
        {"container.Config.Image": validator.EXPECTED_IMAGE_REPOSITORY + ":latest"},
        {"container.Config.Image": "ghcr.io/other/codestra-caddy@" + DIGEST},
        {"container.Config.Labels": {validator.SOURCE_LABEL: SOURCE}},
        {"image.Config.User": "0:0"},
        {"image.Config.Labels": {"org.opencontainers.image.source": "https://github.com/evil/Caddy",
                                 "org.opencontainers.image.revision": SOURCE, validator.CONFIG_LABEL: "c" * 64}},
        {"image.RepoDigests": []},
    ):
        broken = container_fixture(**override)
        with pytest.raises(validator.ValidationError):
            validator.require_container_identity(*broken)


def test_runtime_environment_validates_without_echoing_values():
    import pytest
    container, _ = container_fixture()
    entries = container["Config"]["Env"]
    required = {"CADDY_PUBLIC_BIND", "CADDY_PRIVATE_METRICS_BIND", "CADDY_KONG_UPSTREAM", "CADDY_EDITOR_ADMIN_CIDRS"}
    assert set(validator.runtime_environment(entries, required)) == required
    for bad in ("CADDY_KONG_UPSTREAM=kong", "CADDY_PUBLIC_BIND=not-an-ip", "CADDY_EDITOR_ADMIN_CIDRS=999.0.0.0/8",
                "CADDY_PRIVATE_METRICS_BIND=8.8.8.8"):
        name = bad.split("=", 1)[0]
        mutated = [entry for entry in entries if not entry.startswith(name + "=")] + [bad]
        with pytest.raises(validator.ValidationError) as caught:
            validator.runtime_environment(mutated, required)
        assert bad.split("=", 1)[1] not in str(caught.value)
    with pytest.raises(validator.ValidationError):
        validator.runtime_environment(entries, required | {"CADDY_MISSING_UPSTREAM"})


def test_listener_must_belong_to_the_single_caddy_process():
    import pytest
    table = "PID PPID COMMAND ARGS\n4242 4200 caddy /usr/bin/caddy run --config /etc/caddy/Caddyfile\n"
    pid = validator.caddy_host_pid(table)
    sockets = 'tcp LISTEN 0 4096 203.0.113.10:443 0.0.0.0:* users:(("caddy",pid=4242,fd=7))'
    assert validator.require_listener(sockets, "tcp", "203.0.113.10", 443, pid) == "tcp/203.0.113.10:443"
    with pytest.raises(validator.ValidationError):
        validator.require_listener(sockets.replace("pid=4242", "pid=999"), "tcp", "203.0.113.10", 443, pid)
    with pytest.raises(validator.ValidationError):
        validator.caddy_host_pid(table + "4243 4200 caddy /usr/bin/caddy run\n")


def test_main_does_not_report_success_when_served_configuration_drifts(monkeypatch, capsys, tmp_path):
    import pytest
    fields = {name: {'filter': 'delete'} for name in (
        'request>headers>Authorization', 'request>headers>Apikey', 'request>headers>X-Api-Key',
        'request>headers>Proxy-Authorization', 'request>headers>Cookie', 'resp_headers>Set-Cookie')}
    fields['request>uri'] = {'filter': 'query', 'actions': [
        {'type': 'delete', 'parameter': name} for name in (
            'apikey', 'api_key', 'access_token', 'refresh_token', 'id_token',
            'client_secret', 'password', 'secret', 'token')]}
    desired = {
        'admin': {'listen': validator.ADMIN_ADDRESS},
        'logging': {'logs': {'log0': {'include': ['http.log.access.log0'], 'encoder': {'fields': fields}}}},
        'apps': {'http': {'servers': {'srv0': {
            'listen': [':443'], 'logs': {'logger_names': {'api.codestra.co': ['log0']}},
            'routes': [{'match': [{'host': ['api.codestra.co']}], 'handle': [
                {'handler': 'reverse_proxy', 'upstreams': [{'dial': 'kong:8000'}]}]}]
        }}}}}
    container, image = container_fixture(config_sha="e" * 64)
    source = '\n'.join(validator.REQUIRED_REDACTIONS)
    sockets = '\n'.join(
        f'{proto} LISTEN 0 4096 {address}:{port} 0.0.0.0:* users:(("caddy",pid=4242,fd=7))'
        for proto, address, port in (("tcp", "203.0.113.10", 80), ("tcp", "203.0.113.10", 443),
                                     ("udp", "203.0.113.10", 443), ("tcp", "10.40.0.1", 2020),
                                     ("tcp", "10.40.0.1", 18080)))
    calls = []

    def run(command, environment=None):
        calls.append(command)
        tail = command[1:3]
        if tail == ["inspect", validator.CONTAINER]:
            return json.dumps([container])
        if tail[0] == "image":
            return json.dumps([image])
        if tail[0] == "top":
            return "PID PPID COMMAND ARGS\n4242 4200 caddy /usr/bin/caddy run --config /etc/caddy/Caddyfile\n"
        if command[0] == validator.SS:
            return sockets
        if command[0] == validator.CURL:
            return "ok"
        if "adapt" in command:
            return json.dumps(desired)
        if "list-modules" in command:
            return "\n".join(sorted(validator.REQUIRED_MODULES))
        assert "validate" in command
        return ""

    monkeypatch.setattr(validator.sys, 'argv', ['validator'])
    monkeypatch.setattr(validator, 'run_fixed', run)
    monkeypatch.setattr(validator, 'container_config', lambda copied: (source, "e" * 64))
    monkeypatch.setattr(validator, 'active_configuration', lambda: {'old': 'secret-runtime-value'})
    with pytest.raises(validator.ValidationError, match='served configuration differs'):
        validator.main()
    assert capsys.readouterr().out == ''
    monkeypatch.setattr(validator, 'active_configuration', lambda: desired)
    assert validator.main() == 0
    evidence = json.loads(capsys.readouterr().out)
    assert evidence['served_config_matches_image'] is True
    assert evidence['config_identity'] == 'PASS' and evidence['image_digest'] == DIGEST
    assert len(evidence['listeners']) == 5
    assert all(command[0] in {validator.DOCKER, validator.SS, validator.CURL} for command in calls)
    assert not any(verb in command for command in calls for verb in ("rm", "stop", "restart", "kill", "load"))

    monkeypatch.setattr(validator, 'container_config', lambda copied: (source, "f" * 64))
    with pytest.raises(validator.ValidationError, match='does not match the signed image'):
        validator.main()


def test_config_tree_hash_matches_the_release_hash_tool(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("hash_config_tree", ROOT / "scripts" / "hash_config_tree.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stage = importlib.util.spec_from_file_location("stage_image_config", ROOT / "scripts" / "stage_image_config.py")
    staging = importlib.util.module_from_spec(stage)
    stage.loader.exec_module(staging)
    tree = tmp_path / "etc-caddy"
    staged = staging.stage(tree)
    assert "Caddyfile" in staged and not any(path.startswith("sites-pending") for path in staged)
    (tree / "private" / "klyrow-events").mkdir(parents=True)
    (tree / "private" / "klyrow-events" / ".mountpoint").write_text("")
    assert validator.config_tree_hash(tree) == module.config_tree_hash(tree)
    assert validator.canonical_source(tree)[1] == module.config_tree_hash(tree)
