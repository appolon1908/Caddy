import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "caddy_v3_edge_probe.py"
KONG = "127.0.0.1:8000"
LEGACY = "127.0.0.1:18101"

SPOOFABLE_IDENTITY_HEADERS = [
    "X-User-ID",
    "X-Username",
    "X-Email",
    "X-Roles",
    "X-Scopes",
    "X-Authenticated-UserID",
    "X-Authenticated-User",
    "X-Authenticated-Client",
    "X-Authenticated-Subject",
    "X-Authenticated-Tenant",
    "X-Authenticated-Campaign",
    "X-Authenticated-Role",
    "X-Authenticated-Email",
    "X-Codestra-Tenant",
    "X-Codestra-Scopes",
    "X-Codestra-Gateway-Secret",
    "X-Internal-Service",
    "X-Admin",
    "X-Consumer-ID",
    "X-Consumer-Username",
    "X-Consumer-Custom-ID",
    "X-Credential-Identifier",
    "X-Anonymous-Consumer",
]

# The same synthetic upstream values scripts/validate-ci.sh passes to the
# pinned validator image; the adapted document must never carry real hosts.
CI_ENVIRONMENT = {
    "CADDY_KONG_UPSTREAM": KONG,
    "CADDY_LEGACY_API_UPSTREAM": LEGACY,
    "CADDY_REALTIME_UPSTREAM": "127.0.0.1:18102",
    "CADDY_EDITOR_ADMIN_CIDRS": "192.0.2.0/24",
    "CADDY_N8N_EDITOR_HOST": "n8n-editor.invalid",
    "CADDY_N8N_OAUTH2_PROXY_UPSTREAM": "127.0.0.1:4180",
    "CADDY_N8N_EDITOR_MAX_REQUEST_BODY": "16777216",
    "CADDY_GRAFANA_UPSTREAM": "127.0.0.1:18003",
    "CADDY_SUPERSET_UPSTREAM": "127.0.0.1:18088",
    "CADDY_OPENBAO_UPSTREAM": "127.0.0.1:18200",
    "CADDY_CODESTRA_WEB_UPSTREAM": "127.0.0.1:13080",
    "CADDY_ODOO_CRM_UPSTREAM": "127.0.0.1:18069",
    "CADDY_KLYROW_UPSTREAM": "127.0.0.1:18081",
    "CADDY_KEYCLOAK_UPSTREAM": "127.0.0.1:18180",
    "CADDY_PROMETHEUS_UPSTREAM": "127.0.0.1:19090",
    "CADDY_ALERTMANAGER_UPSTREAM": "127.0.0.1:19093",
    "CADDY_MONITORING_ADMIN_HASH": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    "CADDY_OPENBAO_ALLOWED_CIDRS": "192.0.2.0/24 198.51.100.0/24",
    "CADDY_KYYOW_APP_UPSTREAM": "127.0.0.1:18300",
    "CADDY_KYYOW_API_UPSTREAM": "127.0.0.1:18301",
    "CADDY_KYYOW_SEARCH_UPSTREAM": "127.0.0.1:18302",
    "CADDY_KYYOW_DOCS_UPSTREAM": "127.0.0.1:18303",
    "CADDY_KYYOW_AUTH_UPSTREAM": "127.0.0.1:18304",
    "CADDY_KYYOW_STATUS_UPSTREAM": "127.0.0.1:18305",
}


def load_module():
    spec = importlib.util.spec_from_file_location("caddy_v3_edge_probe", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def proxy(dial, **headers):
    handler = {"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}
    if headers:
        handler["headers"] = {"request": headers}
    return handler


def site(routes):
    """Wrap api.codestra.co subroutes the way `caddy adapt` nests them."""
    return {
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "routes": [
                            {
                                "match": [{"host": ["api.codestra.co"]}],
                                "handle": [{"handler": "subroute", "routes": routes}],
                                "terminal": True,
                            }
                        ]
                    }
                }
            }
        }
    }


# Shape of sites/api.codestra.co.caddy on main before the prefix rules: an
# explicit @kong list without the V3/automation/odoo families, then realtime,
# then the legacy catch-all.
def legacy_fallback_document():
    return site(
        [
            {
                "match": [{"path": ["/api/v1/control*", "/v1/integrations/n8n*", "/v1/crm*"]}],
                "handle": [proxy(KONG, set={"Host": ["{http.request.host}"]})],
            },
            {
                "match": [{"path": ["/ws/agent", "/healthz"]}],
                "handle": [proxy("127.0.0.1:18102")],
            },
            {"handle": [proxy(LEGACY, set={"Host": ["{http.request.host}"]})]},
        ]
    )


# Shape with host-level prefix transport to Kong ahead of the fallback and the
# private namespace refused at the edge.
def kong_prefix_document():
    return site(
        [
            {
                "match": [{"path": ["/internal*", "/metrics*"]}],
                "handle": [{"handler": "static_response", "status_code": 404}],
            },
            {
                "match": [
                    {
                        "path": [
                            "/api/v1/events/telnexa",
                            "/api/v1/n8n/acknowledgements",
                            "/v1/observability/incidents",
                            "/v1/observability/kpis",
                            "/webhooks/sms/inbound/*",
                            "/webhooks/vicidial/call-result/*",
                        ]
                    }
                ],
                "handle": [{"handler": "static_response", "status_code": 404}],
            },
            {
                "match": [
                    {
                        "path": [
                            "/v2/automation*",
                            "/platform/v1*",
                            "/api/v1/odoo/events*",
                            "/api/v1/integrations/n8n/results*",
                            "/api/v1/control*",
                            "/v1/integrations/n8n*",
                        ]
                    }
                ],
                "handle": [
                    proxy(
                        KONG,
                        set={"Host": ["{http.request.host}"], "X-Real-IP": ["{http.request.remote.host}"]},
                        delete=SPOOFABLE_IDENTITY_HEADERS,
                    )
                ],
            },
            {"handle": [proxy(LEGACY)]},
        ]
    )


class ProbeTableTests(unittest.TestCase):
    def test_probe_table_covers_the_six_v3_kernel_operations(self):
        module = load_module()
        templated = [
            (method, path.replace("OP-TEST-SYN-0001", "{operation_id}"))
            for method, path in module.V3_KERNEL_PROBES
        ]
        self.assertEqual(
            templated,
            [
                ("POST", "/platform/v1/commands"),
                ("GET", "/platform/v1/kernel/describe"),
                ("GET", "/platform/v1/operations/{operation_id}"),
                ("GET", "/platform/v1/operations/{operation_id}/timeline"),
                ("POST", "/platform/v1/operations/{operation_id}/cancel"),
                ("POST", "/platform/v1/operations/{operation_id}/replay"),
            ],
        )

    def test_negative_table_covers_metrics_internal_and_retired_n8n(self):
        module = load_module()
        paths = {path for _, path in module.NEGATIVE_PROBES}
        self.assertIn("/metrics", paths)
        self.assertTrue(any(path.startswith("/internal/") for path in paths))
        self.assertTrue(any(path.startswith("/v1/integrations/n8n/") for path in paths))


class LegacyFallbackDetectionTests(unittest.TestCase):
    def test_v3_kernel_falling_to_legacy_upstream_fails(self):
        module = load_module()
        results = module.probe_edge(legacy_fallback_document(), KONG)
        kernel = [r for r in results if r.group == "V3_KERNEL"]
        self.assertEqual(len(kernel), 6)
        for result in kernel:
            self.assertFalse(result.ok, result)
            self.assertEqual(result.resolution.upstream, LEGACY, result)

    def test_family_and_private_namespace_falling_to_legacy_fail(self):
        module = load_module()
        results = {(r.method, r.path): r for r in module.probe_edge(legacy_fallback_document(), KONG)}
        for probe in (
            ("POST", "/v2/automation/commands"),
            ("POST", "/api/v1/odoo/events"),
            ("GET", "/metrics"),
            ("GET", "/internal/v1/anything"),
        ):
            self.assertFalse(results[probe].ok, results[probe])

    def test_retired_n8n_namespace_reaching_kong_is_acceptable(self):
        module = load_module()
        results = {(r.method, r.path): r for r in module.probe_edge(legacy_fallback_document(), KONG)}
        self.assertTrue(results[("POST", "/v1/integrations/n8n/commands")].ok)


class KongPrefixTransportTests(unittest.TestCase):
    def test_prefix_rule_transports_every_probe_to_kong_or_refuses_it(self):
        module = load_module()
        results = module.probe_edge(kong_prefix_document(), KONG)
        self.assertTrue(all(result.ok for result in results), [r for r in results if not r.ok])
        self.assertEqual(module.header_policy_violations(kong_prefix_document()), [])

    def test_caddy_404_for_private_namespace_counts_as_denied(self):
        module = load_module()
        resolution = module.resolve_request(kong_prefix_document(), "GET", "/internal/v1/anything")
        self.assertIsNone(resolution.upstream)
        self.assertEqual(resolution.response_status, 404)


class HeaderPolicyTests(unittest.TestCase):
    def _document_with_handoff_headers(self, **headers):
        requested_delete = list(headers.pop("delete", []))
        headers["delete"] = [*SPOOFABLE_IDENTITY_HEADERS, *requested_delete]
        return site([{"match": [{"path": ["/platform/v1*"]}], "handle": [proxy(KONG, **headers)]}])

    def test_setting_authorization_or_identity_headers_is_a_violation(self):
        module = load_module()
        document = self._document_with_handoff_headers(
            set={"Authorization": ["Bearer minted"], "X-Authenticated-Tenant": ["t1"], "Host": ["x"]}
        )
        self.assertEqual(
            module.header_policy_violations(document),
            ["set:authorization", "set:x-authenticated-tenant"],
        )

    def test_deleting_idempotency_or_trace_headers_is_a_violation(self):
        module = load_module()
        document = self._document_with_handoff_headers(delete=["Idempotency-Key", "traceparent", "Cookie"])
        self.assertEqual(
            module.header_policy_violations(document),
            ["delete:idempotency-key", "delete:traceparent"],
        )

    def test_host_and_real_ip_only_is_clean(self):
        module = load_module()
        document = self._document_with_handoff_headers(
            set={"Host": ["{http.request.host}"], "X-Real-IP": ["{http.request.remote.host}"]}
        )
        self.assertEqual(module.header_policy_violations(document), [])

    def test_missing_spoofed_identity_stripping_is_a_violation(self):
        module = load_module()
        document = site(
            [
                {
                    "match": [{"path": ["/platform/v1*"]}],
                    "handle": [proxy(KONG, set={"Host": ["{http.request.host}"]})],
                }
            ]
        )
        violations = module.header_policy_violations(document)
        self.assertTrue(any(item.startswith("not-stripped:") for item in violations), violations)


class CommandLineTests(unittest.TestCase):
    def test_cli_exit_code_reflects_failures(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            bad = Path(tmp) / "bad.json"
            good.write_text(json.dumps(kong_prefix_document()), encoding="utf-8")
            bad.write_text(json.dumps(legacy_fallback_document()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(module.main([str(good), "--kong-upstream", KONG]), 0)
            self.assertIn("CADDY_V3_EDGE_PROBE=PASS FAILURES=0", captured.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(module.main([str(bad), "--kong-upstream", KONG]), 1)
            self.assertIn("CADDY_V3_EDGE_PROBE=FAIL", captured.getvalue())


@unittest.skipUnless(os.environ.get("CADDY_BIN"), "set CADDY_BIN to probe the adapted repository config")
class RepositoryConfigTests(unittest.TestCase):
    """Adapt the repository Caddyfile with a real binary and probe the result.

    This is the source-level assertion the V3 edge contract needs: every kernel
    operation on the canonical host must land on CADDY_KONG_UPSTREAM. It is
    expected to fail on any source revision whose legacy fallback still catches
    /platform/v1*, and to pass once the prefix handoff to Kong is in place.
    """

    def test_repository_config_transports_v3_kernel_to_kong(self):
        module = load_module()
        completed = subprocess.run(
            [os.environ["CADDY_BIN"], "adapt", "--config", str(ROOT / "Caddyfile"), "--adapter", "caddyfile", "--validate"],
            capture_output=True,
            text=True,
            env={**os.environ, **CI_ENVIRONMENT},
            cwd=ROOT,
            check=True,
        )
        document = json.loads(completed.stdout)
        failed = [r for r in module.probe_edge(document, KONG) if not r.ok]
        self.assertEqual(failed, [], "\n".join(f"{r.group} {r.method} {r.path} -> {r.resolution.upstream}" for r in failed))
        self.assertEqual(module.header_policy_violations(document), [])


if __name__ == "__main__":
    unittest.main()
