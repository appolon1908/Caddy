from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITES = sorted((ROOT / "sites").glob("*.caddy"))

SENSITIVE_LOG_DIRECTIVES = (
    "request>headers>Authorization delete",
    "request>headers>Proxy-Authorization delete",
    "request>headers>Cookie delete",
    "resp_headers>Set-Cookie delete",
)
SENSITIVE_QUERY_DIRECTIVES = (
    "delete access_token",
    "delete refresh_token",
    "delete id_token",
    "delete client_secret",
    "delete password",
    "delete secret",
    "delete api_key",
    "delete token",
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_structured_logging_and_sensitive_redaction_are_configured() -> None:
    for site_path in SITES:
        source = site_path.read_text(encoding="utf-8")
        assert "log {" in source
        assert "output file" in source
        assert "format filter" in source
        assert all(directive in source for directive in SENSITIVE_LOG_DIRECTIVES)
        assert all(directive in source for directive in SENSITIVE_QUERY_DIRECTIVES)


def test_authorization_and_secret_material_are_not_persisted() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in SITES)
    assert "request>headers>Authorization delete" in combined
    assert "request>headers>Proxy-Authorization delete" in combined
    assert "request>headers>Cookie delete" in combined
    assert "resp_headers>Set-Cookie delete" in combined
    assert "header_up Authorization" not in combined


def test_correlation_contract_does_not_claim_unimplemented_runtime_features() -> None:
    contract = read("docs/correlation-contract-v1.md")
    assert "records Caddy request UUIDs" in contract
    assert "traceparent" in contract
    assert "tracestate" in contract
    assert "Kong, which owns trust" in contract
    assert "No external tracing exporter is required" in contract


def test_metrics_contract_rejects_high_cardinality_designs_by_policy() -> None:
    contract = read("docs/metrics-contract-v1.md")
    assert "loopback Admin API" in contract
    assert "user ID" in contract
    assert "correlation ID" in contract
    assert "unbounded query values" in contract


def test_health_and_readiness_contract_is_present() -> None:
    routes = read("config/caddy-kong-contract.v1.json")
    api = read("sites/api.codestra.co.caddy")
    assert "/api/v1/health" in routes
    assert "/healthz" in routes
    assert "/readyz" in api
    assert "health/readiness" in read("docs/mission4-observability-operational-control.md")


def test_admin_api_is_loopback_only() -> None:
    caddyfile = read("Caddyfile")
    assert "admin 127.0.0.1:2019" in caddyfile
    assert "admin :2019" not in caddyfile
    assert "admin 0.0.0.0:2019" not in caddyfile


def test_candidate_validation_precedes_adaptation() -> None:
    ci = read("scripts/validate-ci.sh")
    assert ci.index("caddy adapt") < ci.index("caddy validate")
    assert "--validate" in ci
    assert "caddy reload" not in ci
    assert "systemctl reload caddy" not in ci


def test_reload_rollback_and_configuration_identity_contracts_exist() -> None:
    contract = read("docs/reload-rollback-contract-v1.md")
    for value in ("known-good", "Git SHA", "configuration hash", "environment", "UTC timestamp"):
        assert value in contract
    control = read("docs/mission4-observability-operational-control.md")
    assert "Finish rollback" in control
    assert "Configuration identity" in control


def test_monitoring_and_alert_boundaries_are_explicit() -> None:
    monitoring = read("docs/monitoring-boundary-v1.md")
    alerts = read("docs/alert-contract-v1.md")
    assert "Prometheus" in monitoring
    assert "does not become the monitoring authority" in monitoring
    assert "TLS certificate" in alerts
    assert "reload failure" in alerts
    assert "redaction regression" in alerts


def test_m1_identity_boundary_is_preserved() -> None:
    contract = read("config/caddy-kong-contract.v1.json")
    assert '"caddyAuthenticatesUsersOrServices": false' in contract
    assert '"authorizationHeaderForwardedToKong": true' in contract
    assert '"caddyCreatesTrustedApplicationIdentityHeaders": false' in contract


def test_m2_tls_and_security_boundary_is_preserved() -> None:
    headers = read("snippets/security_headers.caddy")
    assert "Strict-Transport-Security" in headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers
    for site_path in SITES:
        assert "import security_headers" in site_path.read_text(encoding="utf-8")


def test_m3_caddy_to_kong_routing_boundary_is_preserved() -> None:
    api = read("sites/api.codestra.co.caddy")
    assert "reverse_proxy {$CADDY_KONG_UPSTREAM}" in api
    assert "header_up Host {host}" in api
    assert "codestra-middleware-integration-api-1" not in api
    assert "http://middleware" not in api
    assert "https://middleware" not in api


def test_runtime_only_controls_are_not_falsely_certified() -> None:
    exposure = read("config/observability-exposure.v1.json")
    assert '"upstreamHealthVerified": false' in exposure
    assert '"liveCaddyReloadAuthorized": false' in exposure
    assert "RUNTIME CERTIFICATION PENDING" in read(
        "docs/mission4-observability-operational-control.md"
    )
