# Codestra live platform certification — 2026-10-08

This evidence binds repository desired state to the live work completed on
2026-10-08 (with final UTC verification after midnight). It contains no
credentials, tokens, private keys, password hashes, or database data.

## Public endpoint certification

| URL | Expected result | Certified result |
| --- | --- | --- |
| https://codestra.co/ | customer frontend | HTTP 200 |
| https://crm.codestra.agency/web/login | Odoo 20 CRM login | HTTP 200 |
| https://app.klyrow.com/ | Klyrow browser app | HTTP 200 after login redirect |
| https://grafana.codestra.co/ | Grafana operator UI | HTTP 200 after login redirect |
| https://analytics.codestra.co/ | Superset operator UI | HTTP 200 after login redirect |
| https://auth.codestra.co/realms/codestra/.well-known/openid-configuration | canonical Codestra issuer | HTTP 200; issuer=https://auth.codestra.co/realms/codestra |
| https://monitoring.codestra.co/ | monitoring entrypoint | HTTP 200 after redirect to Grafana |
| https://prometheus.codestra.co/ | protected Prometheus UI | HTTP 401 without edge credentials |
| https://alerts.codestra.co/ | protected Alertmanager UI | HTTP 401 without edge credentials |

GoDaddy/public resolver readback for the certified hosts resolves to the current
Codestra ingress IPv4: 179.52.246.125.

## Server-side readiness

### s1-middleware
- Caddy: active.
- SentinelX: active.
- Public DNS/TLS routing: active.
- Caddy remains the public TLS and request-boundary authority.

### Server-3 / CRM
- SentinelX: active.
- Odoo login: HTTP 200 on the private upstream.
- Codestra frontend health: HTTP 200 on the private upstream.
- Klyrow health: HTTP 200 on the private upstream.
- Klyrow gateway host publication is restored on the reviewed server-side port.
- Odoo database-manager paths are denied at the public edge.

### s2-monitoring
- Prometheus readiness: HTTP 200.
- Grafana health: HTTP 200.
- Alertmanager readiness: HTTP 200.
- Superset health: HTTP 200.
- Keycloak Codestra realm discovery: HTTP 200.
- OpenTelemetry collector, Loki, Tempo and Alloy are running.
- Loki, Tempo, Alloy, OpenTelemetry collectors and exporters remain private.

## Identity recovery

The canonical Keycloak realm was restored from the repository definition
config/realms/codestra.json. Public readback returns the exact canonical issuer:

https://auth.codestra.co/realms/codestra

The base realm restore did not embed users or client secrets in source.

## Safety and access boundaries

- Prometheus and Alertmanager public operator aliases require edge authentication.
- Odoo database-manager URLs are fail-closed at the edge.
- Client-supplied trusted identity headers are stripped at the public boundary.
- Live backend IP addresses and credential hashes are environment supplied, not committed.
- Klyrow external email/provider effects remain governed separately from browser availability.
- OpenBao is not exposed by the platform-public route contract.

## OpenBao exception

OpenBao is running but remains sealed after the monitoring-server reboot. Its
health endpoint returns HTTP 503 while sealed. This certification therefore does
not claim OpenBao green or unsealed. The protected local unseal material remains
outside Git and was not copied into this evidence.

## Repository certification

The Caddy change adds a machine-readable public-site contract, negative tests,
runtime placeholders, fail-closed Odoo database-manager protection, protected
Prometheus/Alertmanager operator aliases, and the live route desired state.

Required certification is:
- repository authority validation,
- observability exposure validation,
- platform-public-site validation,
- Caddy adapt and validate,
- complete pytest suite,
- git diff whitespace/conflict check,
- live DNS/TLS/HTTP readback.

No direct push to protected main is authorized by this evidence.
