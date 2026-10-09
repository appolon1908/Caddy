# Codestra Caddy Edge

Canonical Git source for Codestra shared Caddy edge configuration and release policy.

## Principal authority

This repository is the **principal source** for shared Caddy TLS termination, public host selection, reverse-proxy configuration, shared edge request policy, security-header imports, access-log redaction, validation, and Caddy release evidence.

For the shared API edge, the required ownership chain is:

```text
client
  -> Caddy
  -> Kong
  -> Middleware
  -> owned downstream service
```

Caddy does not authenticate application users/services, does not issue identity, and does not create trusted application identity headers. It preserves the bearer token and canonical host so Kong can apply Keycloak OIDC/JWT, scope, route, rate, and request policy. Middleware then revalidates privileged authorization and remains the cross-system write boundary.

Each system keeps its own source authority:

- `appolon1908/Caddy` — shared Caddy TLS/reverse-proxy edge source and policy.
- `appolon1908/Kong` — Kong gateway services, routes, plugins, OIDC/scope policy and gateway reconciliation.
- `appolon1908/Keycloak` — identity, clients, scopes and token issuance.
- `appolon1908/Middleware-` — cross-system command/event control plane and privileged provider orchestration.
- product/provider repositories — their own application and runtime source.
- `appolon1908/codestra-production-platform` — historical runtime/deployment/reconciliation/rollback evidence only. It is a migration reference, not principal source for future Caddy changes.

## Canonical source layout

- `Caddyfile` — complete root source; the Caddy admin API listens only on a private Unix socket.
- `snippets/security_headers.caddy` — shared security-header snippet owned here, including HSTS. Every site block must import it; `scripts/validate_repository.py` fails the build if one does not.
- `sites/api.codestra.co.caddy` — shared API-edge routing source.
- `sites/automation.codestra.co.caddy` — administrative editor host gated by Kong's Keycloak browser flow (see "Two editor hosts, two gates").
- `config/caddy-kong-contract.v1.json` — machine-readable Caddy/Kong/Keycloak/Middleware boundary.
- `config/runtime-values.example` — non-secret runtime variable names and repository-backed reference listeners.
- `docs/CADDY_KONG_INTEGRATION.md` — migration and validation gates.
- `sites/n8n-editor.community.caddy` — Keycloak/oauth2-proxy boundary for the community-edition editor.
- `deploy/community-n8n/` — fail-closed node and outbound-network policy overlay.
- `config/community-n8n-credentials.v1.json` — metadata-only ownership and rotation contract.
- `config/observability-exposure.v1.json` — repository-only public/private observability URL contract.
- `sites/codestra.media.observability.caddy` — the only permitted observability UI/restricted-management routes.
- Production-lineage hosts carried forward from `caddy-production-2489bf0` (owner decision, 2026-09-30):
  `sites/api.breero.com.caddy`, `sites/api.codestra.agency.caddy`, `sites/auth.codestra.co.caddy`,
  `sites/crm.codestra.agency.caddy`, `sites/agent-desktop.codestra.agency.caddy`,
  `sites/monitoring.codestra.co.caddy`, `sites/n8n-legacy.codestra.agency.caddy`,
  `sites/staging-internal.caddy`, and the private listeners in `sites/middleware-private.caddy`
  and `sites/klyrow-events.private.caddy`. `tests/test_production_lineage_hosts.py` fails if any
  production address is dropped or a gate is weakened.
- `docs/PRODUCTION_RUNTIME.md`, `Dockerfile`, `deploy/compose.runtime.yaml` — the canonical production runtime: one immutable, signed, non-root container with controlled release and rollback.
- `sites-pending/kyyow.com.caddy` — Kyyow hosts, kept in source but not imported until their DNS and
  upstreams exist, so no certificate is requested for them.
- The root `Caddyfile` keeps the private `:2020` metrics listener that Prometheus scrapes as
  `caddy:2020`; it binds `CADDY_PRIVATE_METRICS_BIND` only.

Grafana and Superset are the only public observability UI routes. OpenBao has a
separate source-network gate in addition to native OIDC and policy enforcement.
Prometheus, Alertmanager, Loki, Tempo, OpenTelemetry, Alloy, every exporter, and
cAdvisor have no public Caddy site. In particular, `pgex.codestra.media` is a
prohibited public name, not a denial page or certificate target.

The runtime identity remains the canonical Keycloak-managed `n8n-automation`
client. The editor gateway uses the existing `n8n_operator` and `n8n_admin`
roles. Until OpenBao is commissioned, its client and cookie material is supplied
as root-owned Docker secret files; only paths and rotation metadata belong here.

## Two editor hosts, two gates

This repository deliberately ships two n8n editor edges. They are different
hosts with different audiences and different authentication gates, and both are
current source authority. Neither supersedes the other.

| Host | Chain | Gate | Audience |
| --- | --- | --- | --- |
| `automation.codestra.co` | Caddy -> Kong -> n8n | Kong runs the Keycloak authorization-code browser flow; n8n's native owner login stays enabled behind it | Codestra platform administrators |
| `{$CADDY_N8N_EDITOR_HOST}` | Caddy -> oauth2-proxy -> n8n | oauth2-proxy owns the Keycloak OIDC session and injects identity | Community-edition editor users |

`automation.codestra.co` additionally applies a `CADDY_EDITOR_ADMIN_CIDRS`
source-range gate ahead of the browser flow. Caddy authenticates nobody on
either host: it terminates TLS, strips spoofable identity headers, and hands off
to the gate that owns identity for that host. Pointing either host directly at
n8n on `:5678` is prohibited.

`n8n.codestra.agency` (and its staging twin) is the one reviewed exception: a
legacy staff editor reachable only from private source addresses, with a 403
for everyone else. It is not a third public editor, and adding any other editor
edge is prohibited.

## Runtime values that must be supplied before deployment

`config/runtime-values.example` ships deliberately unusable defaults. They fail
closed — Caddy refuses to load or the host answers `404`/`403` — so a missing
value can never widen access. None of them are deployable as written:

| Variable | Shipped value | Why it cannot ship as-is |
| --- | --- | --- |
| `CADDY_EDITOR_ADMIN_CIDRS` | `REPLACE_WITH_VERIFIED_ADMIN_CIDRS` | Not a CIDR; Caddy fails to parse the `remote_ip` matcher and refuses the config. |
| `CADDY_N8N_EDITOR_HOST` | `n8n-editor.invalid` | Reserved TLD; no DNS, no ACME certificate. |
| `CADDY_OPENBAO_ALLOWED_CIDRS` | `192.0.2.0/24 198.51.100.0/24` | TEST-NET-1/TEST-NET-2 documentation ranges; no real client matches, so OpenBao answers `403`. |
| `CADDY_GRAFANA_UPSTREAM`, `CADDY_SUPERSET_UPSTREAM`, `CADDY_OPENBAO_UPSTREAM` | loopback high ports | Repository-only validation references; they assert no production listener. |

Supplying real values is a deployment-review step performed outside Git, and
`validate_observability_exposure.py` fails if the committed examples are ever
replaced with routable ranges.

## Caddy -> Kong integration

The reviewed Kong repository exposes host-bound `api.codestra.co` route contracts and exercises the Kong data plane on loopback port `8000`. The Caddy source therefore uses `CADDY_KONG_UPSTREAM` for path families already represented in Kong source and preserves `Host: api.codestra.co` on that handoff.

The historical `codestra-production-platform` Caddy source used loopback listeners `18101` and `18102`. They are retained only as explicit environment-controlled migration fallbacks for paths that do not yet have proven Kong parity. They are **not** principal source authority and must be removed after the equivalent Kong routes pass staging acceptance.

No new shared API route should be added as a direct Caddy -> Middleware or Caddy -> provider path. The owning repository must add the service contract, Kong must own the gateway route/security policy, and Caddy then owns the outer edge handoff.

The private callback ingress (`middleware.internal.codestra.agency`, its staging twin, and the Klyrow
event listener on `:18080`) is the one reviewed exception to Caddy -> Middleware. Each binds only the
private interface, requires a verified client certificate, accepts one method+path from one source
range and answers 403 to everything else. It never carries public API traffic.

## Branch model

- `development` — active integration branch.
- `test` — configuration promoted after validation.
- `production` — release-candidate source for a live Caddy host.
- `main` — reviewed canonical baseline and release history.

Promotion flow: `feature/*` -> `development` -> `test` -> `production` -> `main`.

The repository may use short-lived authority or migration branches for source-convergence work, but accepted shared-edge source must end on reviewed `main` before an immutable release is created.

## Historical reference

The first `api.codestra.co` source was imported from:

`appolon1908/codestra-production-platform:release/production-activation:operations/caddy/api.codestra.co.caddy`

That repository is reference/evidence only. Its historical source does not prove a live host currently matches this repository.

Before any Caddy cutover:

1. inventory the live runtime read-only;
2. record active config/listener checksums;
3. compare live behavior with this repository;
4. validate Caddy -> Kong -> Middleware in write-disabled staging;
5. prove invalid identity is rejected at Kong;
6. rehearse rollback;
7. build/accept an immutable Caddy source artifact;
8. obtain explicit deployment approval;
9. reload using the reviewed artifact/config only;
10. perform post-change read-back.

## Safety rules

1. Never commit TLS private keys, API tokens, credentials, passwords, `.env` files, ACME account data, or Caddy data-directory contents.
2. Validate the complete root `Caddyfile` before a reload.
3. Keep the Caddy admin API on the `unix//run/caddy/admin.sock` socket; never expose it on a network listener.
4. Caddy must not manufacture `X-Authenticated-*` or gateway-secret headers.
5. Caddy must preserve the bearer token for Kong; Authorization is redacted from logs only.
6. Shared API paths represented in Kong source must route Caddy -> Kong, never directly to Middleware.
7. Back up active runtime configuration before replacement.
8. A failed validation must leave the running configuration untouched.
9. A merge does not automatically authorize a production reload, DNS/TLS change, or traffic cutover.
10. `codestra-production-platform` may be consulted for historical evidence, but new Caddy source changes belong here.
