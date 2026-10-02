# Domain Registry v1

## Canonical edge hosts

| Hostname | Owner | Environment | Purpose | Traffic class | Upstream | TLS mode |
| --- | --- | --- | --- | --- | --- | --- |
| `api.codestra.co` | appolon1908/Caddy | shared public API edge | public API ingress | API | `CADDY_KONG_UPSTREAM` | HTTPS termination |
| `automation.codestra.co` | appolon1908/Caddy | admin browser edge | operational/editor access | ADMIN | `CADDY_KONG_UPSTREAM` | HTTPS termination with admin CIDR gate |
| `n8n-editor.community` / `{$CADDY_N8N_EDITOR_HOST}` | appolon1908/Caddy | community editor edge | oauth2-proxy + n8n boundary | WEB | `CADDY_N8N_OAUTH2_PROXY_UPSTREAM` | HTTPS termination |
| observability host(s) | appolon1908/Caddy | repository-controlled policy boundary | monitoring UI exposure | OBSERVABILITY | validated internal-only upstreams | HTTPS-only, no public unapproved listener |

## Required metadata

Every host is expected to record:

- hostname
- owner
- environment
- purpose
- traffic_class
- upstream
- protocol
- port
- health_path
- TLS_mode
- WebSocket requirement
- maintenance behavior
- security-header profile
- logging profile

## Repository policy

The repository explicitly forbids public exposure of unapproved observability hosts and forbids direct upstreaming to n8n from public internet routes. The edge remains a transport boundary, not an identity or business-control plane.
