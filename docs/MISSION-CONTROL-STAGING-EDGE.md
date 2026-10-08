# Mission Control staging-only Caddy edge

This candidate only becomes active after the Keycloak and Kong owner reviews,
the 9 read-only dashboard routes have been certified, and the staging
environment has been configured. It is not imported by the root Caddyfile.

- Frontend URL: https://dashboard.staging.internal.codestra.agency/mission-control
- API: same-origin /platform/v1/dashboard/* through Kong to the independent
  Mission Control read-only service. There is no public direct upstream.
- Security: TLS internal, private metrics/admin denied, only enumerated GET
  APIs, identity headers stripped, failed requests not downgraded to frontend.
- Frontend requires OIDC/PKCE scope dashboard.read. Kong requires Keycloak
  staging issuer and mission-control-backend audience; backend repeats
  authorization and returns 401/403 when invalid.
- Set CADDY_KONG_UPSTREAM and CADDY_MISSION_CONTROL_FRONTEND_UPSTREAM using
  private staging service discovery. No production host or provider activation.
- Exact source SHA, Caddy-adapted output, Kong YAML manifest checksum, negative
  auth tests, and browser test report are needed for the staging certificate.

Production effects remain OFF; this file is a source-only staging candidate.
