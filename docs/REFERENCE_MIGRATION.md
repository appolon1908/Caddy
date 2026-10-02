# Caddy reference migration

## Decision

`appolon1908/Caddy` is the principal Git source for shared Codestra Caddy edge configuration.

`appolon1908-hue/codestra-production-platform` is retained as historical runtime, deployment, reconciliation and rollback evidence. Historical Caddy files there must not receive new feature development after this authority change.

## Imported baseline

The first source baseline was copied from:

- repository: `appolon1908/codestra-production-platform`
- ref: `release/production-activation`
- path: `operations/caddy/api.codestra.co.caddy`
- historical blob: `35779597f413a78e78c5297e24d8510b661a170f`
- destination: `sites/api.codestra.co.caddy`

The import is source-only and does not claim runtime convergence.

## Cutover requirements

Before using this repository to change a live Caddy host:

1. inventory the active host configuration read-only;
2. capture hashes for the active Caddyfile and imported fragments;
3. reconcile any runtime-only differences into reviewed source here;
4. validate the complete assembled configuration with the intended Caddy version;
5. test Caddy → Kong/Middleware routes in staging;
6. verify TLS, request limits, security headers and credential redaction;
7. rehearse rollback to the prior known-good configuration;
8. deploy only an explicitly reviewed immutable source identity;
9. record runtime read-back after reload.

No production reload is authorized by this document or by merging its pull request.
