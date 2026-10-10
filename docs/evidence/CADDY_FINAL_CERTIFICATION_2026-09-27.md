# Caddy Final Certification — 2026-09-27

Canonical source SHA: `74c5035627a960c190dcdaf84ec3ac1a18181e0a`

Certification result: **NO-GO for production**

The source checks below passed at the recorded historical SHA. They do not clear the release blockers in `docs/CADDY_CANONICAL_CONVERGENCE.md`: the pinned image has 6 critical and 75 high vulnerabilities and requires patched-image certification. Production approval remains blocked until that evidence is collected.

## Evidence

- Full repository gate: `261 passed, 114 subtests passed`
- Live convergence harness with pinned Caddy v2.10.0: `PASS`
- Database/public-boundary assertions: `17 passed`
- Caddy configuration validation: `Valid configuration`
- Caddy repository authority: `PASS`
- Caddy → Kong contract: `PASS`
- Kong route contract bidirectional parity: `PASS`
- Adapted route matrix: `PASS` (`11 canonical`, `28 fail-closed`, `1 unknown-route probe`)
- Private `/internal` and `/metrics` namespaces: fail-closed
- PostgreSQL/Redis/NATS/Temporal internal services: no public Caddy exposure
- OpenBao: `bao.codestra.media` is an allowlisted public ingress; unauthorized clients are denied. It is not a private-only service.
- Identity header stripping and private-boundary enforcement: `PASS`
- Observability URL contract: `PASS`
- Kyyow ingress contract: `PASS`
- Community n8n security contract: `PASS`
- Postman/Newman live harness: `PASS`
- Working tree at certification start/end: clean

## Postman evidence

Source and generated collection SHA-256:

`146730776132c946bd559178ec1062c92674e9502c7d4ed27f5b6057493a01e8`

Safe-local environment SHA-256:

`842bf78b5c4cae41ca95d03f15a71bd7ddc2bf3ed6f5976563cb9cbb58cb837e`

## Scope boundary

This certificate covers source implementation, edge routing, API/Postman behavior, runtime reload/rollback harness behavior, and database/control-plane public-denial guarantees.

The following remain authorization-gated and do not constitute production certification:

- `LIVE_RELOAD_AUTHORIZED=NO`
- `N8N_COMMUNITY_EDITOR_EDGE=PREPARED_NOT_APPLIED`

No production reload or deployment effect was performed by this certification.
