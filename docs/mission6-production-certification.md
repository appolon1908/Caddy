# Mission 6 Production Certification

## Certification scope

Mission 6 evaluates the frozen M1-M5 Caddy Edge Control Plane as one candidate. It does not deploy production or authorize DNS, certificate, traffic, or runtime mutation.

## Source and native gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Repository validator | PASS | `python scripts/validate_repository.py` |
| Full source regression | PASS, 88 passed | `python -m pytest -q` |
| Configuration identity | PASS | `python scripts/config_digest.py` matches `e75e85...` |
| Caddy adapt | PASS | pinned immutable Caddy image |
| Caddy validate | PASS | pinned immutable Caddy image |
| Secret scan / architecture checks | PASS | canonical validator |

## Runtime gates

The current host is Windows with Docker available, but no native Caddy binary, Linux staging target, governed DNS/TLS certificates, live Kong upstream, or authorized runtime readback/apply endpoint. Therefore these mandatory gates are not certified:

- TLS handshake, chain, hostname, redirect, renewal, and negative TLS tests
- known-host and unknown-host live routing
- Caddy -> Kong runtime boundary and legacy fallback failure behavior
- upstream failure injection, timeout, WebSocket, SSE, and maintenance behavior
- runtime structured-log marker leakage
- correlation and metrics runtime behavior
- public admin exposure and local management readback
- desired/effective runtime drift and controlled drift repair
- validated reload, invalid-candidate prevention, rollback, and restart recovery

## Verdict

`BLOCKED`

Blocker: `M6-RUNTIME-001` — mandatory Linux staging runtime evidence is unavailable. The source candidate is ready for execution on an authorized Linux certification environment, but this workspace cannot truthfully claim production certification.

Required retest: execute the runtime matrix from the Mission 6 specification against the exact Git SHA and configuration SHA recorded in `mission6-release-candidate.md`, then rerun the full source regression after any repair.
