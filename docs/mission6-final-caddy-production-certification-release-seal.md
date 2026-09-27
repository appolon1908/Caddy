# M6 — Final Caddy Production Certification & Release Seal

## Governing principle

Caddy is the secure ingress / Edge TLS plane. Kong remains the API gateway behind it. Caddy does not absorb Keycloak, Middleware, Odoo, or n8n responsibilities.

## Mission structure

### 1. Candidate freeze
- freeze the reviewed source and candidate runtime configuration
- record exact hashes, build/release references, and deployment metadata
- prevent further drift before certification gate review

### 2. Complete Linux regression
- validate Caddy service startup and configuration reload behavior on the target OS/runtime
- verify admin API remains loopback-only and non-public
- confirm no extra listener or unrestricted port exposure is introduced

### 3. Caddy config validation
- run canonical Caddy validation against the exact target configuration
- verify all imported snippets and site blocks load without syntax or policy drift
- reject invalid templates or stale references

### 4. Real TLS certification
- validate real certificate acquisition, trust chain, and expiry behavior
- confirm redirects and public hosts are HTTPS-only where required
- verify certificate errors fail closed instead of silently broadening access

### 5. Host / path / method routing
- test all public hosts and approved path families for correct route selection
- verify method restrictions and exact route precedence
- ensure unknown hosts, paths, and unsupported methods do not fall through to insecure defaults

### 6. Fail-closed tests
- confirm unknown host rejection
- confirm unknown route rejection
- confirm invalid upstream or policy case does not create a silent bypass
- confirm legacy fallback is never used for Kong-managed routes

### 7. Caddy → Kong boundary
- verify the public edge routes to Kong for reviewed gateway-managed traffic
- validate host preservation and required `Authorization` handling
- confirm Caddy does not create trusted app identity headers or direct business authorization

### 8. WebSocket / SSE
- validate upgrade handling, long-lived connection policy, and timeout behavior
- verify no buffering or proxy errors break real-time traffic
- confirm source and upstream policy remains appropriate to the traffic class

### 9. Upstream failure
- simulate upstream failure, timeout, and connection reset scenarios
- verify the edge fails safely and surfaces controlled responses without topology leakage
- ensure edge reliability does not create insecure fallback behavior

### 10. Maintenance
- validate maintenance mode behavior and response policy
- ensure maintenance windows remain scoped and explicit
- verify special-case bypasses are controlled and documented

### 11. Trusted proxy / security tests
- test trusted-proxy and forwarded-header handling
- validate spoofed `X-Forwarded-*` values are rejected or ignored appropriately
- confirm HSTS and edge security headers remain correct without weakening the API boundary

### 12. Logs / redaction / metrics
- confirm access logs redact Authorization and secret-bearing material
- verify metrics remain bounded and non-sensitive
- confirm correlation and request IDs support operational review without exposing secrets

### 13. Reload / rollback
- test reload success and rollback behavior under failure conditions
- confirm the previous known-good config remains active when validation fails
- preserve auditable evidence for each action

### 14. Restart persistence
- validate that the service resumes correctly after restart
- confirm configured state and policy remain consistent across process restarts
- ensure no unsafe implicit fallback appears on restart

### 15. Failure injection
- inject upstream outage, invalid TLS, invalid host, and malformed header scenarios
- confirm fail-closed responses remain stable and reviewable
- verify no business control plane responsibilities are accidentally assumed by Caddy

### 16. Security scan
- perform repository and config security review for secrets, credential exposure, and policy drift
- confirm no private keys, tokens, or deployment secrets are stored in Git
- ensure no plugin or route pattern increases the trust boundary beyond the edge contract

### 17. Evidence seal
- package validation logs, config hashes, health readbacks, and final approval evidence
- seal the release with the reviewed configuration identity
- keep the evidence chain available for audit and rollback review

### 18. GO / NO-GO
- GO only when the full edge certification set is green
- NO-GO when any route, TLS, trust boundary, identity boundary, or observability contract fails
- no production cutover is authorized by source-only approval

## Mission status

CADDY MISSION 6 — FINAL CADDY PRODUCTION CERTIFICATION & RELEASE SEAL:
IMPLEMENTATION COMPLETE — RUNTIME CERTIFICATION PENDING
