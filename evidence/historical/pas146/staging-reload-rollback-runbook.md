# PAS-146 — Staging, Reload, Rollback & Immutable Edge Candidate

## Scope

This package prepares the Caddy staging/reload/rollback certification lane without authorizing a runtime mutation.

Current staging chain:

```text
Caddy staging → Kong → Middleware :8095 → TEST_SYN
```

Caddy remains the public transport/TLS boundary only. Kong owns API authorization. Middleware owns command/business meaning and effect decisions. Caddy must never become provider or business authority.

## Current execution gate

Runtime execution is blocked until **all ten** current gates are true at the same time:

1. PAS-162 digest-chain authority is accepted PASS.
2. PAS-145 edge/API/Postman/V3 certification is accepted PASS.
3. PR #179 exact-head source-authority and deploy-readiness CI are green.
4. PR #179 has an independent approval recorded.
5. PR #179 is merged to Caddy `main`.
6. The exact merged Caddy main SHA is recorded.
7. Shared deploy-readiness repair `ingtrader21-spec/Infustruction-repo#126` is accepted and merged.
8. Caddy protected-main deploy-readiness is rerun green using the accepted reusable workflow.
9. PR #181 source-hygiene drift repair is merged from a reviewed/green exact head.
10. PAS-178 proves protected-main/review enforcement is active before runtime mutation.

The gate must be re-read immediately before any staging action. A historical PASS is not sufficient if the source head moved.

Current preparation state:

- PAS-162: **Done / Complete Verified**.
- PAS-145: **Done / Complete Verified**.
- PR #179: merged to `main`; exact-head source-authority/deploy-readiness PASS; independent approval from `kazan555`.
- Current protected main: `22c6d51ed2f5340139177131fb810e787f0f7550`.
- Shared deploy-readiness root: **PASS**. `Infustruction-repo#126` merged as `5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636` with independent approval.
- Caddy repin PR #183 is open. Its source-authority workflow is green (`validate-source`, `validate-merge-result`, aggregate `validate`), but deploy-readiness still fails before jobs instantiate; the wrapper is being localized because Caddy is public while the shared reusable-workflow repository remains private.
- A fresh Caddy protected-main deploy-readiness PASS is still required after the accepted workflow is callable from Caddy and merged.
- PR #181: local exact-head source, native Caddy, Postman, route, digest-chain, full pytest and Gitleaks gates PASS; it remains unmerged pending reviewed exact-head CI on the current base.
- PAS-178: **Done / Complete Verified**. Caddy is public, `main.protected=true`, and active rulesets require PR review, one approval, stale-review dismissal, last-push approval, thread resolution, strict status checks and no bypass actors.
- Start gates satisfied: **8/10**.
- Runtime action authorized: **NO**.
- Provider effects / business writes / production GO remain **0 / 0 / NO**.

## Prepared immutable identities

Prepared-from PR head:

`8a0ff7f45e5b50750a603a9e653ff2687e25361a`

Pinned Caddy runtime:

`docker.io/library/caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c`

Caddy version:

`v2.10.0`

Prepared configuration SHA-256:

`f77be0593ce3c728749ee8930ebe21c6f7191bb6c6d47d661a2cee056f50463b`

External authorities carried by the preparation contract:

- Middleware source: `bd406a6508c8095a3f23b35149a2eebcb94c94c6`
- Middleware public contract: `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`
- canonical Middleware port: `8095`
- required Kong source: `3e68cb2a4955bd71ddb3e839f4d9e3770465fc08`
- required Keycloak source: `45a487d7…469ffe7a` (full exact SHA is retained in the machine-readable candidate record)

These are current preparation inputs. PAS-162, PAS-145, the shared deploy-readiness repair (#126), and PAS-178 are accepted. Runtime remains blocked only by a fresh Caddy protected-main deploy-readiness PASS after the Caddy workflow repin/localization and the reviewed merge of PR #181.

## Machine-readable artifacts

- `release/pas146/caddy-staging-candidate.v1.json`
- `release/pas146/caddy-staging-evidence.template.v1.json`
- `scripts/validate_caddy_staging_candidate.py`
- `tests/test_caddy_staging_candidate.py`

Static validation:

```text
python scripts/validate_caddy_staging_candidate.py
python -m pytest -q tests/test_caddy_staging_candidate.py
```

## Runtime procedure — execute only after all ten current start gates pass

### 1. Freeze exact merged source

Record the exact current protected-main SHA immediately before staging. Rebase/regenerate this preparation package if `main` has moved (including after PR #181). Recompute the desired-state digest:

```text
python scripts/config_digest.py
```

Do not execute if the digest differs from the candidate record until the candidate record has been reviewed and updated.

### 2. Prove the immutable Caddy runtime

Use only the digest-pinned Caddy image. Do not replace it with a mutable tag.

Required evidence:

- image reference
- image digest
- reported Caddy version
- source/configuration SHA
- timestamp

### 3. Validate before reload

Before touching the running process:

- repository validator PASS
- Caddy format check PASS
- Caddy adapt PASS
- Caddy validate PASS
- digest-chain PASS
- private/pending route denial PASS
- no direct public Middleware/Odoo/n8n bypass
- last-known-good configuration captured
- pre-reload health captured
- effective runtime config hash captured

Any failure stops the run. Do not reload an invalid candidate.

### 4. TLS / ACME / certificate health

Capture evidence for:

- certificate chain
- hostname match
- not-before / expiry
- HTTPS redirect policy
- ACME storage health without exposing keys or account credentials
- renewal/rotation readiness
- negative TLS failure behavior

Do not store private keys, ACME account secrets, bearer tokens, cookies, passwords, or provider credentials in evidence.

### 5. Controlled staging reload

Only the approved staging host may be used.

The reload must use the reviewed exact configuration and must preserve:

- public host ownership
- Caddy → Kong boundary
- Authorization
- X-Correlation-ID
- Idempotency-Key
- traceparent
- tracestate
- public 404 for private namespaces
- no unknown-route bypass for Kong-managed routes

Record command metadata and outcome without storing secrets.

### 6. Staging chain probes

Exercise:

```text
Caddy staging → Kong → Middleware :8095 → TEST_SYN
```

Required positive/negative evidence includes:

- canonical route transport
- wrong issuer
- wrong audience
- wrong AZP
- wrong scope
- private/pending route denial
- wrong method
- Kong unavailable
- Middleware unavailable

Caddy must fail closed and must not route around Kong.

### 7. Restart / reconnect

After reload certification:

- restart the staging Caddy process using the approved runtime mechanism
- verify the exact effective configuration returns
- verify TLS health
- verify Kong connectivity
- verify TEST_SYN path
- verify no new listener/admin exposure
- verify no legacy bypass appeared

### 8. Rollback rehearsal

Rollback requires a captured last-known-good configuration.

The rehearsal must:

1. restore the last-known-good configuration
2. validate it
3. reload/restart using the approved staging mechanism
4. verify post-rollback health
5. verify effective config hash equals the last-known-good hash
6. record rollback evidence
7. restore the candidate again only after re-validation, if the staging plan requires it

A failed rollback is a NO-GO.

### 9. Evidence seal

Populate a copy of:

`release/pas146/caddy-staging-evidence.template.v1.json`

Record:

- merged Caddy source SHA
- immutable Caddy image/digest
- configuration SHA-256
- Caddy version
- Middleware SHA / contract digest
- Kong SHA
- Keycloak SHA
- TLS/ACME results
- reload result
- restart result
- rollback result
- before/after health
- effective config readback
- zero-effect counters

Do not modify the checked-in template to pretend a runtime execution occurred.

## Read-only/no-effect canary boundary

Any eventual production canary is strictly:

`READ_ONLY_NO_EFFECT`

The following remain zero:

- provider effects
- business writes
- PSTN calls
- payments
- production writes

Source approval or staging certification does not authorize those effects.

## Production blockers

Final production edge certification cannot be claimed while any of these remain non-zero/unclassified:

- `UNKNOWN_ROUTE_FALLBACK`
- unclassified public routes
- unclassified webhooks
- unclassified upstreams

The preparation record therefore intentionally says:

```text
UNKNOWN_ROUTE_FALLBACK_ZERO=NO
PRODUCTION_CANARY_AUTHORIZED=NO
PRODUCTION_GO=NO
```

PAS-146 may move from preparation to live staging execution only after all ten current start gates are reverified against current Linear/GitHub state.
