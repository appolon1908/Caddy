# PAS-145 — Edge/API/Postman and V3 probe certification

## Source and ownership

- Repository: `ingtrader21-spec/Caddy`
- Canonical successor PR: #175
- PAS-162 accepted technical head: `e29247990a05c6ed1d8c88bfd48a2816dfa90770`
- Agent-2 branch: `mission/caddy-pas145-edge-certification-20260920`
- Primary local checkout remains untouched:
  `C:\Users\agent\Documents\GitHub\Caddy`
- Preserved primary head:
  `1f72905471645d490e7bd4ddf20a11d846df1446`

PAS-145 owns certification tooling, Postman generation/checks and
source/adapted-route evidence. It does not own PAS-162 digest-chain authority
files and does not perform PAS-146 reload/deployment/rollback actions.

## Real Caddy adapter certification

The current source was adapted and validated with the checksum-verified
official Caddy v2.10.0 Windows amd64 release.

- Caddy: `v2.10.0 h1:fonubSaQKF1YANl8TXqGcn4IbIRUDdfAkpcsfI/vX5U=`
- release ZIP SHA-512:
  `cb97adb2bff5de752e470486ae72d55a6ddcfe4bfa43f09ed849260955df7f61385ac1e2d28fc80458b6910d71fa38d4295bb0689263dcc1743f2050d847c2ad`
- adapted JSON SHA-256:
  `0850afc881c99ce9c1091874de237713404b4cd753c07b85670d2cfe55088d42`
- synthetic explicit Kong upstream: `127.0.0.1:8000`
- synthetic legacy upstream: `127.0.0.1:18101`

This is source/adapted-config certification only. No Caddy reload, deployment,
DNS change, certificate cutover or provider/business effect occurred.

## V3 edge probe

The real adapted JSON was passed to
`scripts/caddy_v3_edge_probe.py` with the explicit Kong upstream.

Certified:

- all six V3 kernel probes route to Kong;
- `/v2/automation/*` probes route to Kong;
- canonical Odoo and n8n ingress route to Kong;
- wrong-method and unknown canonical namespace probes do not hit the legacy
  upstream;
- `/metrics`, `/metrics/*`, `/internal/*` return public 404 before any
  upstream;
- pending Telnexa, VICIdial, n8n acknowledgement, observability and SMS ingress
  return public 404 before the legacy fallback;
- Authorization, X-Correlation-ID, Idempotency-Key, traceparent and tracestate
  are preserved;
- every contracted spoofable identity/consumer header is stripped before the
  Kong handoff.

Result:

```text
CADDY_V3_EDGE_PROBE=PASS FAILURES=0
CADDY_ADAPTED_ROUTE_MATRIX=PASS CANONICAL=11 FAIL_CLOSED=28 LEGACY_PROBES=1
```

The one legacy probe is the explicitly transitional unknown-route fallback.
PAS-145 does not claim `UNKNOWN_ROUTE_FALLBACK=0`.

## Strict PAS-145 certification

After PAS-162 repinned the digest-chain authority on exact head
`e29247990a05c6ed1d8c88bfd48a2816dfa90770`, PAS-145 was rerun in strict
mode without the temporary dependency flag.

```text
CADDY_EDGE_API_CERTIFICATION=PASS
API_URL_REGISTRY=PASS
PUBLIC_HOST_REGISTRY=PASS
UPSTREAM_REGISTRY=PASS
WEBHOOK_REGISTRY=PASS
PLATFORM_V1_TO_KONG=PASS
AUTOMATION_V2_TO_KONG=PASS
PRIVATE_NAMESPACE_DENIAL=PASS
DATABASE_PUBLIC_EXPOSURE=0
SPOOFED_IDENTITY_HEADERS_STRIPPED=PASS
PRESERVED_TRANSPORT_HEADERS=PASS
PUBLIC_API_DIRECT_TO_MIDDLEWARE=0
PUBLIC_API_DIRECT_TO_ODOO=0
PUBLIC_API_DIRECT_TO_N8N=0
FAILURE_BYPASS_PATHS=0
POSTMAN_API_CERTIFICATION=PASS
POSTMAN_WEBHOOK_CERTIFICATION=PASS
POSTMAN_PRIVATE_ROUTE_CERTIFICATION=PASS
MIDDLEWARE_KONG_CADDY_DIGEST_CHAIN=PASS
POSTMAN_DIGEST_CHAIN=PASS
UNKNOWN_ROUTE_FALLBACK=TRANSITIONAL
CADDY_LIVE_RELOAD_AUTHORIZED=NO
```

## Deterministic Postman

Repository-owned checker/generator:

`scripts/generate_caddy_edge_certification_postman.py`

The accepted collection bytes remain exactly those pinned by PAS-162. The
source manifest is byte-identical to the generated collection so regeneration
cannot silently change the digest-chain evidence.

Artifacts:

- `postman/Caddy-V3-Edge-Certification.source.json`
- `postman/Caddy-V3-Edge-Certification.postman_collection.json`
- `postman/Caddy-V3-Edge-Certification.postman_environment.json`

Digests:

- source SHA-256:
  `43aa674ba80f80fea3af70da245b03d0c3f04e59e2fe017a4be7d7b12c03a78e`
- collection SHA-256:
  `43aa674ba80f80fea3af70da245b03d0c3f04e59e2fe017a4be7d7b12c03a78e`
- safe-local environment SHA-256:
  `842bf78b5c4cae41ca95d03f15a71bd7ddc2bf3ed6f5976563cb9cbb58cb837e`

Safety defaults:

- `base_url=https://127.0.0.1:9443`
- `RUN_CADDY_EDGE_CERTIFICATION=false`
- token variables empty
- no secret-bearing environment values

Coverage includes positive edge transport, wrong webhook methods, public
private-route/database denial, pending-contract 404s, and the explicitly
transitional unknown-route evidence probe.

## Local gates

```text
FULL_PYTEST=113 passed
SUBTESTS=18 passed
CADDY_REPOSITORY_AUTHORITY=PASS
CADDY_TO_KONG_CONTRACT=PASS
KONG_ROUTE_CONTRACT_BIDIRECTIONAL=PASS
CADDY_KONG_CONTRACT_TESTS=14/14 PASS
CADDY_POSTMAN_GENERATION=PASS
CADDY_V3_EDGE_PROBE=PASS
CADDY_ADAPTED_ROUTE_MATRIX=PASS
STRICT_EDGE_API_CERTIFICATION=PASS
MIDDLEWARE_KONG_CADDY_DIGEST_CHAIN=PASS
POSTMAN_DIGEST_CHAIN=PASS
```

## Remaining integration gate

The PAS-145 implementation and strict source certification are green against
PAS-162 head `e292479…`. PR #175 still requires its independent review before
the canonical successor can merge, and PAS-145's stacked PR must not bypass
that predecessor.

No reload/deployment/production effect is authorized by PAS-145.
