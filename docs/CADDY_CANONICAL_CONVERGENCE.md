# Canonical Caddy convergence — 2026-09-27

The integration candidate preserves main `100a9fa28f6f9a17f665daf9baaaf77f6e79ea00` and the exact PR heads below as merge ancestors. Main and other worktrees were left unchanged.

| PR | Preserved SHA | Authority retained |
|---|---|---|
| 190 | f4b4204103bc4595a343d2335f6580364be5d47e | compiler, private control API, candidate identity, activation/readback |
| 191 | 9cd1f673fa9115110514942676bc7c8521a55877 | explicit unknown-route 404, classification, negative probes |
| 192 | 5f5e53d6cec6b11aab905e7f4260d564a061ffca | TLS posture and identity stripping on every proxy |
| 193 | 5e6f39d52dce2e2df46302c686c38b38920fce64 | Kong/Middleware contract and Postman boundary |
| 194 | a1bb59e1112b0fe25f4d48ca7f614d3853505874 | durable file-runtime apply/reload/rollback; includes 190 |

## Reconciled authority

`config/caddy-kong-contract.v1.json` is the executable shared API route registry. Its vendored Middleware operation contract remains pinned. The public and webhook inventories retain classification/certification metadata; they are not alternative runtime registries. `scripts/caddy_route_compiler.py` generates the actual `sites/api.codestra.co.caddy` and its route inventory, used by control API readback. The previous six-route sample is retained only as a test fixture. The Middleware contract import tool delegates to this compiler. Reviewed non-API site ownership is unchanged.

Unknown API paths return 404; the explicitly accepted realtime compatibility paths from PR 191 remain allowlisted. Private routes are denied on every public host. Caddy directive ordering makes that boundary precede site-specific handles, including OpenBao. Header forwarding and TLS protections are preserved. Runtime validation uses the Caddy CLI: `/adapt` alone accepts invalid module configuration and is not a validation gate.

Both activation implementations default to disabled. The control API's apply and rollback operations share a filesystem lock; idempotency checks occur inside it. Source identity rejects dirty authority. Public binding and ambiguous/non-loopback admin URLs are rejected. This branch authorizes no live deployment.

Structured access logs include bounded route labels, upstream, status, duration, request/correlation identity, release SHA and configuration digest. Deployments must provide `CADDY_RELEASE_SHA` and `CADDY_CONFIGURATION_SHA256`; unsealed source validation is explicitly marked `UNSEALED`. Native metrics exist only at the loopback Admin API, with per-host labels disabled. Trace headers remain transport context, not trusted application identity.

## Local certification and release

Run `bash scripts/validate-ci.sh` with Docker, Python/pytest and Newman 6.2.2. It extracts the validator binary from the immutable image, runs adapted-JSON checks, and runs the full native suite. The local HTTP test uses disposable loopback Caddy and a synthetic Kong stand-in: it proves edge routing, WebSocket/SSE transport, header stripping, redaction, private metrics, failure behavior, Postman, and apply/rollback readback. It does not certify real Kong authentication, remote staging, provider effects, or production.

From a clean committed worktree, build an immutable local package:

```
python3 scripts/caddy_release.py build --output /approved/evidence/candidate --rollback-ref <reviewed-commit>
python3 scripts/caddy_release.py verify --output /approved/evidence/candidate --source-sha <exact-candidate-commit>
```

The package binds source, configuration, rollback source, image identity and a source SPDX inventory by digest. Verification rejects dirty sources at build, stale identity, tampered bundles, arbitrary artifact paths and image substitution. A rollback reference is evidence packaging, not authorization to restore it. Protected CI signing/provenance and runtime deployment gates remain mandatory.

## Remaining release gates

The inherited pinned Caddy 2.10.0 image scan reports 6 critical and 75 high vulnerabilities. An exploratory official Caddy 2.11.4 scan reports zero critical and 17 high vulnerabilities; that image was not substituted into the frozen runtime authority. A patched, reviewed image and its full certification are required before release approval. No signing/provider credentials were used and no production or remote staging mutation occurred.

`CODEX_SOURCE_INGESTION = BLOCKED_ARTIFACT_UNAVAILABLE`: object `9fef4777f195e8315bc35bb88dc13f187894cca5` is absent. It was not reconstructed or ingested. If it becomes available, verify its bundle and compare immutable source against this candidate before adding missing semantics.

The convergence coding checkpoint and self-hosted publication are distinct from production readiness. Do not mark the complete mission COMPLETED while the image-security and protected release gates remain unresolved.

## Semantic overlap matrix

| File | PR lanes | Resolution responsibility |
|---|---|---|
| .github/workflows/reusable-codestra-deploy-readiness.yml | 190, 194 | Reconcile all semantics |
| config/caddy-kong-contract.v1.json | 190, 191, 193, 194 | Reconcile all semantics |
| config/caddy-route-authority.v1.json | 190, 194 | Reconcile all semantics |
| config/edge-contract-chain.v1.json | 190, 191, 193, 194 | Reconcile all semantics |
| config/public-edge-registry.v1.json | 190, 191, 194 | Reconcile all semantics |
| config/runtime-values.example | 191 | Preserve lane |
| contracts/mcr-k/edge.v1.json | 193 | Preserve lane |
| contracts/mcr-k/validate.py | 193 | Preserve lane |
| docs/PAS-145_EDGE_API_POSTMAN_CERTIFICATION.md | 191, 193 | Reconcile all semantics |
| docs/caddy-release-seal.md | 194 | Preserve lane |
| docs/mission6-evidence-matrix.md | 194 | Preserve lane |
| docs/mission6-final-caddy-production-certification-release-seal.md | 194 | Preserve lane |
| docs/mission6-production-certification.md | 194 | Preserve lane |
| docs/mission6-release-candidate.md | 194 | Preserve lane |
| generated/pas144-edge.generated.caddy | 190, 194 | Reconcile all semantics |
| generated/pas144-route-inventory.json | 190, 194 | Reconcile all semantics |
| postman/Caddy-V3-Edge-Certification.postman_collection.json | 190, 191, 193, 194 | Reconcile all semantics |
| postman/Caddy-V3-Edge-Certification.source.json | 190, 191, 193, 194 | Reconcile all semantics |
| release/observability/caddy-observability-configuration.sha256 | 190, 191, 192, 194 | Reconcile all semantics |
| release/pas146/caddy-staging-candidate.v1.json | 190, 191, 192, 193, 194 | Reconcile all semantics |
| scripts/caddy_activation.py | 190, 194 | Reconcile all semantics |
| scripts/caddy_adapted_routes.py | 190, 191, 194 | Reconcile all semantics |
| scripts/caddy_candidate.py | 190, 194 | Reconcile all semantics |
| scripts/caddy_control_api.py | 190, 194 | Reconcile all semantics |
| scripts/caddy_execution_store.py | 190, 194 | Reconcile all semantics |
| scripts/caddy_kong_contract.py | 192 | Preserve lane |
| scripts/caddy_readonly_validator.py | 191, 192 | Reconcile all semantics |
| scripts/caddy_route_compiler.py | 190, 194 | Reconcile all semantics |
| scripts/caddy_runtime.py | 194 | Preserve lane |
| scripts/caddy_runtime_readback.py | 190, 194 | Reconcile all semantics |
| scripts/certify_caddy_edge_api.py | 190, 191, 193, 194 | Reconcile all semantics |
| scripts/classify_public_edge.py | 191 | Preserve lane |
| scripts/generate_caddy_edge_certification_postman.py | 191 | Preserve lane |
| scripts/generate_middleware_edge_contract.py | 191 | Preserve lane |
| scripts/test_caddy_kong_contract.py | 190, 191, 192, 194 | Reconcile all semantics |
| scripts/validate-ci.sh | 190, 194 | Reconcile all semantics |
| scripts/validate_caddy_staging_candidate.py | 191 | Preserve lane |
| scripts/validate_observability_exposure.py | 190, 194 | Reconcile all semantics |
| scripts/validate_repository.py | 190, 191, 192, 194 | Reconcile all semantics |
| sites/api.codestra.co.caddy | 190, 191, 192, 194 | Reconcile all semantics |
| sites/automation.codestra.co.caddy | 190, 192, 194 | Reconcile all semantics |
| sites/codestra.media.observability.caddy | 190, 192, 194 | Reconcile all semantics |
| sites/kyyow.com.caddy | 190, 192, 194 | Reconcile all semantics |
| sites/n8n-editor.community.caddy | 190, 192, 194 | Reconcile all semantics |
| snippets/public_boundary.caddy | 190, 194 | Reconcile all semantics |
| snippets/security_headers.caddy | 192 | Preserve lane |
| tests/test_caddy_adapted_routes.py | 190, 191, 194 | Reconcile all semantics |
| tests/test_caddy_edge_api_postman_certification.py | 190, 191, 193, 194 | Reconcile all semantics |
| tests/test_caddy_readonly_validator.py | 192 | Preserve lane |
| tests/test_caddy_runtime.py | 194 | Preserve lane |
| tests/test_caddy_staging_candidate.py | 190, 191, 192, 193, 194 | Reconcile all semantics |
| tests/test_classify_public_edge.py | 191 | Preserve lane |
| tests/test_edge_api_url_webhook_boundaries.py | 190, 191, 194 | Reconcile all semantics |
| tests/test_kyyow_ingress.py | 190, 194 | Reconcile all semantics |
| tests/test_mcr_edge_contract.py | 193 | Preserve lane |
| tests/test_mcr_k_edge_contract.py | 193 | Preserve lane |
| tests/test_mission3_routing_reliability.py | 190, 191, 194 | Reconcile all semantics |
| tests/test_mission6_release_certification.py | 194 | Preserve lane |
| tests/test_pas141_private_boundaries.py | 190, 192, 194 | Reconcile all semantics |
| tests/test_pas144_activation_runtime.py | 190, 194 | Reconcile all semantics |
| tests/test_pas144_candidate_drift.py | 190, 194 | Reconcile all semantics |
| tests/test_pas144_route_compiler_api.py | 190, 194 | Reconcile all semantics |
| tests/test_tls_posture.py | 192 | Preserve lane |
