# Mission 6 Release Candidate

## Candidate identity

| Field | Value |
| --- | --- |
| Remote | `https://github.com/ingtrader21-spec/Caddy.git` |
| Branch | `feature/caddy-integration-route-hardening` |
| Git SHA | `1f72905471645d490e7bd4ddf20a11d846df1446` |
| Working tree | DIRTY, all entries classified below |
| Configuration SHA-256 | `e75e85f529ee1b8c0aa31441ccdfb5c3f0e31245d0681006be6dad0bcdc21196` |
| Caddy image | `docker.io/library/caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c` |
| Dockerfile | NOT PRESENT; no hash claimed |
| Caddy Compose | NOT PRESENT; no hash claimed |
| Candidate timestamp | 2026-09-18 UTC session capture |

## Hash inventory

| Artifact | SHA-256 |
| --- | --- |
| `Caddyfile` | `7294ada05050e0c2483641126b6343aaf0e91ef226f64db06208154f7dcb3a8c` |
| `config/runtime-values.example` | `5a8693082b9673524837dab863dde6745fac957df1afa25d291dbbf41c369ea2` |
| `docs/domain-registry-v1.md` | `8cbc28a865b560d65f3ba690a4309f79e7ab2a8ed9a178401aaf7dfb2830d725` |
| `docs/upstream-registry-v1.md` | `f3b1e9bdf5cd20976ea216724fa0892ac9a4c54a7b6c0966b366415429d47dbf` |
| `scripts/validate_repository.py` | `481e61a756c1400479bb50e6f54879a038ff2ea23fa19af47d677b030bae915` |
| `scripts/config_digest.py` | `3d4cc7c8cfd01b10a1a4998d524a51f69ccc7525c9a5fcff24b52ddc5749ba84` |
| `deploy/community-n8n/compose.security.yaml` | `6f7636dc4bf0e5b8118935ea9ccb142a5cba354c1662d143ebc14c18b937a078` |

## Working-tree classification

### INTENDED M1-M5

All modified and untracked Mission 1 through Mission 5 source, contract, validator, test, and evidence files reported by `git status --short`, including:

- modified Caddy site files and `scripts/validate-ci.sh`
- modified `scripts/validate_repository.py`
- Mission 1-5 documentation under `docs/`
- `scripts/config_digest.py` and `scripts/mission5_desired_state.py`
- Mission 3, Mission 4, and Mission 5 focused tests

### EVIDENCE

No separate evidence-only working-tree files were present at capture time.

### TEMPORARY

No temporary tracked or untracked candidate files were present at capture time. `.pytest_cache/` is ignored tooling state and is not part of the candidate.

### UNRELATED

None identified.

### UNKNOWN

None. An unknown working-tree entry would block certification.

## Source evidence

- Repository validator: PASS
- Full repository suite: 88 passed after M6 certification tests
- Deterministic configuration digest: matches the M5 frozen identity
- Pinned Caddy image: adapt and validate PASS
- Caddy native binary: not installed on the Windows host

## Certification disposition

This is a frozen source candidate, not a production deployment authorization. Linux runtime TLS, routing, upstream failure, readback, drift, reload/rollback, restart, and synthetic log-leakage evidence remain required before a production GO.
