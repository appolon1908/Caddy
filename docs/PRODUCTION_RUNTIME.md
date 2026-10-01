# Production runtime

## Canonical mode

Production runs one immutable, signed, non-root Caddy image as the container
`codestra-caddy` on the host network, started from `deploy/compose.runtime.yaml`.
This is the topology the production lineage deployed and validated
(`caddy-production-2489bf0`; the 2026-09-03 reconciliation replaced the separate
systemd service with the container). There is no host-installed Caddy service.

| Concern | Location |
| --- | --- |
| Image | `ghcr.io/appolon1908-hue/codestra-caddy@sha256:<digest>` (digest only, never a tag) |
| Configuration | `/etc/caddy` inside the image: `Caddyfile`, `snippets/`, `sites/` exactly as staged by `scripts/stage_image_config.py` |
| Configuration identity | `scripts/hash_config_tree.py` over that tree; carried by the image label and the Compose label `io.codestra.caddy.config.sha256` |
| Certificates and ACME account | `/data`, bound from `/var/lib/codestra/caddy/data`; persists across releases and rollbacks |
| Private mTLS material | read-only host binds `/etc/caddy/private/klyrow-events` and `/etc/codestra/pki/middleware-private-ingress` |
| Admin API | `unix//run/caddy/admin.sock`, the host's `/run/caddy` bound at the same path; provisioned by `deploy/tmpfiles.d/codestra-caddy.conf` |
| Metrics | private `:2020` listener on `CADDY_PRIVATE_METRICS_BIND` |
| Runtime values | the protected environment file; every value the tree reads is required by Compose |

## Build

`scripts/build-release-inputs.sh` builds the patched Caddy binary, the HTTP/3
probe and the bind-capability helper, stages `/etc/caddy`, and records the binary
build attestation. The `Dockerfile` ships those inputs only. Signing, provenance
and publication run in the protected production release workflow.

## Release and rollback

`scripts/caddy_container_release.py` is the controlled reload. It records the
running release, validates the candidate image offline (no network, read-only,
non-root, real runtime values and private mounts), switches the Compose digest,
and waits for a healthy container. Any failure after the switch restores the
recorded release; a failed restore is reported as `ROLLBACK_FAILED`. Without
`--apply` it only plans. It never pulls, builds or prunes, so the previous image
remains available. `config/release-baseline.v1.json` records the immutable
historical rollback baseline.

`scripts/caddy_readonly_validator.py` proves the running container afterwards:
image identity and labels, non-root user, configuration identity, effective
redaction and transport policy, served configuration equal to the image, and
listener ownership.

The admin-API activation in `scripts/caddy_control_api.py` stays disabled by
default; it does not replace image releases.

## Open items

- `.github/workflows/production-readonly-canary-v2.yml` still calls
  `scripts/run_production_readonly_canary.sh`, which exists on neither lineage.
  Its zero-public-traffic loopback canary must be restored before that workflow
  can pass.
- Image namespace: signed images live under `appolon1908-hue`; moving them is a
  separate decision from the source repository transfer.
