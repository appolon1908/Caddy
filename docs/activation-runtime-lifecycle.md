# Activation runtime lifecycle

## Safety contract

The JSON control API and file runtime share `RuntimeCoordinator`: a nonblocking
process lock, accepted startup JSON, and durable execution ledger. Set
`CADDY_CONTROL_STATE_DIR` to the same absolute directory for both engines and the
restart launcher. Use one private directory per Caddy instance, owned by the
runtime service account. All cooperating controllers must run under that account
with the same directory. This coordinates local processes, not distributed nodes
or direct administrative changes made outside these engines.

Runtime mutation remains disabled by default. This change does not authorize any
production operation or broaden the control API/admin listener beyond loopback.

## Health and activation

Supply one or more meaningful functional readiness URLs in the space-separated
`CADDY_ACTIVATION_HEALTH_URLS` variable, or explicitly pass `health_urls` to a
runtime constructor. A probe must return HTTP 200; redirects, login challenges,
errors, and unreachable dependencies fail. Choose paths that exercise required
upstreams rather than the control service's process-only `/health` endpoint.
No probe configuration means activation fails closed.

Both engines validate the candidate, read the pre-state, check baseline health,
and compare it with the accepted restart state before any load. JSON apply accepts
`expected_active_digest`; the control apply endpoint accepts it through `If-Match`.
The file engine retains `expected_active_digest`. Callers should provide the exact
active SHA-256 from their approved plan. Retries of a completed idempotency key
return its original receipt without loading again; a different candidate, source,
or engine cannot reuse the same key. Failed and interrupted keys remain failures.

After loading, activation checks exact runtime readback and functional health
before atomically accepting restart JSON and recording completion. A failure
restores the exact captured runtime JSON, checks readback and health, and records
whether recovery succeeded. This restoration does not depend on a prior source
file or re-expanding environment variables.

Dry-run validates source and metadata and provisions the configuration validator;
it never loads a runtime configuration. It can contact the private admin adapt
endpoint, so "no runtime mutation" does not mean "no POST requests".

## Durable restart authority

`$CADDY_CONTROL_STATE_DIR/active.json` is the runtime startup authority. It is
written through a private temporary file, file fsync, atomic replacement, and
parent-directory fsync. The first activation saves the healthy baseline before
loading. Later accepted activations and successful rollback update this file.
Do not configure the supervisor to restart from the repository Caddyfile, a
mutable backup, or implicit Caddy autosave after adopting this lifecycle.

Configure the service supervisor to run the supported launcher:

```sh
python3 /workspace/Caddy/scripts/caddy_restart.py \
  --caddy-bin /absolute/path/to/approved/caddy \
  --admin-api http://127.0.0.1:2019 \
  --health-url http://127.0.0.1:YOUR_EDGE_PORT/your-functional-readiness-path
```

The hostname, port and path above are deployment choices, not values to copy into
production. A supervisor must set the shared state directory and required XDG
storage locations, and preserve them across restart. Public certificate data and
ACME storage remain private persistent volumes separate from execution evidence.
The launcher does not bootstrap an absent accepted config. Start the explicitly
reviewed baseline once through the existing deployment procedure; the first
health-checked activation creates its restart checkpoint. For an already-running
Caddy listener, stop that process through its supervisor before invoking the
launcher. The launcher refuses to run over an existing admin listener.

On restart the launcher validates accepted JSON, starts Caddy from that exact
file, compares live configuration, and checks functional health while holding the
shared mutation lock. It releases the lock only when ready, writes a private
`startup.json` readiness record, forwards termination signals to its Caddy child,
and supervises that child. The readiness record includes supervisor/child PIDs
and config digest; it is historical evidence, so consumers must also verify the
process and live readiness rather than trusting a stale file.

Local tests certify this flow with `persist_config off`, proving that it does not
rely on autosave. No production systemd service was installed by this change.

## Interrupted operations and drift

Before a runtime mutation, either engine writes a durable RUNNING receipt. JSON
manual rollback also writes its own distinct intent receipt before loading.
Every new mutation checks the shared ledger. Any unresolved RUNNING receipt
blocks further apply/rollback, including commands with a different key or engine.
An external configuration change cannot silently replace the accepted restart
checkpoint: a baseline mismatch fails closed.

To recover after a controller crash, stop Caddy using its supervisor and restart
through the launcher. Once accepted configuration readback and health pass, the
launcher marks interrupted receipts FAILED with
`INTERRUPTED_RESTART_RESTORED`. Recovery restores the last accepted checkpoint;
it does not assume that an interrupted candidate or rollback was approved.
An interrupted rollback may therefore restart into the previously accepted
candidate. Inspect the receipt and deliberately request a new rollback after
recovery if that remains the desired operation. Never delete a RUNNING record
merely to clear the fence.

## Rollback and source-file compatibility

Prefer `file_runtime.rollback(execution_id=..., expected_active_digest=...)`.
If no execution ID is supplied, the file engine resolves its latest retained
successful apply and still requires the live digest to match that execution's
result. A later JSON activation prevents an old file rollback from overwriting
it. The mutable `last-known-good.caddy` file no longer authorizes manual rollback.
A backup without a retained successful execution requires a separately reviewed
migration; it is rejected by the new rollback path.

Recovery and named rollback restore JSON as the accepted runtime state. A file
engine's source file is a compatibility artifact and can differ after JSON
rollback; it is not startup authority. Operators should use runtime readback and
the accepted JSON, and regenerate reviewed source through the normal development
workflow instead of inferring active state from that file.

## Audit and idempotency retention

The shared ledger is `$CADDY_CONTROL_STATE_DIR/executions`. Mutating, idempotent,
and recovery receipts are retained indefinitely, including exact pre-state for
rollback. `ExecutionStore.max_records` now bounds only disposable observations
and dry-run plans. Those records cannot evict mutation/retry/rollback evidence.
The legacy evidence directory remains a compatibility mirror; the shared ledger
is authoritative for mutation retries, execution readback, and crash recovery.

JSON and file engines use the same receipt envelope in the shared ledger, with an
engine discriminator. A RUNNING/failed key never returns a success response.
Corrupt audit data fails closed. Files are written atomically and private; their
runtime config snapshots may contain sensitive module configuration. Do not
publish these records or treat them as sanitized telemetry.

Back up this entire directory together with persistent Caddy state. Monitor disk
space. There is no automatic deletion of mutation records; any future archival
policy must preserve retry indexes and rollback checkpoints before deleting
receipts. Local file locks and fsync require a filesystem that supports them.

## Validation

Run `bash scripts/validate-ci.sh` with the pinned CI tools. New tests include
functional health rejection, automatic/manual rollback, stale state rejection,
retention churn, shared keys and locks, restart with autosave disabled, and real
controller SIGKILL during apply and rollback for both engines. Each killed
controller must fence new commands until checked restart recovery.

These are local development/runtime lifecycle checks. They do not establish
production deployment, Codestra integration, external certificate renewal,
distributed coordination, or live monitoring readiness.
