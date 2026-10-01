#!/usr/bin/env bash
# Bounded, zero-public-traffic production canary for the immutable Caddy container.
#
# It never starts, stops or reconfigures the live container and sends only
# GET/HEAD requests and TLS handshakes. It proves, in order:
#   1. the live container passes the fixed read-only validator (snapshot before);
#   2. the expected signed image carries the expected source, configuration and
#      non-root identity, and its embedded /etc/caddy hashes to that identity;
#   3. the expected image's configuration validates offline (no network);
#   4. live edge behaviour: Kong handoff, HTTPS redirect and HSTS, realtime,
#      unknown-route 404, Keycloak discovery, HTTP/2, HTTP/3, certificate
#      lifetime, WebSocket upgrade, editor and OpenBao denial, mTLS private
#      ingress, private-surface denial and Grafana health;
#   5. the live runtime is byte-identical afterwards (snapshot after).
# Modes: pre-activation (certify the live runtime before a candidate goes
# live), post-activation and rollback (the live runtime must be the expected tuple).
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VALIDATOR="$ROOT/scripts/caddy_readonly_validator.py"
readonly STAGE_CONFIG="$ROOT/scripts/stage_image_config.py"
readonly HASH_CONFIG="$ROOT/scripts/hash_config_tree.py"
readonly WEBSOCKET_PROBE="$ROOT/scripts/websocket_probe.py"
readonly DOCKER=/usr/bin/docker
readonly PYTHON=/usr/bin/python3
readonly CURL=/usr/bin/curl
readonly OPENSSL=/usr/bin/openssl
# Kong must reject this deliberately invalid bearer; nothing here is a credential.
readonly AUTH_HEADER_NAME=Authorization
readonly AUTH_SCHEME=Bearer
readonly IMAGE="${CADDY_CANARY_IMAGE:-}"
readonly SOURCE_SHA="${CADDY_CANARY_SOURCE_SHA:-}"
readonly CONFIG_SHA256="${CADDY_CANARY_CONFIG_SHA256:-}"
readonly ENV_FILE="${CADDY_CANARY_ENV_FILE:-}"
readonly MTLS_CLIENT_CERT="${CADDY_CANARY_MTLS_CLIENT_CERT:-}"
readonly MTLS_CLIENT_KEY="${CADDY_CANARY_MTLS_CLIENT_KEY:-}"
readonly MTLS_CA_CERT="${CADDY_CANARY_MTLS_CA_CERT:-}"
readonly MODE="${CADDY_PRODUCTION_CANARY_MODE:-pre-activation}"
readonly PRIVATE_MOUNTS=(/etc/caddy/private/klyrow-events /etc/codestra/pki/middleware-private-ingress)

fail() {
  printf 'CADDY_PRODUCTION_READONLY_CANARY=FAIL:%s\n' "$1" >&2
  exit 2
}

[[ $# -eq 0 ]] || fail arguments_not_allowed
case "$MODE" in
  pre-activation|post-activation|rollback) ;;
  *) fail invalid_canary_mode ;;
esac
[[ "$IMAGE" =~ ^ghcr\.io/appolon1908-hue/codestra-caddy@sha256:[0-9a-f]{64}$ ]] || fail invalid_image
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail invalid_source_sha
[[ "$CONFIG_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail invalid_config_sha256
# System binaries may be distribution symlinks (Ubuntu's python3 -> python3.12);
# what runs must resolve to a root-owned file nobody else can write.
for path in "$DOCKER" "$PYTHON" "$CURL" "$OPENSSL"; do
  resolved="$(readlink -f -- "$path")" || fail "trusted_binary:${path##*/}"
  [[ -f "$resolved" ]] || fail "trusted_binary:${path##*/}"
  read -r owner mode < <(stat -c '%u %a' -- "$resolved")
  [[ "$owner" == 0 && $(( 8#$mode & 8#022 )) -eq 0 ]] || fail "trusted_binary:${path##*/}"
done
for path in "$VALIDATOR" "$STAGE_CONFIG" "$HASH_CONFIG" "$WEBSOCKET_PROBE"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "trusted_path:${path##*/}"
done
for path in "$ENV_FILE" "$MTLS_CLIENT_CERT" "$MTLS_CLIENT_KEY" "$MTLS_CA_CERT"; do
  [[ "$path" = /* && "$path" != *..* && "$path" != *//* ]] || fail "unsafe_path:${path##*/}"
  [[ -f "$path" && ! -L "$path" && -r "$path" ]] || fail "invalid_file:${path##*/}"
done

root_prefix=()
if "$DOCKER" info >/dev/null 2>&1; then
  :
elif command -v sudo >/dev/null 2>&1 && sudo -n "$DOCKER" info >/dev/null 2>&1; then
  root_prefix=(sudo -n)
else
  fail docker_access
fi
docker_cmd() { "${root_prefix[@]}" "$DOCKER" "$@"; }
run_validator() { "${root_prefix[@]}" "$PYTHON" "$VALIDATOR" >"$1" || fail live_validation; }

work="$(mktemp -d)"
image_probe=""
cleanup() {
  [[ -z "$image_probe" ]] || docker_cmd rm -f "$image_probe" >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT

run_validator "$work/pre.json"
"$PYTHON" - "$work/pre.json" "$MODE" "$SOURCE_SHA" "${IMAGE##*@}" "$CONFIG_SHA256" <<'PY' || fail live_identity
import json
import sys

path, mode, source_sha, digest, config_sha256 = sys.argv[1:]
live = json.load(open(path, encoding="utf-8"))
assert live["schema"] == "codestra.caddy-readonly-validation.v2"
assert live["container_health"] == "healthy"
assert live["config_identity"] == "PASS" and live["config_validation"] == "PASS"
assert live["served_config_matches_image"] is True and live["credential_redaction"] == "PASS"
if mode != "pre-activation":
    assert (live["source_sha"], live["image_digest"], live["config_sha256"]) == (source_sha, digest, config_sha256)
PY

# The expected image must exist locally by digest; the canary never pulls.
label() { docker_cmd image inspect "$IMAGE" --format "{{index .Config.Labels \"$1\"}}"; }
case "$(label org.opencontainers.image.source)" in
  https://github.com/appolon1908-hue/Caddy|https://github.com/appolon1908/Caddy) ;;
  *) fail candidate_source ;;
esac
[[ "$(label org.opencontainers.image.revision)" == "$SOURCE_SHA" ]] || fail candidate_revision
[[ "$(label io.codestra.caddy.config.sha256)" == "$CONFIG_SHA256" ]] || fail candidate_config_label
[[ "$(docker_cmd image inspect "$IMAGE" --format '{{.Config.User}}')" == 65532:65532 ]] || fail candidate_user

mkdir -p "$work/image-config"
image_probe="$(docker_cmd create "$IMAGE")"
docker_cmd cp "$image_probe:/etc/caddy/." "$work/image-config"
docker_cmd rm -f "$image_probe" >/dev/null
image_probe=""
image_config_sha256="$("$PYTHON" "$HASH_CONFIG" "$work/image-config")"
[[ "$image_config_sha256" == "$CONFIG_SHA256" ]] || fail image_config_identity
# The protected checkout stays on the candidate during rollback, so only the
# forward modes also bind the checkout to the expected configuration.
if [[ "$MODE" != rollback ]]; then
  [[ "$("$PYTHON" "$STAGE_CONFIG" --digest)" == "$CONFIG_SHA256" ]] || fail source_config_identity
fi

offline=(run --rm --network none --read-only --user 65532:65532 --env-file "$ENV_FILE"
         --env XDG_DATA_HOME=/data --env XDG_CONFIG_HOME=/config)
for path in /data /config /run/caddy /var/log/caddy /tmp; do
  offline+=(--tmpfs "$path:uid=65532,gid=65532,mode=0700")
done
for path in "${PRIVATE_MOUNTS[@]}"; do
  offline+=(--mount "type=bind,src=$path,dst=$path,readonly")
done
docker_cmd "${offline[@]}" --entrypoint /usr/bin/caddy "$IMAGE" \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null || fail candidate_offline_validation

readarray -t binds < <("$PYTHON" - "$(docker_cmd inspect codestra-caddy --format '{{json .Config.Env}}')" <<'PY'
import json
import sys

values = dict(entry.split("=", 1) for entry in json.loads(sys.argv[1]) if "=" in entry)
for name in ("CADDY_PUBLIC_BIND", "CADDY_PRIVATE_INGRESS_BIND"):
    print(values.get(name, ""))
PY
)
[[ ${#binds[@]} -eq 2 && -n "${binds[0]}" && -n "${binds[1]}" ]] || fail live_bind_contract
public_bind="${binds[0]}"
private_bind="${binds[1]}"

status_of() { "$CURL" --noproxy '*' --silent --show-error --max-time 15 --output /dev/null --write-out '%{http_code}' "$@" || true; }
https_get() { status_of --resolve "$1:443:${public_bind}" "https://$1$2" "${@:3}"; }

api_status="$("$CURL" --noproxy '*' --silent --show-error --max-time 15 --dump-header "$work/api.headers" \
  --output /dev/null --write-out '%{http_code}' --resolve "api.codestra.co:443:${public_bind}" \
  -H "${AUTH_HEADER_NAME}: ${AUTH_SCHEME} bounded-production-canary-invalid" https://api.codestra.co/api/v1/health)"
case "$api_status" in 200|204|401|403) ;; *) fail "live_kong_status:${api_status}" ;; esac
grep -Eqi '^strict-transport-security: max-age=31536000' "$work/api.headers" || fail live_hsts
redirect_status="$(status_of --resolve "api.codestra.co:80:${public_bind}" http://api.codestra.co/api/v1/health)"
[[ "$redirect_status" =~ ^30(1|7|8)$ ]] || fail "live_redirect:${redirect_status}"
version_status="$(https_get api.codestra.co /version)"
[[ "$version_status" == 200 ]] || fail "live_realtime_status:${version_status}"
for path in /not-a-contracted-route /metrics '/metrics;x' /internal/v1/database/health; do
  denied="$(https_get api.codestra.co "$path")"
  [[ "$denied" == 404 ]] || fail "live_private_or_unknown:${path}:${denied}"
done

"$CURL" --noproxy '*' --silent --show-error --max-time 15 --output "$work/keycloak.json" \
  --resolve "auth.codestra.co:443:${public_bind}" \
  https://auth.codestra.co/realms/codestra/.well-known/openid-configuration || fail live_keycloak
"$PYTHON" -c 'import json,sys; assert json.load(open(sys.argv[1]))["issuer"] == "https://auth.codestra.co/realms/codestra"' \
  "$work/keycloak.json" || fail live_keycloak_issuer

# Capture each probe before checking it: an early-exiting reader would send the
# writer SIGPIPE and, under pipefail, fail a healthy edge at random.
"$OPENSSL" s_client -connect "${public_bind}:443" -servername api.codestra.co -alpn h2 </dev/null \
  >"$work/alpn.txt" 2>/dev/null || true
grep -q 'ALPN protocol: h2' "$work/alpn.txt" || fail live_http2
"$OPENSSL" s_client -connect "${public_bind}:443" -servername api.codestra.co </dev/null \
  >"$work/tls.txt" 2>/dev/null || true
"$OPENSSL" x509 -in "$work/tls.txt" -noout -checkend 604800 >/dev/null || fail live_certificate_expiry
docker_cmd exec codestra-caddy /usr/bin/codestra-http3-probe api.codestra.co "$public_bind" /version \
  >"$work/http3.txt" || fail live_http3
grep -q 'CADDY_HTTP3_CANARY=PASS' "$work/http3.txt" || fail live_http3
"$PYTHON" "$WEBSOCKET_PROBE" api.codestra.co "$public_bind" /ws/agent >/dev/null || fail live_websocket

# A loopback alias outside every allowlist proves the source gates deny.
editor_status="$(status_of --interface 127.0.0.3 --resolve "automation.codestra.co:443:${public_bind}" https://automation.codestra.co/)"
[[ "$editor_status" == 404 ]] || fail "live_editor_denial:${editor_status}"
bao_status="$(status_of --interface 127.0.0.3 --resolve "bao.codestra.media:443:${public_bind}" https://bao.codestra.media/)"
[[ "$bao_status" == 403 ]] || fail "live_openbao_denial:${bao_status}"

# Private ingress: no client certificate fails the handshake; the reviewed
# client identity reaches only the route-level 403 for an uncontracted path.
klyrow=(--cacert "$MTLS_CA_CERT" --resolve "middleware-email-events.internal.codestra.agency:18080:${private_bind}"
        https://middleware-email-events.internal.codestra.agency:18080/not-contracted)
without_cert="$(status_of "${klyrow[@]}")"
[[ "$without_cert" == 000 || "$without_cert" == 400 ]] || fail "live_mtls_without_cert:${without_cert}"
with_cert="$(status_of --cert "$MTLS_CLIENT_CERT" --key "$MTLS_CLIENT_KEY" "${klyrow[@]}")"
[[ "$with_cert" == 403 ]] || fail "live_mtls_denial:${with_cert}"

grafana_status="$(https_get graf.codestra.media /api/health)"
[[ "$grafana_status" == 200 ]] || fail "live_grafana_status:${grafana_status}"

run_validator "$work/post.json"
cmp -s "$work/pre.json" "$work/post.json" || fail live_runtime_changed
cp "$work/post.json" production-canary-runtime.json

"$PYTHON" - "$work/post.json" "$MODE" "$IMAGE" "$SOURCE_SHA" "$CONFIG_SHA256" "$api_status" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

path, mode, image, source_sha, config_sha256, api_status = sys.argv[1:]
live = json.loads(Path(path).read_text(encoding="utf-8"))
evidence = {
    "schema": "codestra.caddy.production-readonly-canary.v3",
    "canary_mode": mode,
    "expected_image": image,
    "expected_source_sha": source_sha,
    "expected_config_sha256": config_sha256,
    "candidate_offline_validation": "PASS",
    "live_source_sha": live["source_sha"],
    "live_image_digest": live["image_digest"],
    "live_config_sha256": live["config_sha256"],
    "live_runtime_is_expected_tuple": mode != "pre-activation",
    "live_runtime_unchanged": True,
    "live_runtime_snapshot_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
    "live_kong_readonly_status": int(api_status),
    "live_edge_probes": "PASS",
    "write_requests_sent": False,
    "public_traffic_changed": False,
    "result": "PASS",
}
Path("production-canary-evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf '%s\n' \
  'CADDY_PRODUCTION_READONLY_CANARY=PASS' \
  "CADDY_PRODUCTION_CANARY_MODE=$MODE" \
  "CANDIDATE_IMAGE=$IMAGE" \
  "CANDIDATE_SOURCE_SHA=$SOURCE_SHA" \
  "CANDIDATE_CONFIG_SHA256=$CONFIG_SHA256" \
  'WRITE_REQUESTS_SENT=false' \
  'PUBLIC_TRAFFIC_CHANGED=false'
