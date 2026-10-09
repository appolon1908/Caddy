#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
# Every configuration gate runs the version authority's verified release binary
# inside the pinned distroless runtime base, so certification and production
# never disagree about the Caddy version.
CADDY_VALIDATOR_IMAGE="$(python3 scripts/caddy_version.py field runtime_base_image)"
readonly CADDY_VALIDATOR_IMAGE
python3 scripts/caddy_route_compiler.py --check
python3 scripts/test_caddy_kong_contract.py
python3 scripts/validate_repository.py
python3 scripts/validate_community_n8n.py
python3 scripts/test_observability_exposure.py
python3 scripts/validate_observability_exposure.py --check

docker_root_parent="${HOME}/.cache"
mkdir -p "$docker_root_parent"
docker_root="$(mktemp -d "$docker_root_parent/caddy-validator.XXXXXX")"
tar --exclude=.git -cf - . | tar -C "$docker_root" -xf -
caddy_release_bin="$(python3 scripts/caddy_version.py fetch "$docker_root_parent/caddy-release-$(python3 scripts/caddy_version.py field version)/caddy")"
# Disposable certificates for the private mTLS listeners: provisioning
# validation loads every configured certificate and trust pool.
python3 scripts/synthetic_private_pki.py "$docker_root/pki" >/dev/null

common_args=(
  --rm
  --network none
  --user "$(id -u):$(id -g)"
  --workdir /srv
  -e XDG_DATA_HOME=/tmp/data
  -e XDG_CONFIG_HOME=/tmp/config
  -e CADDY_LOG_DIR=/tmp/logs
  -e CADDY_KONG_UPSTREAM=127.0.0.1:8000
  -e CADDY_LEGACY_API_UPSTREAM=127.0.0.1:18101
  -e CADDY_REALTIME_UPSTREAM=127.0.0.1:18102
  -e CADDY_EDITOR_ADMIN_CIDRS=192.0.2.0/24
  -e CADDY_N8N_EDITOR_HOST=n8n-editor.invalid
  -e CADDY_N8N_OAUTH2_PROXY_UPSTREAM=127.0.0.1:4180
  -e CADDY_N8N_EDITOR_MAX_REQUEST_BODY=16777216
  -e CADDY_GRAFANA_UPSTREAM=127.0.0.1:18003
  -e CADDY_SUPERSET_UPSTREAM=127.0.0.1:18088
  -e CADDY_OPENBAO_UPSTREAM=127.0.0.1:18200
  -e 'CADDY_OPENBAO_ALLOWED_CIDRS=192.0.2.0/24 198.51.100.0/24'
  -e CADDY_KYYOW_APP_UPSTREAM=127.0.0.1:18300
  -e CADDY_KYYOW_API_UPSTREAM=127.0.0.1:18301
  -e CADDY_KYYOW_SEARCH_UPSTREAM=127.0.0.1:18302
  -e CADDY_KYYOW_DOCS_UPSTREAM=127.0.0.1:18303
  -e CADDY_KYYOW_AUTH_UPSTREAM=127.0.0.1:18304
  -e CADDY_KYYOW_STATUS_UPSTREAM=127.0.0.1:18305
  -e CADDY_PUBLIC_BIND=127.0.0.1
  -e CADDY_PRIVATE_METRICS_BIND=127.0.0.3
  -e CADDY_PRIVATE_INGRESS_BIND=127.0.0.2
  -e CADDY_KLYROW_SOURCE_CIDRS=192.0.2.4/32
  -e CADDY_VICIDIAL_SOURCE_CIDRS=192.0.2.2/32
  -e CADDY_STAGING_EVENT_SOURCE_CIDRS=198.51.100.7/32
  -e CADDY_KEYCLOAK_UPSTREAM=127.0.0.1:18103
  -e CADDY_CRM_RESELLER_UPSTREAM=127.0.0.1:18104
  -e CADDY_CRM_UPSTREAM=127.0.0.1:18105
  -e CADDY_N8N_UPSTREAM=127.0.0.1:18106
  -e CADDY_N8N_STAGING_UPSTREAM=127.0.0.1:18107
  -e CADDY_STAGING_API_UPSTREAM=127.0.0.1:18108
  -e CADDY_STAGING_PORTAL_UPSTREAM=127.0.0.1:18109
  -e CADDY_STAGING_KEYCLOAK_UPSTREAM=127.0.0.1:18110
  -e CADDY_STAGING_ODOO_UPSTREAM=127.0.0.1:18111
  -e CADDY_MIDDLEWARE_CALLBACK_UPSTREAM=127.0.0.1:18112
  -e CADDY_AGENT_GATEWAY_UPSTREAM=127.0.0.1:18113
  -e CADDY_AGENT_UI_UPSTREAM=127.0.0.1:18114
  -e CADDY_MONITORING_UPSTREAM=127.0.0.1:18115
  -e CADDY_KLYROW_EVENTS_UPSTREAM=127.0.0.1:18180
  -e CADDY_MIDDLEWARE_PKI_DIR=/srv/pki/middleware
  -e CADDY_KLYROW_PKI_DIR=/srv/pki/klyrow
  -v "$docker_root:/srv:ro"
  -v "$caddy_release_bin:/usr/bin/caddy:ro"
)

formatted_file="$(mktemp)"
trap 'rm -f -- "$formatted_file"; rm -rf -- "$docker_root"' EXIT
docker run "${common_args[@]}" "$CADDY_VALIDATOR_IMAGE" \
  caddy fmt /srv/sites/codestra.media.observability.caddy >"$formatted_file"
cmp -s sites/codestra.media.observability.caddy "$formatted_file" || {
  printf 'CADDY_FORMAT_ERROR=sites/codestra.media.observability.caddy\n' >&2
  diff -u sites/codestra.media.observability.caddy "$formatted_file" >&2 || true
  exit 1
}

python3 scripts/validate_kyyow_ingress.py
python3 -m unittest discover -s tests -p 'test_kyyow_ingress.py' -v

adapted_file="$(mktemp)"
trap 'rm -f -- "$formatted_file" "$adapted_file"; rm -rf -- "$docker_root"' EXIT
docker run "${common_args[@]}" "$CADDY_VALIDATOR_IMAGE" \
  caddy adapt --config /srv/Caddyfile --adapter caddyfile --validate --pretty >"$adapted_file"
docker run "${common_args[@]}" "$CADDY_VALIDATOR_IMAGE" \
  caddy validate --config /srv/Caddyfile --adapter caddyfile

# Resolve the canonical Middleware edge matrix through the adapted config that
# Caddy itself produced: exact method+path rules reach Kong, wrong methods and
# retired aliases never reach the legacy upstream, and the fallback stays last.
python3 scripts/caddy_adapted_routes.py "$adapted_file" \
  --kong-upstream 127.0.0.1:8000 \
  --legacy-upstream 127.0.0.1:18101
# Certify native HTTP, admin readback, Postman and the release rehearsal
# against this exact verified binary.
export CADDY_BIN="$caddy_release_bin"
export CADDY_RELEASE_BIN="$caddy_release_bin"
export CADDY_ADAPTED_JSON="$adapted_file"
export CADDY_MIDDLEWARE_PKI_DIR="$docker_root/pki/middleware"
export CADDY_KLYROW_PKI_DIR="$docker_root/pki/klyrow"
export CADDY_LOG_DIR="$docker_root/logs"
export XDG_DATA_HOME="$docker_root/data"
export XDG_CONFIG_HOME="$docker_root/config"
export PATH="$docker_root:$PATH"
mkdir -p "$CADDY_LOG_DIR"
python3 -m pytest -q

git diff --check
