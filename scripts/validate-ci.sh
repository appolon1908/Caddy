#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CADDY_VALIDATOR_IMAGE='docker.io/library/caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c'

cd "$ROOT_DIR"
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

common_args=(
  --rm
  --network none
  --workdir /srv
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
  -v "$docker_root:/srv:ro"
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
python3 -m pytest -q

git diff --check
