#!/usr/bin/env bash
# Build the Caddy binary from the version authority's source commit, the image
# helpers and the staged /etc/caddy tree that the Dockerfile ships, with a
# binary-build attestation.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
CADDY_SOURCE_SHA="$(python3 "$ROOT/scripts/caddy_version.py" field source.commit)"
CADDY_VERSION="$(python3 "$ROOT/scripts/caddy_version.py" field version)"
rm -rf -- "$BUILD/caddy-source" "$BUILD/etc-caddy"
mkdir -p "$BUILD"
git clone --filter=blob:none https://github.com/caddyserver/caddy.git "$BUILD/caddy-source"
git -C "$BUILD/caddy-source" checkout --detach "$CADDY_SOURCE_SHA"
pushd "$BUILD/caddy-source" >/dev/null
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$BUILD/caddy" ./cmd/caddy
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$BUILD/codestra-http3-probe" "$ROOT/build-tools/http3-probe/main.go"
"$BUILD/caddy" version | tee "$BUILD/caddy-version.txt"
[[ "$(cut -d' ' -f1 "$BUILD/caddy-version.txt")" == "$CADDY_VERSION" ]] || { echo "CADDY_VERSION=FAIL" >&2; exit 1; }
"$BUILD/caddy" list-modules --packages > "$BUILD/caddy-modules.txt"
go version -m "$BUILD/caddy" > "$BUILD/caddy-go-version.txt"
go version -m "$BUILD/codestra-http3-probe" > "$BUILD/http3-probe-go-version.txt"
git diff -- go.mod go.sum > "$BUILD/caddy-module-overrides.patch"
popd >/dev/null
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$BUILD/codestra-set-bind-capability" "$ROOT/build-tools/set-bind-capability/main.go"
python3 "$ROOT/scripts/stage_image_config.py" "$BUILD/etc-caddy" >/dev/null
config_sha256="$(python3 "$ROOT/scripts/hash_config_tree.py" "$BUILD/etc-caddy")"
printf '%s\n' "$config_sha256" > "$BUILD/config-sha256.txt"
jq -n --arg repository 'https://github.com/caddyserver/caddy' --arg version "$CADDY_VERSION" --arg source_sha "$CADDY_SOURCE_SHA" --arg wrapper_sha "${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}" --arg binary_sha256 "$(sha256sum "$BUILD/caddy" | cut -d' ' -f1)" --arg http3_probe_sha256 "$(sha256sum "$BUILD/codestra-http3-probe" | cut -d' ' -f1)" --arg go_mod_sha256 "$(sha256sum "$BUILD/caddy-source/go.mod" | cut -d' ' -f1)" --arg go_sum_sha256 "$(sha256sum "$BUILD/caddy-source/go.sum" | cut -d' ' -f1)" --arg config_sha256 "$config_sha256" '{schema:"codestra.caddy.binary-build.v3",caddy_version:$version,source_repository:$repository,source_sha:$source_sha,wrapper_sha:$wrapper_sha,binary_sha256:$binary_sha256,http3_probe_sha256:$http3_probe_sha256,go_mod_sha256:$go_mod_sha256,go_sum_sha256:$go_sum_sha256,config_sha256:$config_sha256}' > "$BUILD/caddy-binary-build-attestation.json"
printf 'CADDY_RELEASE_INPUTS=PASS\nCADDY_VERSION=%s\nCADDY_UPSTREAM_SHA=%s\nCONFIG_SHA256=%s\nHTTP3_PROBE=BUILT\n' "$CADDY_VERSION" "$CADDY_SOURCE_SHA" "$config_sha256"
