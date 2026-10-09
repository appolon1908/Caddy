# Immutable Codestra Caddy edge image. Inputs come from scripts/build-release-inputs.sh:
# the patched binary, the helpers, and build/etc-caddy (the exact deployable tree).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
ARG BUILD_CREATED
ARG SOURCE_URL
ARG VCS_REF
ARG VERSION
ARG CONFIG_SHA256
ARG CADDY_UPSTREAM_SHA
LABEL org.opencontainers.image.created="$BUILD_CREATED" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.title="Codestra Caddy Edge" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot" \
      io.codestra.caddy.config.sha256="$CONFIG_SHA256" \
      io.codestra.caddy.upstream.sha="$CADDY_UPSTREAM_SHA"
COPY --chown=65532:65532 build/caddy /usr/bin/caddy
COPY --chown=65532:65532 build/codestra-http3-probe /usr/bin/codestra-http3-probe
COPY --chown=0:0 build/codestra-set-bind-capability /usr/bin/codestra-set-bind-capability
USER 0:0
RUN ["/usr/bin/codestra-set-bind-capability"]
COPY --chown=65532:65532 build/etc-caddy/ /etc/caddy/
COPY --chown=65532:65532 deploy/runtime-mountpoints/klyrow-events/ /etc/caddy/private/klyrow-events/
COPY --chown=65532:65532 deploy/runtime-mountpoints/middleware-private-ingress/ /etc/codestra/pki/middleware-private-ingress/
USER 65532:65532
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
