#!/usr/bin/env python3
"""Fixed-target, read-only validation of the production Caddy container.

Production runs one immutable, signed, non-root image as container
`codestra-caddy` on the host network (deploy/compose.runtime.yaml). This program
accepts no arguments, never mutates the runtime and never emits raw Caddy
configuration. Installation and sudo/forced-command wiring are deliberately
outside this source change and require the protected deployment authority.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

CONTAINER = "codestra-caddy"
DOCKER = "/usr/bin/docker"
CURL = "/usr/bin/curl"
SS = "/usr/bin/ss"
CONTAINER_CADDYFILE = "/etc/caddy/Caddyfile"
EXPECTED_IMAGE_REPOSITORY = "ghcr.io/appolon1908-hue/codestra-caddy"
# The repository was transferred; signed images carry either canonical name.
SOURCE_REPOSITORIES = {"https://github.com/appolon1908-hue/Caddy", "https://github.com/appolon1908/Caddy"}
SOURCE_LABEL = "io.codestra.caddy.source.sha"
DIGEST_LABEL = "io.codestra.caddy.image.digest"
CONFIG_LABEL = "io.codestra.caddy.config.sha256"
RELEASE_LABEL = "io.codestra.caddy.release.id"
RUNTIME_USER = "65532:65532"
REQUIRED_MODULES = {"http.handlers.reverse_proxy", "http.handlers.headers", "http.handlers.metrics", "tls"}
IP_VARIABLES = {"CADDY_PUBLIC_BIND", "CADDY_PRIVATE_METRICS_BIND", "CADDY_PRIVATE_INGRESS_BIND"}
# Fixed admin socket, bind-mounted from the host at the same path; this program
# stays stdlib-only and installs standalone.
ADMIN_SOCKET = "/run/caddy/admin.sock"
ADMIN_ADDRESS = f"unix/{ADMIN_SOCKET}"
SAFE_DIAL = re.compile(r"^(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$")
REQUIRED_REDACTIONS = (
    "request>headers>Authorization delete",
    "request>headers>Apikey delete",
    "request>headers>X-Api-Key delete",
    "delete apikey",
)
# Minimum set that must always be present. Every other `{$NAME}` placeholder
# referenced by the canonical source is required too: Caddy adapts an unset
# placeholder to an empty value, so a missing upstream variable still passes
# `caddy validate` while leaving a reverse_proxy with no upstream at all.
RUNTIME_VARIABLES = {
    "CADDY_KONG_UPSTREAM",
    "CADDY_REALTIME_UPSTREAM",
    "CADDY_EDITOR_ADMIN_CIDRS",
    "CADDY_N8N_EDITOR_HOST",
    "CADDY_N8N_OAUTH2_PROXY_UPSTREAM",
    "CADDY_N8N_EDITOR_MAX_REQUEST_BODY",
    # Listener ownership is checked on every bind address.
    "CADDY_PUBLIC_BIND",
    "CADDY_PRIVATE_METRICS_BIND",
    "CADDY_PRIVATE_INGRESS_BIND",
}
PLACEHOLDER = re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)(:[^}]*)?\}")


class ValidationError(RuntimeError):
    pass


def run_fixed(command: list[str], environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", **(environment or {})},
    )
    if result.returncode != 0:
        raise ValidationError(f"fixed command failed: {Path(command[0]).name}")
    return result.stdout


def config_tree_hash(root: Path) -> str:
    """Same digest as scripts/hash_config_tree.py over the shipped /etc/caddy tree."""
    digest = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == "private":
            continue
        if path.is_symlink():
            raise ValidationError("container configuration contains a symbolic link")
        if not path.is_file():
            continue
        payload = path.read_bytes()
        name = relative.as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        count += 1
    if count == 0:
        raise ValidationError("container configuration tree is empty")
    return digest.hexdigest()


def canonical_source(root: Path) -> tuple[str, str]:
    paths = [root / "Caddyfile"]
    for pattern in ("sites/*.caddy", "snippets/*.caddy"):
        paths.extend(sorted(root.glob(pattern)))
    if any(not path.is_file() for path in paths):
        raise ValidationError("canonical Caddy source is incomplete")
    payload = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    return payload, config_tree_hash(root)


def require_redaction(source: str) -> None:
    missing = [token for token in REQUIRED_REDACTIONS if token not in source]
    if missing:
        raise ValidationError("credential redaction policy is incomplete")


def required_runtime_variables(source: str) -> set[str]:
    """Return every variable the source needs: the fixed floor plus each
    `{$NAME}` placeholder that has no `{$NAME:default}` fallback."""
    referenced = {name for name, default in PLACEHOLDER.findall(source) if not default}
    return RUNTIME_VARIABLES | referenced


def runtime_environment(entries: list[str], required: set[str]) -> dict[str, str]:
    """Select and validate the container's runtime values without echoing them."""
    selected = {name: value for name, _, value in (entry.partition("=") for entry in entries) if name in required}
    if set(selected) != required or any(not value for value in selected.values()):
        raise ValidationError("required Caddy runtime variables are unavailable")
    try:
        for name, value in selected.items():
            if name in IP_VARIABLES:
                ipaddress.ip_address(value)
            elif name.endswith("_CIDRS"):
                for network in value.split():
                    ipaddress.ip_network(network, strict=False)
            elif name.endswith("_UPSTREAM"):
                host, _, port = value.rpartition(":")
                if not SAFE_DIAL.fullmatch(value) or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                    raise ValidationError(f"invalid upstream runtime value: {name}")
        metrics = selected.get("CADDY_PRIVATE_METRICS_BIND")
        if metrics and not ipaddress.ip_address(metrics).is_private:
            raise ValidationError("metrics listener is not bound to a private address")
    except ValueError as exc:
        raise ValidationError("invalid address runtime value") from exc
    return selected


def require_container_identity(container: dict[str, Any], image: dict[str, Any]) -> dict[str, str]:
    """The running container must be the healthy, immutable, labelled, non-root release."""
    state = container.get("State") or {}
    if state.get("Running") is not True or (state.get("Health") or {}).get("Status") != "healthy":
        raise ValidationError("Caddy container is not running and healthy")
    config = container.get("Config") or {}
    reference = config.get("Image") or ""
    match = re.fullmatch(rf"{re.escape(EXPECTED_IMAGE_REPOSITORY)}@(sha256:[0-9a-f]{{64}})", reference)
    if not match:
        raise ValidationError("container image is not the immutable canonical identity")
    labels = config.get("Labels") or {}
    identity = {
        "source_sha": labels.get(SOURCE_LABEL) or "",
        "image_digest": match.group(1),
        "config_sha256": labels.get(CONFIG_LABEL) or "",
        "release_id": labels.get(RELEASE_LABEL) or "",
    }
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_sha"]):
        raise ValidationError("container source SHA label is invalid")
    if labels.get(DIGEST_LABEL) != identity["image_digest"]:
        raise ValidationError("container image digest label does not match the image")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["config_sha256"]) or not identity["release_id"]:
        raise ValidationError("container configuration or release label is invalid")
    image_labels = (image.get("Config") or {}).get("Labels") or {}
    if reference not in (image.get("RepoDigests") or []):
        raise ValidationError("local image repository digest does not match")
    if image_labels.get("org.opencontainers.image.source") not in SOURCE_REPOSITORIES:
        raise ValidationError("image source label is not canonical")
    if image_labels.get("org.opencontainers.image.revision") != identity["source_sha"]:
        raise ValidationError("image revision label does not match container source")
    if image_labels.get(CONFIG_LABEL) != identity["config_sha256"]:
        raise ValidationError("image configuration label does not match container label")
    if (image.get("Config") or {}).get("User") != RUNTIME_USER:
        raise ValidationError("image runtime user is not non-root")
    return identity


def caddy_host_pid(table: str) -> int:
    candidates = []
    for line in table.splitlines()[1:]:
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[2] == "caddy" and re.search(r"(?:^|\s)(?:/usr/bin/)?caddy\s+run(?:\s|$)", fields[3]):
            if fields[0].isdigit() and int(fields[0]) > 1:
                candidates.append(int(fields[0]))
    if len(candidates) != 1:
        raise ValidationError("exactly one Caddy runtime process is required")
    return candidates[0]


def require_listener(table: str, protocol: str, address: str, port: int, pid: int) -> str:
    endpoint = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    owner = re.compile(rf"\bpid={pid}(?:,|\))")
    for line in table.splitlines():
        fields = line.split()
        if fields and fields[0] == protocol and endpoint in line and owner.search(line):
            return f"{protocol}/{endpoint}"
    raise ValidationError(f"Caddy-owned listener missing: {protocol}/{endpoint}")


def require_proxy_upstreams(adapted: dict[str, Any]) -> None:
    """Every adapted reverse_proxy handler must dial at least one upstream."""

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("handler") == "reverse_proxy":
                upstreams = value.get("upstreams") or []
                if not upstreams or any(not (u or {}).get("dial") for u in upstreams):
                    raise ValidationError("adapted reverse_proxy has no upstream")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(adapted)


def require_transport_security(adapted: dict[str, Any]) -> None:
    """Reject public administration and explicit weakening of Caddy TLS defaults."""
    if (adapted.get("admin") or {}).get("listen") != ADMIN_ADDRESS:
        raise ValidationError("admin listener is not the fixed private socket")
    servers = (((adapted.get("apps") or {}).get("http") or {}).get("servers") or {})
    if not servers:
        raise ValidationError("HTTP servers are missing")
    for server in servers.values():
        automatic = server.get("automatic_https") or {}
        if automatic.get("disable") or automatic.get("disable_redirects"):
            raise ValidationError("automatic HTTPS or redirects disabled")
        for policy in server.get("tls_connection_policies") or []:
            if policy.get("protocol_min", "tls1.2") not in {"tls1.2", "tls1.3"}:
                raise ValidationError("TLS protocol floor is unsafe")

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("insecure_skip_verify"):
                raise ValidationError("upstream TLS verification disabled")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(adapted)


class AdminSocketConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def active_configuration() -> dict[str, Any]:
    """Read only the fixed private admin socket; never redirect or use proxies."""
    connection = AdminSocketConnection(ADMIN_SOCKET, timeout=5)
    try:
        connection.request("GET", "/config/")
        response = connection.getresponse()
        if response.status != 200:
            raise ValidationError("active configuration readback failed")
        payload = response.read(4 * 1024 * 1024 + 1)
        if len(payload) > 4 * 1024 * 1024:
            raise ValidationError("active configuration exceeds readback limit")
        value = json.loads(payload)
        if not isinstance(value, dict) or not value:
            raise ValidationError("active configuration is not an object")
        return value
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise ValidationError("active configuration readback failed") from exc
    finally:
        connection.close()


def require_served_config(desired: dict[str, Any], active: Any) -> str:
    """Fail closed on drift; hash canonical JSON without disclosing either config."""
    if not isinstance(active, dict) or not active or json.dumps(active, sort_keys=True) != json.dumps(desired, sort_keys=True):
        raise ValidationError("served configuration differs from validated disk configuration")
    return hashlib.sha256(json.dumps(active, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_adapted_redaction(adapted: dict[str, Any]) -> None:
    logs = ((adapted.get("logging") or {}).get("logs") or {})
    access_logs = [value for name, value in logs.items() if name != "default"]
    if not access_logs:
        raise ValidationError("adapted access logs are missing")
    required_headers = {
        "request>headers>Authorization",
        "request>headers>Apikey",
        "request>headers>X-Api-Key",
        "request>headers>Proxy-Authorization",
        "request>headers>Cookie",
        "resp_headers>Set-Cookie",
    }
    for log in access_logs:
        fields = ((log.get("encoder") or {}).get("fields") or {})
        if any((fields.get(name) or {}).get("filter") != "delete" for name in required_headers):
            raise ValidationError("adapted access log header redaction is incomplete")
        uri = fields.get("request>uri") or {}
        actions = uri.get("actions") or []
        required_queries = {"apikey", "api_key", "access_token", "refresh_token", "id_token",
                            "client_secret", "password", "secret", "token"}
        deleted = {action.get("parameter") for action in actions if action.get("type") == "delete"}
        if uri.get("filter") != "query" or not required_queries <= deleted:
            raise ValidationError("adapted access log query redaction is incomplete")


def require_access_log_coverage(adapted: dict[str, Any]) -> None:
    """Every served host must write to a dedicated, redacted access log.

    Redaction is enforced per log, so a host with no log mapping would escape
    it: Caddy writes that host's access entries to the unfiltered default
    logger instead. Each host matched by a server route must map to at least
    one access log, and each mapped log must exist and include that logger.
    """
    logs = ((adapted.get("logging") or {}).get("logs") or {})
    servers = (((adapted.get("apps") or {}).get("http") or {}).get("servers") or {})
    covered = 0
    for server in servers.values():
        hosts = {
            host
            for route in server.get("routes") or []
            for matcher in route.get("match") or []
            for host in matcher.get("host") or []
        }
        if not hosts:
            continue
        logger_names = ((server.get("logs") or {}).get("logger_names") or {})
        for host in hosts:
            names = logger_names.get(host) or []
            if isinstance(names, str):
                names = [names]
            if not names:
                raise ValidationError("served host has no access log")
            for name in names:
                log = logs.get(name)
                if name == "default" or not log or f"http.log.access.{name}" not in (log.get("include") or []):
                    raise ValidationError("served host access log is not configured")
            covered += 1
    if not covered:
        raise ValidationError("adapted access logs are missing")


def sanitized_summary(adapted: dict[str, Any]) -> dict[str, Any]:
    hosts: set[str] = set()
    paths: set[str] = set()
    upstreams: set[str] = set()
    header_names: set[str] = set()
    duration_fields: set[str] = set()
    mtls_present = False

    def visit(value: Any, key: str = "") -> None:
        nonlocal mtls_present
        if isinstance(value, dict):
            for child_key, child in value.items():
                lowered = child_key.lower()
                if lowered in {"client_authentication", "client_certificate", "client_ca_pool"}:
                    mtls_present = True
                if lowered in {"headers", "set", "add", "delete"} and isinstance(child, dict):
                    header_names.update(str(name) for name in child)
                if any(part in lowered for part in ("timeout", "keepalive", "duration")):
                    duration_fields.add(child_key)
                visit(child, child_key)
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str):
            if key == "host" and re.fullmatch(r"[A-Za-z0-9.*_-]+", value):
                hosts.add(value)
            elif key == "path" and value.startswith("/") and "?" not in value:
                paths.add(value)
            elif key == "dial":
                if not SAFE_DIAL.fullmatch(value):
                    raise ValidationError("unsafe upstream representation")
                upstreams.add(value)

    visit(adapted)
    return {
        "hosts": sorted(hosts),
        "paths": sorted(paths),
        "upstreams": sorted(upstreams),
        "header_names": sorted(header_names),
        "duration_fields": sorted(duration_fields),
        "mtls_policy_present": mtls_present,
        "websocket_transport_supported": bool(upstreams),
    }


def container_config(copied: Path) -> tuple[str, str]:
    run_fixed([DOCKER, "cp", f"{CONTAINER}:/etc/caddy/.", str(copied)])
    return canonical_source(copied)


def main() -> int:
    if len(sys.argv) != 1:
        raise ValidationError("arguments are not accepted")
    containers = json.loads(run_fixed([DOCKER, "inspect", CONTAINER]))
    if len(containers) != 1:
        raise ValidationError("fixed Caddy container not found")
    container = containers[0]
    images = json.loads(run_fixed([DOCKER, "image", "inspect", (container.get("Config") or {}).get("Image") or ""]))
    if len(images) != 1:
        raise ValidationError("immutable Caddy image is unavailable locally")
    identity = require_container_identity(container, images[0])

    copied = Path(tempfile.mkdtemp(prefix="codestra-caddy-config-"))
    try:
        source, checksum = container_config(copied)
    finally:
        shutil.rmtree(copied, ignore_errors=True)
    if checksum != identity["config_sha256"]:
        raise ValidationError("running configuration does not match the signed image")
    require_redaction(source)
    environment = runtime_environment((container.get("Config") or {}).get("Env") or [], required_runtime_variables(source))

    caddy = [DOCKER, "exec", CONTAINER, "/usr/bin/caddy"]
    run_fixed([*caddy, "validate", "--config", CONTAINER_CADDYFILE, "--adapter", "caddyfile"])
    adapted = json.loads(run_fixed([*caddy, "adapt", "--config", CONTAINER_CADDYFILE, "--adapter", "caddyfile"]))
    require_adapted_redaction(adapted)
    require_access_log_coverage(adapted)
    require_proxy_upstreams(adapted)
    require_transport_security(adapted)
    modules = {line.split()[0] for line in run_fixed([*caddy, "list-modules", "--packages"]).splitlines() if line.strip()}
    if not REQUIRED_MODULES <= modules:
        raise ValidationError("required Caddy modules missing")
    active_digest = require_served_config(adapted, active_configuration())

    pid = caddy_host_pid(run_fixed([DOCKER, "top", CONTAINER, "-eo", "pid,ppid,comm,args"]))
    sockets = run_fixed([SS, "-H", "-lntup"])
    public, metrics, private = (environment[name] for name in ("CADDY_PUBLIC_BIND", "CADDY_PRIVATE_METRICS_BIND", "CADDY_PRIVATE_INGRESS_BIND"))
    listeners = [
        require_listener(sockets, "tcp", public, 80, pid),
        require_listener(sockets, "tcp", public, 443, pid),
        require_listener(sockets, "udp", public, 443, pid),
        require_listener(sockets, "tcp", metrics, 2020, pid),
        require_listener(sockets, "tcp", private, 18080, pid),
    ]
    run_fixed([CURL, "--fail", "--silent", "--show-error", "--connect-timeout", "3", "--max-time", "5",
               f"http://{metrics}:2020/healthz"])
    evidence = {
        "schema": "codestra.caddy-readonly-validation.v2",
        "container": CONTAINER,
        **identity,
        "container_health": "healthy",
        "config_identity": "PASS",
        "config_validation": "PASS",
        "served_config_sha256": active_digest,
        "served_config_matches_image": True,
        "credential_redaction": "PASS",
        "listeners": listeners,
        "module_set_sha256": hashlib.sha256("\n".join(sorted(modules)).encode()).hexdigest(),
        "summary": sanitized_summary(adapted),
    }
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
        print(f"CADDY_READONLY_VALIDATION=FAIL:{type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2)
