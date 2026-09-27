#!/usr/bin/env python3
"""Validate the repository-only observability URL and Caddy source contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ROOT_CADDYFILE_PATH = ROOT / "Caddyfile"
CONTRACT_PATH = ROOT / "config" / "observability-exposure.v1.json"
SITE_PATH = ROOT / "sites" / "codestra.media.observability.caddy"
RUNTIME_PATH = ROOT / "config" / "runtime-values.example"
HEADERS_PATH = ROOT / "snippets" / "security_headers.caddy"
RULESET_PATH = ROOT / "config" / "github" / "main-ruleset.json"
CHECKSUM_PATH = ROOT / "release" / "observability" / "caddy-observability-configuration.sha256"

PUBLIC = {
    "graf.codestra.media": ("grafana", "CADDY_GRAFANA_UPSTREAM", "native-keycloak-oidc"),
    "supe.codestra.media": ("superset", "CADDY_SUPERSET_UPSTREAM", "native-keycloak-oidc"),
    "bao.codestra.media": ("openbao", "CADDY_OPENBAO_UPSTREAM", "private-network-plus-native-keycloak-oidc"),
}
PRIVATE = {
    "prometheus": "prom.codestra.media",
    "alertmanager": "aler.codestra.media",
    "loki": "loki.codestra.media",
    "tempo": "temp.codestra.media",
    "opentelemetry": "otel.codestra.media",
    "alloy": "allo.codestra.media",
    "node-exporter": "node.codestra.media",
    "cadvisor": "cadv.codestra.media",
    "redis-exporter": "rdex.codestra.media",
    "blackbox-exporter": "blac.codestra.media",
}
PROHIBITED_PUBLIC_NAME = "pgex.codestra.media"
APPROVED_DYNAMIC_SITE_ADDRESS = "{$CADDY_N8N_EDITOR_HOST}"
KYYOW_PUBLIC = {
    "app.kyyow.com",
    "api.kyyow.com",
    "search.kyyow.com",
    "docs.kyyow.com",
    "auth.kyyow.com",
    "status.kyyow.com",
}


class ExposureError(ValueError):
    pass


def root_caddy_source_paths() -> tuple[Path, ...]:
    """Return every source fragment imported by the root Caddyfile."""

    root_source = ROOT_CADDYFILE_PATH.read_text(encoding="utf-8")
    paths = [ROOT_CADDYFILE_PATH]
    approved_imports = {"snippets/*.caddy", "sites/*.caddy"}
    imports = re.findall(r"(?m)^\s*import\s+([^\s#]+)\s*$", root_source)
    if set(imports) != approved_imports or len(imports) != len(approved_imports):
        raise ExposureError("root Caddy import inventory is not the reviewed static set")
    for pattern in sorted(imports):
        matches = sorted(ROOT.glob(pattern))
        if not matches or any(not path.is_file() for path in matches):
            raise ExposureError(f"root Caddy import has no regular-file match: {pattern}")
        for path in matches:
            validate_fragment_imports(path, path.read_text(encoding="utf-8"))
        paths.extend(matches)
    return tuple(paths)


def validate_fragment_imports(path: Path, source: str) -> None:
    """Allow only the reviewed named snippet import inside site fragments."""

    imports = []
    for raw_line in source.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("import "):
            imports.append(line.removeprefix("import ").strip())
    relative_parent = path.parent.relative_to(ROOT)
    allowed = {"security_headers", "public_boundary"} if relative_parent == Path("sites") else set()
    unexpected = sorted({value for value in imports if value not in allowed})
    if unexpected:
        raise ExposureError(
            f"nested or unreviewed import in {path.relative_to(ROOT)}: {unexpected}"
        )


def load_root_caddy_sources() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in root_caddy_source_paths()
    )


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExposureError(f"cannot parse {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExposureError("exposure contract must be a JSON object")
    return value


def site_block(site: str, host: str) -> str:
    match = re.search(rf"(?m)^{re.escape(host)}\s*\{{", site)
    if not match:
        raise ExposureError(f"missing public site block: {host}")
    depth = 0
    for index in range(match.end() - 1, len(site)):
        if site[index] == "{":
            depth += 1
        elif site[index] == "}":
            depth -= 1
            if depth == 0:
                return site[match.start() : index + 1]
    raise ExposureError(f"unterminated public site block: {host}")


def extract_static_site_addresses(all_sites: str) -> tuple[str, ...]:
    """Return normalized top-level addresses while rejecting unsafe forms."""

    depth = 0
    addresses: list[str] = []
    for raw_line in all_sites.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        structural = re.sub(
            r"\{(?:\$|env\.)[^}]+\}",
            lambda match: " " * len(match.group(0)),
            line,
            flags=re.IGNORECASE,
        )
        if depth == 0 and "{" in structural:
            address = line[: structural.index("{")].strip()
            if address and not (address.startswith("(") and address.endswith(")")):
                for candidate in (item.strip() for item in address.split(",")):
                    if not candidate:
                        raise ExposureError("empty top-level Caddy site address")
                    if "{$" in candidate:
                        if candidate != APPROVED_DYNAMIC_SITE_ADDRESS:
                            raise ExposureError(
                                "wildcard, catch-all, or dynamic public site address "
                                f"prohibited: {candidate}"
                            )
                        addresses.append(candidate)
                        continue
                    lowered = candidate.lower()
                    if lowered.startswith("http://"):
                        raise ExposureError(
                            f"insecure public site scheme prohibited: {candidate}"
                        )
                    if lowered.startswith("https://"):
                        candidate = candidate[len("https://") :]
                    elif "://" in candidate:
                        raise ExposureError(
                            f"unreviewed public site scheme prohibited: {candidate}"
                        )
                    if (
                        "*" in candidate
                        or "{env." in candidate.lower()
                        or candidate.startswith(":")
                        or not candidate
                        or any(character.isspace() for character in candidate)
                    ):
                        raise ExposureError(
                            "wildcard, catch-all, or dynamic public site address "
                            f"prohibited: {candidate}"
                        )
                    addresses.append(candidate)
        depth += structural.count("{") - structural.count("}")
        if depth < 0:
            raise ExposureError("unbalanced public Caddy source")
    if depth != 0:
        raise ExposureError("unbalanced public Caddy source")
    return tuple(addresses)


def validate(contract: dict[str, Any], site: str, all_sites: str, runtime: str, headers: str) -> None:
    if contract.get("schema") != "codestra.observability-exposure.v1":
        raise ExposureError("unsupported exposure schema")
    if contract.get("principalRepository") != "ingtrader21-spec/Caddy":
        raise ExposureError("Caddy repository is not principal authority")
    if any(key in contract for key in ("dnsTarget", "publicIpv4", "dnsTtlSeconds")):
        raise ExposureError("repository-only contract must not assert production DNS state")

    public_routes = contract.get("publicRoutes")
    if not isinstance(public_routes, list) or [item.get("host") for item in public_routes] != list(PUBLIC):
        raise ExposureError("public route set or order mismatch")
    for item in public_routes:
        host = item["host"]
        service, env_name, authentication = PUBLIC[host]
        expected = {
            "host": host,
            "service": service,
            "upstreamEnvironmentVariable": env_name,
            "authentication": authentication,
        }
        if any(item.get(key) != value for key, value in expected.items()):
            raise ExposureError(f"{host}: route mapping or authentication mismatch")
        if item.get("privateUpstreamRequired") is not True or item.get("publicNativePortAllowed") is not False:
            raise ExposureError(f"{host}: private upstream/public port policy mismatch")

    private = contract.get("privateServices")
    if not isinstance(private, list):
        raise ExposureError("private service contract missing")
    by_service = {item.get("service"): item for item in private}
    if set(by_service) != set(PRIVATE) | {"postgres-exporter"}:
        raise ExposureError("private service inventory mismatch")
    for service, hostname in PRIVATE.items():
        item = by_service[service]
        if item.get("retainedPrivateName") != hostname or item.get("publicCaddyRouteAllowed") is not False:
            raise ExposureError(f"{service}: private name or public route policy mismatch")
    postgres = by_service["postgres-exporter"]
    if postgres != {
        "service": "postgres-exporter",
        "retainedPrivateName": None,
        "prohibitedPublicName": PROHIBITED_PUBLIC_NAME,
        "publicDnsHostnameAllowed": False,
        "publicCaddyRouteAllowed": False,
    }:
        raise ExposureError("PostgreSQL Exporter must have no public hostname or route")

    activation = contract.get("activation")
    expected_activation = {
        "repositoryConfigurationOnly": True,
        "dnsStateRead": False,
        "dnsChangeAuthorized": False,
        "upstreamHealthVerified": False,
        "liveCaddyReloadAuthorized": False,
        "productionTrafficCutoverAuthorized": False,
    }
    if activation != expected_activation:
        raise ExposureError("activation state exceeds the repository-only authority")

    ruleset = load_contract(RULESET_PATH)
    if ruleset.get("name") != "Protect main" or ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        raise ExposureError("protected-main ruleset identity mismatch")
    if ruleset.get("conditions", {}).get("ref_name", {}).get("include") != ["~DEFAULT_BRANCH"]:
        raise ExposureError("protected-main default branch condition mismatch")
    rules = {item.get("type"): item.get("parameters", {}) for item in ruleset.get("rules", [])}
    if not {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= set(rules):
        raise ExposureError("protected-main ruleset is incomplete")
    pull_request = rules["pull_request"]
    required_pull_request = {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": True,
        "require_last_push_approval": True,
        "required_review_thread_resolution": True,
    }
    if any(pull_request.get(key) != value for key, value in required_pull_request.items()):
        raise ExposureError("protected-main review controls mismatch")
    checks = [item.get("context") for item in rules["required_status_checks"].get("required_status_checks", [])]
    if checks != ["validate-source", "validate-merge-result"]:
        raise ExposureError("protected-main exact-source checks mismatch")

    comments_removed = re.sub(r"(?m)^\s*#.*$", "", all_sites)
    extracted_addresses = extract_static_site_addresses(comments_removed)
    top_level_addresses = set(extracted_addresses)
    reviewed_addresses = {
        "api.codestra.co",
        "automation.codestra.co",
        "{$CADDY_N8N_EDITOR_HOST}",
        *PUBLIC,
        *KYYOW_PUBLIC,
    }
    if top_level_addresses != reviewed_addresses:
        unexpected = sorted(top_level_addresses - reviewed_addresses)
        missing = sorted(reviewed_addresses - top_level_addresses)
        raise ExposureError(
            f"top-level site-address allowlist mismatch; unexpected={unexpected}, missing={missing}"
        )
    if len(extracted_addresses) != len(top_level_addresses):
        raise ExposureError("duplicate top-level Caddy site address prohibited")
    if any("*" in address for address in top_level_addresses):
        raise ExposureError("wildcard top-level Caddy site address prohibited")
    forbidden_hostnames = set(PRIVATE.values()) | {PROHIBITED_PUBLIC_NAME}
    reserved_matcher = "@reserved_observability_host host " + " ".join(sorted(forbidden_hostnames))
    dynamic_block = site_block(all_sites, APPROVED_DYNAMIC_SITE_ADDRESS)
    if reserved_matcher not in dynamic_block or 'respond @reserved_observability_host "Not Found" 404' not in dynamic_block:
        raise ExposureError("approved dynamic site is missing its reserved observability host denial")
    comments_removed = comments_removed.replace(reserved_matcher, "")
    for hostname in forbidden_hostnames:
        if re.search(rf"(?i)(?<![A-Za-z0-9.-]){re.escape(hostname)}(?![A-Za-z0-9.-])", comments_removed):
            raise ExposureError(f"private hostname appears in public Caddy source: {hostname}")

    for host, (_, env_name, _) in PUBLIC.items():
        if len(re.findall(rf"(?m)^{re.escape(host)}\s*\{{", all_sites)) != 1:
            raise ExposureError(f"{host}: must have exactly one public site block")
        block = site_block(site, host)
        required = (
            "import security_headers",
            "request>headers>Authorization delete",
            "request>headers>Cookie delete",
            "resp_headers>Set-Cookie delete",
            "delete state",
            "delete session_state",
            "header_up Host {host}",
            "header_up X-Forwarded-Host {host}",
            "header_up X-Forwarded-Proto https",
            "flush_interval -1",
            "stream_timeout 5m",
            "dial_timeout 5s",
        )
        if any(token not in block for token in required):
            raise ExposureError(f"{host}: security, proxy, streaming, timeout, or redaction control missing")
        for query_name in ("access_token", "code", "id_token", "session_state", "state", "token"):
            if f"delete {query_name}" not in block:
                raise ExposureError(f"{host}: OIDC query redaction missing: {query_name}")
        if "{$" + env_name + "}" not in block or re.search(r"\{\$" + re.escape(env_name) + r":[^}]+\}", block):
            raise ExposureError(f"{host}: exact required private upstream variable missing")
        for header in (
            "X-Auth-Request-User",
            "X-Auth-Request-Email",
            "X-Auth-Request-Groups",
            "X-Authenticated-Client",
            "X-Authenticated-Tenant",
            "X-Authenticated-Role",
            "X-Codestra-Gateway-Secret",
        ):
            if f"request_header -{header}" not in block:
                raise ExposureError(f"{host}: spoofable identity header not stripped: {header}")
        if re.search(r"(?m)^\s*(?:request_header|header_up)\s+-?Authorization\b", block):
            raise ExposureError(f"{host}: Authorization forwarding must remain unmodified")

    bao = site_block(site, "bao.codestra.media")
    if "@openbao_allowed remote_ip {$CADDY_OPENBAO_ALLOWED_CIDRS}" not in bao:
        raise ExposureError("OpenBao source-network gate missing")
    if 'respond "Forbidden" 403' not in bao:
        raise ExposureError("OpenBao default denial missing")
    for header in ("X-Vault-Token", "X-Bao-Token"):
        if f"request>headers>{header} delete" not in bao:
            raise ExposureError(f"OpenBao log redaction missing: {header}")

    runtime_values = {}
    for line in runtime.splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            runtime_values[key] = value
    for _, env_name, _ in PUBLIC.values():
        if not runtime_values.get(env_name, "").startswith("127.0.0.1:"):
            raise ExposureError(f"{env_name}: validation reference must remain loopback-only")
    allowed_cidrs = runtime_values.get("CADDY_OPENBAO_ALLOWED_CIDRS", "").split()
    if allowed_cidrs != ["192.0.2.0/24", "198.51.100.0/24"]:
        raise ExposureError("OpenBao example must use documentation-only CIDRs")
    if "0.0.0.0/0" in runtime or "::/0" in runtime:
        raise ExposureError("broad OpenBao source range prohibited")
    for token in (
        'Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ):
        if token not in headers:
            raise ExposureError(f"shared security header missing: {token}")


def configuration_checksum(contract: dict[str, Any], site: str, runtime: str, headers: str) -> str:
    overrides = {SITE_PATH: site, HEADERS_PATH: headers}
    payloads = [
        (CONTRACT_PATH.relative_to(ROOT).as_posix(), json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"),
        (RUNTIME_PATH.relative_to(ROOT).as_posix(), runtime),
    ]
    payloads.extend(
        (path.relative_to(ROOT).as_posix(), overrides.get(path, path.read_text(encoding="utf-8")))
        for path in root_caddy_source_paths()
    )
    material = b"".join(path.encode() + b"\0" + payload.encode() for path, payload in payloads)
    return hashlib.sha256(material).hexdigest()


def run(write: bool) -> str:
    contract = load_contract()
    site = SITE_PATH.read_text(encoding="utf-8")
    runtime = RUNTIME_PATH.read_text(encoding="utf-8")
    headers = HEADERS_PATH.read_text(encoding="utf-8")
    all_sites = load_root_caddy_sources()
    validate(contract, site, all_sites, runtime, headers)
    checksum = configuration_checksum(contract, site, runtime, headers)
    expected = f"{checksum}  caddy-observability-source-bundle\n"
    if write:
        CHECKSUM_PATH.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n" keeps the committed checksum byte-identical no matter
        # which platform regenerated it; the default translation would write
        # CRLF on Windows and diff against the Linux CI runner.
        CHECKSUM_PATH.write_text(expected, encoding="utf-8", newline="\n")
    else:
        try:
            actual = CHECKSUM_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise ExposureError(f"configuration checksum missing: {exc}") from exc
        if actual != expected:
            raise ExposureError("configuration checksum is stale")
    return checksum


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        checksum = run(args.write)
    except ExposureError as exc:
        print(f"CADDY_OBSERVABILITY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    print("CADDY_OBSERVABILITY_URL_CONTRACT=PASS")
    print(f"CADDY_OBSERVABILITY_CONFIGURATION_CHECKSUM={checksum}")
    print("CADDY_PRIVATE_NATIVE_ROUTES=0")
    print("CADDY_LIVE_RELOAD_AUTHORIZED=NO")


if __name__ == "__main__":
    main()
