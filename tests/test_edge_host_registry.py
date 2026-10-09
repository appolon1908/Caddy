"""Every served host is registered, and each site block matches its registered profiles."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = json.loads((ROOT / "config" / "edge-host-registry.v1.json").read_text(encoding="utf-8"))
PROFILES = json.loads((ROOT / "config" / "edge-profiles.v1.json").read_text(encoding="utf-8"))
REQUIRED = {"host", "site_file", "environment", "owner", "route_class", "tls_profile", "upstreams", "auth_boundary",
            "security_header_profile", "request_size_profile", "logging_profile", "public"}
ADDRESS_RE = re.compile(r"(?m)^(\S[^\n{]*?) \{\n")


def site_blocks():
    """(site file, address, block body) for every site block."""
    blocks = []
    for path in sorted((ROOT / "sites").glob("*.caddy")):
        text = path.read_text(encoding="utf-8")
        for match in ADDRESS_RE.finditer(text):
            if match.group(1).startswith("("):
                continue
            end = text.index("\n}\n", match.end())
            for address in match.group(1).split(","):
                blocks.append((f"sites/{path.name}", address.strip(), text[match.end():end]))
    return blocks


BLOCKS = {address: (site, body) for site, address, body in site_blocks()}
ENTRIES = {entry["host"]: entry for entry in REGISTRY["hosts"]}


def test_registry_and_served_hosts_are_identical():
    assert len(ENTRIES) == len(REGISTRY["hosts"])
    assert set(ENTRIES) == set(BLOCKS)


def test_no_wildcard_or_catch_all_public_host():
    for address in BLOCKS:
        assert "*" not in address and not address.startswith(":") and address not in {"http://", "https://"}, address
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    catch_all = re.findall(r"(?ms)^http:// \{\n(.*?)^\}", caddyfile)
    assert len(catch_all) == 1 and "respond 404" in catch_all[0] and "reverse_proxy" not in catch_all[0]


@pytest.mark.parametrize("host", sorted(ENTRIES))
def test_registered_profiles_match_the_site_block(host):
    entry = ENTRIES[host]
    assert REQUIRED <= set(entry), host
    site, body = BLOCKS[host]
    assert entry["site_file"] == site
    for kind, field in (("request_size", "request_size_profile"), ("tls", "tls_profile"),
                        ("security_headers", "security_header_profile"), ("logging", "logging_profile")):
        assert entry[field] in PROFILES[kind], (host, field)
    assert set(re.findall(r"\{\$(CADDY_[A-Z0-9_]+_UPSTREAM)\}", body)) == set(entry["upstreams"]), host
    assert f"max_size {PROFILES['request_size'][entry['request_size_profile']]}" in body, host
    assert "import security_headers" in body, host
    assert "import public_boundary" in body or not entry["public"], host
    assert "import access_log " in body, host
    tls = entry["tls_profile"]
    if tls == "private-mtls":
        assert "client_auth" in body and "require_and_verify" in body and entry["public"] is False, host
    elif tls == "internal-ca":
        assert "\ttls internal" in body and entry["public"] is False, host
    else:
        assert not re.search(r"(?m)^\ttls ", body), host
    auth = entry["auth_boundary"]
    if auth == "mtls":
        assert "client_auth" in body
    if auth == "forward-auth":
        assert "forward_auth" in body
    if "source-cidr" in auth:
        assert "remote_ip" in body or "client_ip" in body, host
    if auth.startswith("kong-jwt"):
        assert "CADDY_KONG_UPSTREAM" in entry["upstreams"], host


def test_no_site_weakens_tls():
    for site, body in BLOCKS.values():
        assert not re.search(r"protocols\s+tls1\.[01]", body), site
        assert "insecure_skip_verify" not in body, site
