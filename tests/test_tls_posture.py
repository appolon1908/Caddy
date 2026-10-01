"""Static guards for the edge TLS posture and the forwarded-header boundary.

docs/tls-contract-v1.md asks for supported Caddy defaults with no plaintext
public exposure and no disabled upstream verification. These checks fail when a
source change weakens that posture, which the adapted-route and checksum gates
do not evaluate. Runtime issuance, renewal and handshakes stay out of scope.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CADDYFILE = ROOT / "Caddyfile"
SOURCES = [CADDYFILE, *sorted((ROOT / "snippets").glob("*.caddy")), *sorted((ROOT / "sites").glob("*.caddy"))]
SITES = sorted((ROOT / "sites").glob("*.caddy"))
COMMENT = re.compile(r"(^|\s)#.*$")
FORBIDDEN_ANYWHERE = {
    "auto_https": "automatic HTTPS and its HTTP->HTTPS redirects must stay on",
    "on_demand_tls": "on-demand issuance lets any SNI trigger ACME orders",
    "on_demand": "on-demand issuance lets any SNI trigger ACME orders",
    "tls_insecure_skip_verify": "upstream TLS verification must never be disabled",
    "insecure_skip_verify": "upstream TLS verification must never be disabled",
    "insecure_secrets_log": "TLS session keys must never be written to disk",
    "must_staple": "Let's Encrypt ended OCSP in 2025; must-staple certificates break",
    "local_certs": "public hosts must not be served from the internal CA",
    "skip_install_trust": "public hosts must not be served from the internal CA",
}
def directive_lines(path: Path) -> list[tuple[int, str]]:
    lines=[]
    for number,raw in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
        line=COMMENT.sub("",raw).strip()
        if line: lines.append((number,line))
    return lines
def site_blocks(path: Path) -> dict[str,list[tuple[int,int,str]]]:
    blocks={}; current=None; depth=0
    for number,line in directive_lines(path):
        if depth==0 and line.endswith("{") and not line.startswith("("):
            current=line[:-1].strip(); blocks[current]=[]
        elif current is not None and line!="}":
            blocks[current].append((number,depth,line))
        depth += line.count("{")-line.count("}")
        if depth==0: current=None
    return blocks
def test_admin_api_stays_on_loopback():
    admin=[line for _,line in directive_lines(CADDYFILE) if line.split()[0]=="admin"]
    assert admin
    for line in admin:
        target=line.split()[1]
        assert target=="off" or re.fullmatch(r"(127\.0\.0\.1|localhost|\[::1\]):\d+",target),line
def test_no_directive_weakens_automatic_https_or_verification():
    violations=[]
    for path in SOURCES:
        for number,line in directive_lines(path):
            reason=FORBIDDEN_ANYWHERE.get(line.split()[0])
            if reason: violations.append(f"{path.relative_to(ROOT)}:{number}: {line} ({reason})")
    assert not violations,"\n".join(violations)
def test_no_public_site_is_plaintext():
    for path in SITES:
        for address_list in site_blocks(path):
            for address in address_list.replace(","," ").split():
                assert not address.startswith("http://"),f"{path.name}: {address}"
                assert not address.endswith(":80"),f"{path.name}: {address}"
def test_sites_keep_default_certificate_policy():
    violations=[]
    for path in SITES:
        for address,body in site_blocks(path).items():
            for number,depth,line in body:
                if depth==1 and line.split()[0]=="tls": violations.append(f"{path.name}:{number}: {address}: {line}")
    assert not violations,"\n".join(violations)
def test_committed_source_never_targets_a_staging_ca():
    for path in SOURCES: assert "acme-staging" not in path.read_text(encoding="utf-8"),path.name
def test_shared_policy_strips_untrusted_forwarded_headers():
    source=(ROOT/"snippets"/"security_headers.caddy").read_text(encoding="utf-8")
    assert "request_header -Forwarded" in source
    assert "request_header -X-Forwarded-Port" in source
def test_every_public_site_imports_shared_edge_policy():
    missing=[]
    for path in SITES:
        for address,body in site_blocks(path).items():
            directives={line for _,_,line in body}
            if "import security_headers" not in directives: missing.append(f"{path.name}: {address}")
    assert not missing,"\n".join(missing)
