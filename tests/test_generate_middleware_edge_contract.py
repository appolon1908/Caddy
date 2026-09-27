import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_middleware_edge_contract as generator  # noqa: E402

CHAIN = json.loads((ROOT / "config/edge-contract-chain.v1.json").read_text())
PUBLIC = json.loads((ROOT / "config/public-edge-registry.v1.json").read_text())


def test_generator_render_matches_checked_in_edge_contract_and_site():
    # The generator is the authority for config/caddy-kong-contract.v1.json and
    # the generated route block in sites/api.codestra.co.caddy. If it drifts from
    # the checked-in files, re-running it would silently rewrite reviewed edge
    # policy (this guard was added after it regressed the /metrics/* denial).
    edge, site = generator.render()
    assert edge == generator.EDGE.read_text(encoding="utf-8")
    assert site == generator.SITE.read_text(encoding="utf-8")


def test_generator_renders_every_private_only_path_the_site_denies():
    edge = json.loads(generator.render()[0])
    assert edge["privateOnlyPaths"] == ["/metrics", "/metrics/*", "/internal", "/internal/*"]
    assert "/metrics/*" in edge["privateOnlyRule"]
    assert "/internal plus /internal/*" in edge["privateOnlyRule"]


def test_vendored_contract_is_the_pinned_final_middleware_digest():
    contract = json.loads(generator.VENDORED.read_text(encoding="utf-8"))
    digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert digest == generator.PINNED.read_text(encoding="utf-8").strip()
    assert digest == CHAIN["middleware"]["public_contract_sha256"]
    assert digest == PUBLIC["middleware_public_contract_sha256"]
    assert generator.MIDDLEWARE_SOURCE_SHA == CHAIN["middleware"]["source_sha"]
    assert generator.MIDDLEWARE_SOURCE_SHA == PUBLIC["middleware_source_sha"]
