#!/usr/bin/env python3
"""Validate the exact Caddy-to-Kong route ownership boundary."""

from __future__ import annotations

import re
from collections.abc import Iterable

KONG_MATCHER_RE = re.compile(r"(?m)^[ \t]*@kong[ \t]+path[ \t]+([^\r\n#]+?)\s*$")


def routed_kong_prefixes(site_source: str) -> tuple[str, ...]:
    """Return normalized prefixes from the sole named ``@kong path`` matcher."""
    matches = KONG_MATCHER_RE.findall(site_source)
    if len(matches) != 1:
        raise ValueError(f"kong_path_matcher_count:{len(matches)}")

    route_tokens = matches[0].split()
    if not route_tokens:
        raise ValueError("empty_kong_path_matcher")

    normalized: list[str] = []
    for token in route_tokens:
        if not token.startswith("/") or "*" in token[:-1]:
            raise ValueError(f"invalid_kong_route:{token}")
        prefix = token[:-1] if token.endswith("*") else token
        if not prefix or prefix == "/":
            raise ValueError(f"invalid_kong_route:{token}")
        normalized.append(prefix)

    if len(normalized) != len(set(normalized)):
        raise ValueError("duplicate_kong_route")
    return tuple(normalized)


def validate_exact_kong_routes(site_source: str, managed_paths: Iterable[str]) -> None:
    """Fail unless Caddy matcher routes and declared Kong paths are identical."""
    declared = tuple(managed_paths)
    if len(declared) != len(set(declared)):
        raise ValueError("duplicate_kong_managed_path")

    routed = set(routed_kong_prefixes(site_source))
    contracted = set(declared)
    uncontracted = sorted(routed - contracted)
    unrouted = sorted(contracted - routed)
    if uncontracted:
        raise ValueError(f"kong_route_not_contracted:{','.join(uncontracted)}")
    if unrouted:
        raise ValueError(f"kong_contract_not_routed:{','.join(unrouted)}")


TRUSTED_IDENTITY_HEADERS = (
    "X-Authenticated-Client",
    "X-Authenticated-Tenant",
    "X-Authenticated-Role",
    "X-Codestra-Gateway-Secret",
)
PRESERVED_EDGE_HEADERS = ("Authorization", "X-Correlation-ID", "Idempotency-Key", "traceparent", "tracestate")
HEADER_UP_RE = re.compile(r"(?m)^[ \t]*header_up[ \t]+(-?)([A-Za-z][A-Za-z0-9-]*)(?:[ \t]+([^\r\n#]*?))?[ \t]*$")


def header_up_directives(site_source: str) -> tuple[tuple[str, str], ...]:
    """Every ``header_up`` directive as (action, header): action is ``set`` or ``delete``."""
    return tuple(("delete" if minus else "set", name) for minus, name, _value in HEADER_UP_RE.findall(site_source))


REVERSE_PROXY_OPEN_RE = re.compile(r"^reverse_proxy[ \t]+\S+[ \t]*\{$")


def kong_handoff_blocks(site_source: str) -> tuple[str, ...]:
    """Return every reverse_proxy block that hands public API traffic to Kong."""
    target = "reverse_proxy {$CADDY_KONG_UPSTREAM} {"
    return _proxy_blocks(site_source, lambda opener: opener == target)


def reverse_proxy_blocks(site_source: str) -> tuple[str, ...]:
    """Return every reverse_proxy block in the site, whatever its upstream."""
    lines = [line.strip() for line in site_source.splitlines()]
    if any(line.startswith("reverse_proxy") and not REVERSE_PROXY_OPEN_RE.match(line) for line in lines):
        # A one-line reverse_proxy has no header_up block, so it cannot strip.
        raise ValueError("reverse_proxy_without_header_block")
    return _proxy_blocks(site_source, lambda opener: bool(REVERSE_PROXY_OPEN_RE.match(opener)))


def _proxy_blocks(site_source: str, selects) -> tuple[str, ...]:
    lines = site_source.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if not selects(line.strip()):
            continue
        indent = line[: len(line) - len(line.lstrip())]
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate == f"{indent}}}":
                blocks.append("\n".join(body))
                break
            body.append(candidate)
        else:
            raise ValueError("unterminated_kong_handoff_block")
    return tuple(blocks)


def validate_identity_header_boundary(site_source: str, deleted_before_kong: Iterable[str]) -> None:
    """Validate every Caddy -> Kong handoff independently.

    Exact generated routes and the broad Kong-prefix fallback are distinct
    reverse-proxy blocks. Every one must delete the contracted spoofable
    identity headers while leaving Authorization, correlation, idempotency and
    trace headers untouched.
    """
    blocks = kong_handoff_blocks(site_source)
    if not blocks:
        raise ValueError("kong_handoff_block_count:0")
    _validate_proxy_identity_blocks(site_source, blocks, deleted_before_kong)


def validate_upstream_identity_header_boundary(site_source: str, deleted_before_kong: Iterable[str]) -> None:
    """Apply the Kong handoff identity rule to every reverse_proxy in the site.

    Transitional upstreams (realtime, legacy fallback) are not behind Kong, so
    nothing downstream would overwrite a client-asserted identity header. Each
    one must delete the same contracted list the Kong handoff deletes.
    """
    blocks = reverse_proxy_blocks(site_source)
    if not blocks:
        raise ValueError("reverse_proxy_block_count:0")
    _validate_proxy_identity_blocks(site_source, blocks, deleted_before_kong)


def _validate_proxy_identity_blocks(
    site_source: str, blocks: tuple[str, ...], deleted_before_kong: Iterable[str]
) -> None:
    required_deletes = set(deleted_before_kong)
    for block in blocks:
        directives = header_up_directives(block)
        for action, name in directives:
            if action == "set" and name in TRUSTED_IDENTITY_HEADERS:
                raise ValueError(f"trusted_identity_header_set_by_caddy:{name}")
            if action == "delete" and name in PRESERVED_EDGE_HEADERS:
                raise ValueError(f"preserved_edge_header_deleted:{name}")

        deleted = {name for action, name in directives if action == "delete"}
        missing = sorted(required_deletes - deleted)
        if missing:
            raise ValueError(f"identity_header_not_deleted:{','.join(missing)}")

    for name in TRUSTED_IDENTITY_HEADERS:
        for line in site_source.splitlines():
            if name in line and line.strip() != f"header_up -{name}":
                raise ValueError(f"trusted_identity_header_in_caddy:{name}")


PRIVATE_ONLY_MATCHER_RE = re.compile(r"(?m)^[ \t]*@private_only[ \t]+path[ \t]+([^\r\n#]+?)\s*$")
PRIVATE_ONLY_HANDLE_RE = re.compile(r"(?ms)^[ \t]*handle[ \t]+@private_only[ \t]*\{\s*respond[ \t]+404\s*\}")


def private_only_paths(site_source: str) -> tuple[str, ...]:
    """Return the paths of the sole ``@private_only path`` matcher."""
    matches = PRIVATE_ONLY_MATCHER_RE.findall(site_source)
    if len(matches) != 1:
        raise ValueError(f"private_only_matcher_count:{len(matches)}")
    tokens = matches[0].split()
    if not tokens:
        raise ValueError("empty_private_only_matcher")
    for token in tokens:
        if not token.startswith("/") or "*" in token[:-1] or token in ("/", "/*"):
            raise ValueError(f"invalid_private_only_path:{token}")
    if len(tokens) != len(set(tokens)):
        raise ValueError("duplicate_private_only_path")
    return tuple(tokens)


def validate_private_only_paths(site_source: str, contracted_paths: Iterable[str]) -> None:
    """Private Middleware surfaces are answered 404 at the edge, ahead of the Kong
    handoff and the legacy fallback, and are never also routed to Kong."""
    declared = tuple(contracted_paths)
    if not declared:
        raise ValueError("missing_private_only_paths")
    if len(declared) != len(set(declared)):
        raise ValueError("duplicate_private_only_contract_path")
    routed = private_only_paths(site_source)
    if set(routed) != set(declared):
        raise ValueError(
            f"private_only_paths_mismatch:site={','.join(sorted(routed))};contract={','.join(sorted(declared))}"
        )
    handles = PRIVATE_ONLY_HANDLE_RE.findall(site_source)
    if len(handles) != 1:
        raise ValueError(f"private_only_handle_count:{len(handles)}")
    handle_at = site_source.index(handles[0])
    kong_match = KONG_MATCHER_RE.search(site_source)
    if kong_match is None or handle_at > kong_match.start():
        raise ValueError("private_only_not_before_kong_handoff")
    legacy_at = site_source.find("{$CADDY_LEGACY_API_UPSTREAM}")
    if legacy_at != -1 and handle_at > legacy_at:
        raise ValueError("private_only_not_before_legacy_fallback")
    kong_prefixes = routed_kong_prefixes(site_source)
    for path in routed:
        bare = path[:-1] if path.endswith("*") else path
        for prefix in kong_prefixes:
            if bare == prefix or bare.startswith(prefix.rstrip("/") + "/") or prefix.startswith(bare.rstrip("/") + "/"):
                raise ValueError(f"private_only_path_routed_to_kong:{path}")
