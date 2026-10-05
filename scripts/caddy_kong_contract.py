#!/usr/bin/env python3
"""Validate the exact Caddy-to-Kong route ownership boundary."""

from __future__ import annotations

import re
from collections.abc import Iterable

MATCHER_RE = re.compile(
    r"(?ms)^[ \t]*@([a-z0-9_]+)[ \t]*\{\s*method[ \t]+([A-Z ]+?)\s*\n\s*path_regexp[ \t]+(\S+)\s*\}"
)
HANDLE_RE = re.compile(r"(?ms)^([ \t]*)handle[ \t]+@([a-z0-9_]+)[ \t]*\{\n(.*?)^\1\}")
KONG_TARGET = "reverse_proxy {$CADDY_KONG_UPSTREAM} {"


def kong_route_matchers(site_source: str) -> dict[str, tuple[frozenset[str], str]]:
    """Every matcher whose handle hands traffic to Kong, as (methods, path regex)."""
    matchers = {name: (frozenset(methods.split()), regex) for name, methods, regex in MATCHER_RE.findall(site_source)}
    routed: dict[str, tuple[frozenset[str], str]] = {}
    for _indent, name, body in HANDLE_RE.findall(site_source):
        if KONG_TARGET not in body:
            continue
        if name not in matchers:
            raise ValueError(f"kong_route_without_exact_matcher:{name}")
        routed[name] = matchers[name]
    if not routed:
        raise ValueError("kong_route_count:0")
    return routed


def expected_kong_matchers(authority: dict) -> dict[str, tuple[frozenset[str], str]]:
    from caddy_route_compiler import _kong_owned_regex, route_regex

    expected: dict[str, tuple[frozenset[str], str]] = {}
    shared = authority["serviceJwtRouteContract"]["routes"]
    for method in sorted({row["method"] for row in shared}):
        regex = "^(" + "|".join(sorted(route_regex(r["path"]) for r in shared if r["method"] == method)) + ")$"
        expected[f"canonical_{method.lower()}"] = (frozenset({method}), regex)
    for index, row in enumerate(authority["kongOwnedRoutes"]):
        expected[f"kong_owned_{index:02d}"] = (frozenset(row["methods"]), _kong_owned_regex(row))
    return expected


def validate_exact_kong_routes(site_source: str, authority: dict) -> None:
    """Fail unless every Kong handoff is exactly a contract or Kong-owned route."""
    routed = kong_route_matchers(site_source)
    expected = expected_kong_matchers(authority)
    uncontracted = sorted(name for name in routed if routed[name] != expected.get(name))
    unrouted = sorted(name for name in expected if name not in routed)
    if uncontracted:
        raise ValueError(f"kong_route_not_contracted:{','.join(uncontracted)}")
    if unrouted:
        raise ValueError(f"kong_contract_not_routed:{','.join(unrouted)}")


def kong_forwards(site_source: str, method: str, path: str) -> bool:
    return any(method in methods and re.match(regex, path) for methods, regex in kong_route_matchers(site_source).values())


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
    """Private Middleware surfaces are answered 404 at the edge, ahead of every
    upstream, and no Kong matcher can select them."""
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
    first_upstream = min((at for at in (site_source.find("{$CADDY_KONG_UPSTREAM}"),
                                        site_source.find("{$CADDY_REALTIME_UPSTREAM}"),
                                        site_source.find("{$CADDY_LEGACY_API_UPSTREAM}")) if at != -1), default=-1)
    if first_upstream == -1 or handle_at > first_upstream:
        raise ValueError("private_only_not_before_kong_handoff")
    for path in routed:
        probe = path[:-1] + "probe" if path.endswith("*") else path
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            if kong_forwards(site_source, method, probe):
                raise ValueError(f"private_only_path_routed_to_kong:{path}")
