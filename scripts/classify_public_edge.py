#!/usr/bin/env python3
"""Classify every public route in Caddy's adapted JSON against the edge authorities.

The adapted document is what Caddy itself will serve, so every terminal handler
(reverse_proxy or static_response) it contains is enumerated and matched to the
committed authority that owns it:

* api.codestra.co        -> caddy-kong-contract + public-edge-registry
* automation.codestra.co -> caddy-kong-contract editorHost (Kong only)
* observability hosts    -> observability-exposure publicRoutes
* kyyow hosts            -> kyyow-ingress publicHosts
* n8n editor host        -> n8n-editor-community (oauth2-proxy only)

Any terminal that no authority explains is UNCLASSIFIED and fails the gate. The
transitional api.codestra.co unknown-route legacy fallback is reported as
UNKNOWN_ROUTE_FALLBACK; ``--require-no-fallback`` turns it into a failure and is
the PAS-177 acceptance mode.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"

API_HOST = "api.codestra.co"


class Terminal(NamedTuple):
    hosts: frozenset[str] | None
    paths: tuple[str, ...]
    path_regexp: bool
    methods: tuple[str, ...]
    source_gated: bool
    upstream: str | None
    status: int | None


class Classified(NamedTuple):
    terminal: Terminal
    host: str
    classification: str
    authority: str


def _intersect(current: frozenset[str] | None, hosts: Iterable[str] | None) -> frozenset[str] | None:
    if not hosts:
        return current
    names = frozenset(str(host).lower() for host in hosts)
    return names if current is None else current & names


def _walk(
    routes: Iterable[Mapping[str, Any]],
    hosts: frozenset[str] | None,
    paths: tuple[str, ...],
    path_regexp: bool,
    methods: tuple[str, ...],
    source_gated: bool,
    out: list[Terminal],
) -> None:
    for route in routes or ():
        for matcher in route.get("match") or [{}]:
            route_hosts = _intersect(hosts, matcher.get("host"))
            route_paths = tuple(str(p) for p in matcher.get("path") or ()) or paths
            route_regexp = path_regexp or bool(matcher.get("path_regexp"))
            if matcher.get("path_regexp"):
                route_paths = ()
            route_methods = tuple(str(m).upper() for m in matcher.get("method") or ()) or methods
            gated = source_gated or any(
                key in matcher for key in ("remote_ip", "client_ip", "not")
            )
            for handler in route.get("handle") or ():
                kind = handler.get("handler")
                if kind == "reverse_proxy":
                    dials = tuple(u.get("dial") for u in handler.get("upstreams") or ())
                    # Every pool member can receive public traffic. Classifying
                    # only the first would hide an unauthorized later target.
                    for dial in dials or (None,):
                        out.append(
                            Terminal(route_hosts, route_paths, route_regexp, route_methods, gated,
                                     dial, None)
                        )
                    break
                if kind == "static_response":
                    out.append(
                        Terminal(route_hosts, route_paths, route_regexp, route_methods, gated,
                                 None, int(handler.get("status_code", 200)))
                    )
                    break
                if handler.get("routes"):
                    _walk(handler["routes"], route_hosts, route_paths, route_regexp,
                          route_methods, gated, out)


def enumerate_terminals(document: Mapping[str, Any]) -> list[Terminal]:
    out: list[Terminal] = []
    for server in document.get("apps", {}).get("http", {}).get("servers", {}).values():
        _walk(server.get("routes") or (), None, (), False, (), False, out)
    return out


def _load(name: str) -> dict[str, Any]:
    return json.loads((CONFIG / name).read_text(encoding="utf-8"))


def load_authorities() -> dict[str, Any]:
    kong = _load("caddy-kong-contract.v1.json")
    registry = _load("public-edge-registry.v1.json")
    observability = _load("observability-exposure.v1.json")
    kyyow = _load("kyyow-ingress.v1.json")
    denied: set[str] = set(kong["privateOnlyPaths"])
    for entry in registry["entries"]:
        if entry.get("expected_public_status") == 404 and entry.get("caddy_upstream") == "NONE":
            for path in str(entry["path"]).split("|"):
                denied.add(path)
                if path.endswith("*"):
                    denied.add(path.rstrip("*").rstrip("/") + "/*")
    return {
        "kong_prefixes": tuple(kong["kongManagedPathPrefixes"]),
        "transitional_paths": frozenset(kong["transitionalPaths"]),
        "denied_paths": frozenset(denied),
        "editor_host": kong["editorHost"]["host"],
        "observability": {r["host"]: r["upstreamEnvironmentVariable"] for r in observability["publicRoutes"]},
        "kyyow": {host: spec["upstream"] for host, spec in kyyow["publicHosts"].items()},
    }


def _kong_managed(pattern: str, prefixes: Iterable[str]) -> bool:
    return any(pattern in (prefix, prefix + "*") for prefix in prefixes)


def _classify_api(terminal: Terminal, env: Mapping[str, str], auth: Mapping[str, Any]) -> tuple[str, str]:
    target = env.get(terminal.upstream or "")
    if terminal.status == 404 and terminal.paths and set(terminal.paths) <= auth["denied_paths"]:
        return "PRIVATE_OR_DENIED_404", "caddy-kong-contract.privateOnlyPaths+public-edge-registry"
    if terminal.status == 404 and not terminal.paths and not terminal.path_regexp:
        # The PAS-177 target state of edge.unknown-fallback.
        return "UNKNOWN_DENIED_404", "public-edge-registry.edge.unknown-fallback.target_state"
    if target == "CADDY_KONG_UPSTREAM":
        if terminal.path_regexp and terminal.methods:
            return "CANONICAL_CONTRACT", "middleware-public-api-route-contract"
        if terminal.paths and all(_kong_managed(p, auth["kong_prefixes"]) for p in terminal.paths):
            return "CANONICAL_KONG_MANAGED", "caddy-kong-contract.kongManagedPathPrefixes"
    if target == "CADDY_REALTIME_UPSTREAM" and terminal.paths and set(terminal.paths) <= auth["transitional_paths"]:
        return "TRANSITIONAL_APPROVED", "caddy-kong-contract.transitionalPaths"
    if target == "CADDY_LEGACY_API_UPSTREAM" and not terminal.paths and not terminal.path_regexp:
        return "UNKNOWN_ROUTE_FALLBACK", "public-edge-registry.edge.unknown-fallback"
    return "UNCLASSIFIED", "none"


def classify(
    terminals: Iterable[Terminal],
    env: Mapping[str, str],
    auth: Mapping[str, Any],
    n8n_editor_host: str,
) -> list[Classified]:
    """``env`` maps each placeholder dial used for adaptation to its env name."""
    results: list[Classified] = []
    for terminal in terminals:
        if terminal.hosts is not None and not terminal.hosts:
            # Ancestor host matchers are disjoint; Caddy can never select it.
            results.append(Classified(terminal, "-", "UNREACHABLE", "host-intersection-empty"))
            continue
        for host in sorted(terminal.hosts or {"*"}):
            target = env.get(terminal.upstream or "")
            if terminal.upstream is not None and target is None:
                results.append(Classified(terminal, host, "UNCLASSIFIED_UPSTREAM", "none"))
                continue
            if host == API_HOST:
                label, authority = _classify_api(terminal, env, auth)
            elif host == auth["editor_host"]:
                ok = target == "CADDY_KONG_UPSTREAM" or (terminal.status == 404 and terminal.source_gated)
                label, authority = ("ADMIN_KONG_GATED", "caddy-kong-contract.editorHost") if ok else ("UNCLASSIFIED", "none")
            elif host in auth["observability"]:
                ok = target == auth["observability"][host] or terminal.status in (403, 404)
                label, authority = ("OBSERVABILITY_PUBLIC", "observability-exposure.publicRoutes") if ok else ("UNCLASSIFIED", "none")
            elif host in auth["kyyow"]:
                ok = target == auth["kyyow"][host] or terminal.status == 404
                label, authority = ("KYYOW_PUBLIC", "kyyow-ingress.publicHosts") if ok else ("UNCLASSIFIED", "none")
            elif host == n8n_editor_host.lower():
                ok = target == "CADDY_N8N_OAUTH2_PROXY_UPSTREAM" or terminal.status == 404
                label, authority = ("N8N_EDITOR_OAUTH2", "n8n-editor-community") if ok else ("UNCLASSIFIED", "none")
            else:
                label, authority = "UNCLASSIFIED", "none"
            results.append(Classified(terminal, host, label, authority))
    return results


def summarize(results: Iterable[Classified], env: Mapping[str, str]) -> dict[str, int]:
    results = list(results)
    legacy = [r for r in results if env.get(r.terminal.upstream or "") == "CADDY_LEGACY_API_UPSTREAM"]
    return {
        "PUBLIC_TERMINAL_ROUTES": len(results),
        "UNKNOWN_ROUTE_FALLBACK": sum(r.classification == "UNKNOWN_ROUTE_FALLBACK" for r in results),
        "LEGACY_API_FALLBACK": len(legacy),
        "UNCLASSIFIED_PUBLIC_ROUTES": sum(r.classification == "UNCLASSIFIED" for r in results),
        "UNCLASSIFIED_UPSTREAMS": sum(r.classification == "UNCLASSIFIED_UPSTREAM" for r in results),
        "UNREACHABLE_ROUTES": sum(r.classification == "UNREACHABLE" for r in results),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("adapted_json", type=Path)
    parser.add_argument(
        "--upstream", action="append", default=[], metavar="ENV=DIAL",
        help="placeholder dial used for an upstream env var during adaptation",
    )
    parser.add_argument("--n8n-editor-host", required=True)
    parser.add_argument("--require-no-fallback", action="store_true",
                        help="PAS-177 acceptance: fail while any legacy fallback remains")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    env = {}
    for item in args.upstream:
        name, _, dial = item.partition("=")
        if not name or not dial:
            parser.error(f"invalid --upstream {item!r}")
        env[dial] = name
    document = json.loads(args.adapted_json.read_text(encoding="utf-8"))
    results = classify(enumerate_terminals(document), env, load_authorities(), args.n8n_editor_host)
    summary = summarize(results, env)

    for result in results:
        if args.verbose or result.classification.startswith("UNCLASSIFIED"):
            t = result.terminal
            where = ",".join(t.paths) or ("<regexp>" if t.path_regexp else "<any>")
            target = env.get(t.upstream or "", t.upstream) if t.upstream else f"static:{t.status}"
            print(f"{result.classification} host={result.host} path={where} "
                  f"methods={','.join(t.methods) or 'ANY'} target={target} authority={result.authority}")
    for key, value in summary.items():
        print(f"{key}={value}")

    failed = summary["UNCLASSIFIED_PUBLIC_ROUTES"] or summary["UNCLASSIFIED_UPSTREAMS"]
    if args.require_no_fallback:
        failed = failed or summary["UNKNOWN_ROUTE_FALLBACK"] or summary["LEGACY_API_FALLBACK"]
    print("CADDY_PUBLIC_EDGE_CLASSIFICATION=" + ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
