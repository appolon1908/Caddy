#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

from caddy_kong_contract import (
    header_up_directives,
    kong_forwards,
    private_only_paths,
    validate_exact_kong_routes,
    validate_identity_header_boundary,
    validate_private_only_paths,
    validate_upstream_identity_header_boundary,
)

ROOT = Path(__file__).resolve().parents[1]


class CaddyKongContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.site = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
        self.contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )

    def test_caddy_and_kong_route_contract_is_bidirectional(self) -> None:
        validate_exact_kong_routes(self.site, self.contract)

    def test_uncontracted_caddy_route_is_rejected(self) -> None:
        modified = self.site.replace("path_regexp ^/v1/crm(/.*)?$", "path_regexp ^/v1/(/.*)?$")
        self.assertNotEqual(modified, self.site)
        with self.assertRaisesRegex(ValueError, "kong_route_not_contracted:kong_owned_"):
            validate_exact_kong_routes(modified, self.contract)

    def test_unrouted_contract_path_is_rejected(self) -> None:
        declared = json.loads(json.dumps(self.contract))
        declared["kongOwnedRoutes"].append({"kongRoute": "declared-only", "match": "exact", "methods": ["GET"],
                                            "path": "/v1/declared-only"})
        with self.assertRaisesRegex(ValueError, "kong_contract_not_routed:kong_owned_"):
            validate_exact_kong_routes(self.site, declared)

    def test_prefix_fallback_is_rejected(self) -> None:
        fallback = "\t\t@kong path /platform/v1*\n\t\thandle @kong {\n\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM} {\n\t\t\t}\n\t\t}\n"
        mutated = self.site.replace("\t\t# Unknown public API paths fail closed.", fallback + "\t\t# Unknown public API paths fail closed.")
        self.assertNotEqual(mutated, self.site)
        with self.assertRaisesRegex(ValueError, "kong_route_without_exact_matcher:kong"):
            validate_exact_kong_routes(mutated, self.contract)


class IdentityHeaderBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.site = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
        contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )
        self.deleted = contract["identityHeaders"]["deletedBeforeKong"]
        self.preserved = contract["identityHeaders"]["preservedToKong"]

    def test_site_deletes_every_contracted_identity_header_and_sets_none(self) -> None:
        validate_identity_header_boundary(self.site, self.deleted)
        directives = header_up_directives(self.site)
        self.assertEqual({name for action, name in directives if action == "set"}, {"Host", "X-Real-IP"})
        self.assertTrue(set(self.deleted) <= {name for action, name in directives if action == "delete"})
        self.assertFalse(set(self.preserved) & {name for action, name in directives if action == "delete"})

    def test_setting_a_trusted_identity_header_is_rejected(self) -> None:
        mutated = self.site.replace(
            "header_up X-Real-IP {remote_host}",
            "header_up X-Real-IP {remote_host}\n\t\t\t\theader_up X-Authenticated-Tenant tenant-a",
            1,
        )
        with self.assertRaises(ValueError) as caught:
            validate_identity_header_boundary(mutated, self.deleted)
        self.assertEqual(str(caught.exception), "trusted_identity_header_set_by_caddy:X-Authenticated-Tenant")

    def test_deleting_a_preserved_edge_header_is_rejected(self) -> None:
        mutated = self.site.replace("header_up -X-User-ID", "header_up -Idempotency-Key", 1)
        with self.assertRaises(ValueError) as caught:
            validate_identity_header_boundary(mutated, [h for h in self.deleted if h != "X-User-ID"])
        self.assertEqual(str(caught.exception), "preserved_edge_header_deleted:Idempotency-Key")

    def test_dropping_a_contracted_deletion_is_rejected(self) -> None:
        mutated = self.site.replace("\t\t\t\theader_up -X-Authenticated-Client\n", "", 1)
        with self.assertRaises(ValueError) as caught:
            validate_identity_header_boundary(mutated, self.deleted)
        self.assertEqual(str(caught.exception), "identity_header_not_deleted:X-Authenticated-Client")

    def test_contract_routes_reach_kong_and_closed_routes_do_not(self) -> None:
        contract = json.loads((ROOT / "config" / "middleware-public-api-route-contract.v1.json").read_text(encoding="utf-8"))
        for row in contract["routes"]:
            path = "/".join("probe-1" if part.startswith("{") else part for part in row["path"].split("/"))
            with self.subTest(route=f"{row['method']} {row['path']}"):
                self.assertEqual(kong_forwards(self.site, row["method"], path), row["classification"] == "shared_edge")
        for method, path in (("GET", "/platform/v1/kernel/describe/extra"), ("DELETE", "/platform/v1/commands"),
                             ("GET", "/v2/automation/unknown"), ("GET", "/api/v1/odoo/anything")):
            self.assertFalse(kong_forwards(self.site, method, path), path)


class PrivateOnlyPathTests(unittest.TestCase):
    """/metrics and /internal/* are answered 404 at the edge before any upstream."""

    def setUp(self) -> None:
        self.site = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
        contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )
        self.private = contract["privateOnlyPaths"]
        self.block = "\t\t@private_only path /metrics /metrics/* /internal /internal/*\n\t\thandle @private_only {\n\t\t\trespond 404\n\t\t}\n"

    def test_site_denies_the_contracted_private_paths_ahead_of_every_upstream(self) -> None:
        validate_private_only_paths(self.site, self.private)
        self.assertEqual(set(private_only_paths(self.site)), {"/metrics", "/metrics/*", "/internal", "/internal/*"})
        deny_at = self.site.index("handle @private_only")
        self.assertLess(deny_at, self.site.index("{$CADDY_KONG_UPSTREAM}"))
        self.assertLess(deny_at, self.site.index("{$CADDY_REALTIME_UPSTREAM}"))
        self.assertNotIn("{$CADDY_LEGACY_API_UPSTREAM}", self.site)

    def test_private_paths_are_not_kong_routed(self) -> None:
        for path in ("/metrics", "/metrics/x", "/internal", "/internal/x"):
            for method in ("GET", "POST"):
                self.assertFalse(kong_forwards(self.site, method, path), path)

    def test_missing_deny_is_rejected(self) -> None:
        mutated = self.site.replace("@private_only path /metrics /metrics/* /internal /internal/*", "@private_only path /internal/*")
        with self.assertRaisesRegex(ValueError, "private_only_paths_mismatch"):
            validate_private_only_paths(mutated, self.private)
        removed = self.site.replace(self.block, "")
        self.assertNotIn("@private_only", removed)
        with self.assertRaisesRegex(ValueError, "private_only_matcher_count:0"):
            validate_private_only_paths(removed, self.private)

    def test_deny_after_the_kong_handoff_is_rejected(self) -> None:
        self.assertIn(self.block, self.site)
        moved = self.site.replace(self.block, "")
        fail_closed = "\t\thandle {\n\t\t\trespond 404\n\t\t}"
        self.assertIn(fail_closed, moved)
        moved = moved.replace(fail_closed, self.block + fail_closed)
        with self.assertRaisesRegex(ValueError, "private_only_not_before_kong_handoff"):
            validate_private_only_paths(moved, self.private)

    def test_private_path_also_routed_to_kong_is_rejected(self) -> None:
        mutated = self.site.replace("path_regexp ^/v1/crm(/.*)?$", "path_regexp ^(/v1/crm(/.*)?|/metrics)$")
        self.assertNotEqual(mutated, self.site)
        with self.assertRaisesRegex(ValueError, "private_only_path_routed_to_kong:/metrics"):
            validate_private_only_paths(mutated, self.private)

    def test_deny_that_proxies_instead_of_responding_is_rejected(self) -> None:
        mutated = self.site.replace("\t\thandle @private_only {\n\t\t\trespond 404\n\t\t}", "\t\thandle @private_only {\n\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}\n\t\t}")
        with self.assertRaisesRegex(ValueError, "private_only_handle_count:0"):
            validate_private_only_paths(mutated, self.private)


class UpstreamIdentityHeaderBoundaryTests(unittest.TestCase):
    """Client identity never reaches any upstream of a Kong-fronted host."""

    def setUp(self) -> None:
        self.sites = {
            name: (ROOT / "sites" / name).read_text(encoding="utf-8")
            for name in ("api.codestra.co.caddy", "automation.codestra.co.caddy")
        }
        contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )
        self.deleted = contract["identityHeaders"]["deletedBeforeKong"]

    @staticmethod
    def unstripped(site: str, upstream: str) -> str:
        # Reproduce the pre-fix shape: the proxy keeps Host/X-Real-IP only.
        lines = site.split("\n")
        start = next(i for i, line in enumerate(lines) if line.strip() == f"reverse_proxy {{${upstream}}} {{")
        closer = lines[start][: len(lines[start]) - len(lines[start].lstrip())] + "}"
        end = lines.index(closer, start)
        body = [line for line in lines[start + 1 : end] if "header_up -" not in line and "#" not in line]
        return "\n".join(lines[: start + 1] + body + lines[end:])

    def test_every_upstream_of_kong_fronted_hosts_deletes_client_identity(self) -> None:
        for name, site in self.sites.items():
            with self.subTest(site=name):
                validate_upstream_identity_header_boundary(site, self.deleted)

    def test_realtime_and_reintroduced_legacy_proxy_strip_admin_and_user_headers(self) -> None:
        api = self.sites["api.codestra.co.caddy"]
        for upstream in ("CADDY_REALTIME_UPSTREAM", "CADDY_LEGACY_API_UPSTREAM"):
            with self.subTest(upstream=upstream):
                if upstream == "CADDY_LEGACY_API_UPSTREAM":
                    self.assertNotIn("CADDY_LEGACY_API_UPSTREAM", api)
                    # Retain the TLS lane's regression check for a reintroduced proxy,
                    # without requiring the retired fallback in the live authority.
                    mutated = api + "\nlegacy.invalid {\n\treverse_proxy {$CADDY_LEGACY_API_UPSTREAM} {\n\t\theader_up Host {host}\n\t}\n}\n"
                else:
                    mutated = self.unstripped(api, upstream)
                self.assertNotEqual(mutated, api)
                # The Kong-only check cannot see this regression; the upstream check must.
                validate_identity_header_boundary(mutated, self.deleted)
                with self.assertRaisesRegex(ValueError, "identity_header_not_deleted:.*X-Admin.*X-User-ID"):
                    validate_upstream_identity_header_boundary(mutated, self.deleted)

    def test_automation_kong_handoff_without_strip_is_rejected(self) -> None:
        mutated = self.unstripped(self.sites["automation.codestra.co.caddy"], "CADDY_KONG_UPSTREAM")
        with self.assertRaisesRegex(ValueError, "identity_header_not_deleted:.*X-Authenticated-UserID"):
            validate_upstream_identity_header_boundary(mutated, self.deleted)

    def test_single_line_reverse_proxy_is_rejected(self) -> None:
        mutated = self.sites["api.codestra.co.caddy"] + "\nexample.invalid {\n\treverse_proxy 127.0.0.1:9\n}\n"
        with self.assertRaisesRegex(ValueError, "reverse_proxy_without_header_block"):
            validate_upstream_identity_header_boundary(mutated, self.deleted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
