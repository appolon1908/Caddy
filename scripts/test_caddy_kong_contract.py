#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

from caddy_kong_contract import (
    header_up_directives,
    private_only_paths,
    routed_kong_prefixes,
    validate_exact_kong_routes,
    validate_identity_header_boundary,
    validate_private_only_paths,
)

ROOT = Path(__file__).resolve().parents[1]


class CaddyKongContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.site = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
        contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )
        self.managed_paths = contract["kongManagedPathPrefixes"]

    def test_caddy_and_kong_route_contract_is_bidirectional(self) -> None:
        validate_exact_kong_routes(self.site, self.managed_paths)

    def test_uncontracted_caddy_route_is_rejected(self) -> None:
        modified = self.site.replace("/v1/intake*", "/v1/intake* /v1/unmanaged*")
        with self.assertRaisesRegex(ValueError, "kong_route_not_contracted:/v1/unmanaged"):
            validate_exact_kong_routes(modified, self.managed_paths)

    def test_unrouted_contract_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "kong_contract_not_routed:/v1/declared-only"):
            validate_exact_kong_routes(self.site, [*self.managed_paths, "/v1/declared-only"])




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

    def test_every_kong_owned_contract_path_is_routed_to_kong(self) -> None:
        prefixes = routed_kong_prefixes(self.site)
        for path in (
            "/api/v1/automation/policy-check",
            "/api/v1/callbacks",
            "/api/v1/control/callbacks",
            "/api/v1/integration/campaign-actions",
            "/api/v1/integrations/n8n/results",
            "/api/v1/integrations/n8n/results/evt-1",
            "/api/v1/integrations/odoo/campaigns/c-1/desired-state",
            "/api/v1/integrations/odoo/campaign-commands",
            "/api/v1/odoo/events",
            "/api/v1/odoo/campaign-actions",
            "/platform/v1/agent-provisioning/requests",
            "/platform/v1/commands",
            "/v2/automation/jobs/claim",
            "/v1/integrations/n8n/commands",
        ):
            self.assertTrue(any(path == p or path.startswith(p) for p in prefixes), path)


class PrivateOnlyPathTests(unittest.TestCase):
    """/metrics and both /internal forms are answered 404 before any upstream."""

    def setUp(self) -> None:
        self.site = (ROOT / "sites" / "api.codestra.co.caddy").read_text(encoding="utf-8")
        contract = json.loads(
            (ROOT / "config" / "caddy-kong-contract.v1.json").read_text(encoding="utf-8")
        )
        self.private = contract["privateOnlyPaths"]
        self.managed = contract["kongManagedPathPrefixes"]

    def test_site_denies_the_contracted_private_paths_ahead_of_every_upstream(self) -> None:
        validate_private_only_paths(self.site, self.private)
        self.assertEqual(set(private_only_paths(self.site)), {"/metrics", "/metrics/*", "/internal", "/internal/*"})
        deny_at = self.site.index("handle @private_only")
        self.assertLess(deny_at, self.site.index("@kong path"))
        self.assertLess(deny_at, self.site.index("{$CADDY_KONG_UPSTREAM}"))
        self.assertLess(deny_at, self.site.index("{$CADDY_REALTIME_UPSTREAM}"))
        self.assertNotIn("{$CADDY_LEGACY_API_UPSTREAM}", self.site)

    def test_private_paths_are_not_kong_managed(self) -> None:
        for path in self.private:
            bare = path[:-1] if path.endswith("*") else path
            self.assertFalse(any(bare == p or bare.startswith(p + "/") for p in self.managed), path)

    def test_missing_deny_is_rejected(self) -> None:
        mutated = self.site.replace("@private_only path /metrics /metrics/* /internal /internal/*", "@private_only path /internal/*")
        with self.assertRaisesRegex(ValueError, "private_only_paths_mismatch"):
            validate_private_only_paths(mutated, self.private)
        removed = self.site.replace("\t\t@private_only path /metrics /metrics/* /internal /internal/*\n\t\thandle @private_only {\n\t\t\trespond 404\n\t\t}\n", "")
        self.assertNotIn("@private_only", removed)
        with self.assertRaisesRegex(ValueError, "private_only_matcher_count:0"):
            validate_private_only_paths(removed, self.private)

    def test_deny_after_the_kong_handoff_is_rejected(self) -> None:
        block = "\t\t@private_only path /metrics /metrics/* /internal /internal/*\n\t\thandle @private_only {\n\t\t\trespond 404\n\t\t}\n"
        self.assertIn(block, self.site)
        moved = self.site.replace(block, "")
        fail_closed = "\t\thandle {\n\t\t\trespond 404\n\t\t}"
        self.assertIn(fail_closed, moved)
        moved = moved.replace(fail_closed, block + fail_closed)
        with self.assertRaisesRegex(ValueError, "private_only_not_before_kong_handoff"):
            validate_private_only_paths(moved, self.private)

    def test_private_path_also_routed_to_kong_is_rejected(self) -> None:
        mutated = self.site.replace("/v1/intake*", "/v1/intake* /metrics")
        with self.assertRaisesRegex(ValueError, "private_only_path_routed_to_kong:/metrics"):
            validate_private_only_paths(mutated, self.private)

    def test_deny_that_proxies_instead_of_responding_is_rejected(self) -> None:
        mutated = self.site.replace("\t\thandle @private_only {\n\t\t\trespond 404\n\t\t}", "\t\thandle @private_only {\n\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}\n\t\t}")
        with self.assertRaisesRegex(ValueError, "private_only_handle_count:0"):
            validate_private_only_paths(mutated, self.private)


if __name__ == "__main__":
    unittest.main(verbosity=2)
