"""Read-only Caddy source review for Mission Control's Kong-owned endpoints."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CADDY=(ROOT/"config/sites/api.codestra.co.caddy").read_text()
CONTRACT=json.loads((ROOT/"config/staging/caddy-mission-control-dashboard.staging.json").read_text())


class DashboardEdgeTests(unittest.TestCase):
    def test_generic_platform_edge_forwards_to_kong(self):
        self.assertIn("@mission_dashboard",CADDY)
        self.assertIn("method GET",CADDY)
        self.assertIn("/platform/v1/dashboard/contract",CADDY)
        self.assertIn("handle @mission_dashboard",CADDY)
        self.assertIn("reverse_proxy {$CADDY_KONG_UPSTREAM}",CADDY)
        self.assertEqual(CONTRACT["gateway"],"Kong")
        self.assertFalse(CONTRACT["production_go"])
        self.assertFalse(CONTRACT["runtime_apply_authorized"])

    def test_client_cannot_assert_identity(self):
        for name in ["X-User-ID","X-Authenticated-Client","X-Authenticated-Tenant",
                     "X-Codestra-Gateway-Secret"]:
            self.assertIn("header_up -"+name,CADDY)
        self.assertNotIn("header_up -Authorization",CADDY)
        self.assertTrue(CONTRACT["backend_rechecks_keycloak"])

    def test_private_paths_denied(self):
        self.assertNotIn("path /metrics",CADDY)
        self.assertNotIn("path /internal",CADDY)
        self.assertIn("respond \"Not Found\" 404",CADDY)

if __name__=="__main__":
    unittest.main()
