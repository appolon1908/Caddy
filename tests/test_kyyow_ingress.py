import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class KyyowIngressTests(unittest.TestCase):
    def test_contract_has_exact_public_host_family(self):
        contract = json.loads((ROOT / "config/kyyow-ingress.v1.json").read_text())
        self.assertEqual(set(contract["publicHosts"]), {
            "app.kyyow.com", "api.kyyow.com", "search.kyyow.com",
            "docs.kyyow.com", "auth.kyyow.com", "status.kyyow.com"
        })

    def test_validator_passes(self):
        result = subprocess.run(
            [sys.executable, "scripts/validate_kyyow_ingress.py"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KYYOW_INGRESS_CONTRACT=PASS", result.stdout)

if __name__ == "__main__":
    unittest.main()

class PerHostIdentityTests(unittest.TestCase):
    def test_each_host_requires_each_identity_header_removal(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('ingress', ROOT / 'scripts/validate_kyyow_ingress.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        contract = json.loads((ROOT / 'config/kyyow-ingress.v1.json').read_text())
        site = (ROOT / 'sites/kyyow.com.caddy').read_text()
        runtime = (ROOT / 'config/runtime-values.example').read_text()
        for host in module.PUBLIC_HOSTS:
            for header in module.IDENTITY_HEADERS:
                with self.subTest(host=host, header=header):
                    before, block = site.split(host + ' {', 1)
                    changed = before + host + ' {' + block.replace('\trequest_header -' + header + '\n', '', 1)
                    with self.assertRaises(ValueError):
                        module.validate(contract, changed, runtime)
