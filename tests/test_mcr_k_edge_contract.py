"""Offline MCR-K conformance tests; no runtime certification is implied."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mcr_k', ROOT / 'contracts/mcr-k/validate.py')
mcr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mcr)


class McrKEdgeTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((ROOT / 'contracts/mcr-k/edge.v1.json').read_text())
        self.evidence = json.loads((ROOT / 'contracts/mcr-k/evidence.blocked.v1.json').read_text())

    def test_contract_and_blocked_evidence_are_valid_offline(self):
        mcr.validate_contract(self.contract)
        mcr.validate_evidence(self.evidence)
        self.assertFalse(mcr.ready(self.evidence))

    def test_denials_precede_every_handoff_for_every_method(self):
        for path in ['/internal', '/internal/', '/internal/v1/database/health',
                     '/metrics', '/metrics/runtime', '/private/example']:
            for method in ['GET', 'HEAD', 'OPTIONS', 'POST', 'DELETE']:
                with self.subTest(path=path, method=method):
                    self.assertEqual(mcr.expected_edge(self.contract, path, method,
                        private_only=path.startswith('/private')), 'edge-404')

    def test_mcr_routes_and_wrong_methods_never_use_legacy(self):
        for path in ['/platform/v1/leads/demo/journey',
                     '/platform/v1/leads/demo/next-action', '/platform/v1/unknown']:
            for method in ['GET', 'POST', 'DELETE', 'OPTIONS']:
                self.assertEqual(mcr.expected_edge(self.contract, path, method), 'kong-only')
        self.assertEqual(mcr.expected_edge(self.contract, '/platform/v10/test', 'GET'), 'out-of-scope')

    def test_unsafe_contract_mutations_are_rejected(self):
        mutations = [
            ('deny', ['/internal/*', '/metrics', '/metrics/*']),
            ('upstream', 'middleware:8095'), ('fallback', True),
            ('preserve', ['authorization']), ('strip', []),
            ('forwarded', ['forwarded']), ('redact', []),
            ('live_apply_authorized', True), ('private_only', 'kong-only')]
        for field, value in mutations:
            with self.subTest(field=field):
                bad = copy.deepcopy(self.contract)
                bad[field] = value
                with self.assertRaises(ValueError):
                    mcr.validate_contract(bad)

    def test_observations_detect_bypass_header_loss_spoofing_and_redaction(self):
        observation = {'edge': 'kong-only', 'upstream': 'CADDY_KONG_UPSTREAM',
            'preserved': self.contract['preserve'], 'client_headers_survived': [],
            'redaction_pass': True, 'kong_failure_bypassed': False}
        mcr.validate_observation(self.contract, '/platform/v1/leads/demo/journey', 'GET', observation)
        for field, value in [('edge', 'legacy'), ('upstream', 'odoo:8069'),
                             ('preserved', []), ('client_headers_survived', ['X-Authenticated-Tenant']),
                             ('client_headers_survived', ['fOrWaRdEd']),
                             ('redaction_pass', False), ('kong_failure_bypassed', True)]:
            bad = dict(observation, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                mcr.validate_observation(self.contract, '/platform/v1/leads/demo/journey', 'GET', bad)
        with self.assertRaises(ValueError):
            mcr.validate_observation(self.contract, '/internal', 'GET', observation)

    def test_kong_required_mcr_headers_survive_and_gateway_secret_does_not(self):
        headers = ['X-Tenant-ID', 'X-Correlation-ID', 'Idempotency-Key', 'X-Codestra-Event-ID',
                   'X-Codestra-Timestamp', 'X-Codestra-Signature']
        observation = {'edge': 'kong-only', 'upstream': 'CADDY_KONG_UPSTREAM',
            'preserved': self.contract['preserve'], 'client_headers_survived': headers,
            'redaction_pass': True, 'kong_failure_bypassed': False}
        mcr.validate_observation(self.contract, '/platform/v1/delivery-events', 'POST', observation)
        for spoofed in ['X-Codestra-Gateway-Secret', 'X-Codestra-Tenant', 'X-Codestra-Scopes']:
            bad = dict(observation, client_headers_survived=headers + [spoofed])
            with self.subTest(spoofed=spoofed), self.assertRaises(ValueError):
                mcr.validate_observation(self.contract, '/platform/v1/delivery-events', 'POST', bad)
        bad = copy.deepcopy(self.contract)
        bad['strip'] = bad['strip'] + ['x-codestra-*']
        with self.assertRaises(ValueError):
            mcr.validate_contract(bad)

    def test_caddy_kong_handoff_matches_normative_header_policy(self):
        site = (ROOT / 'sites/api.codestra.co.caddy').read_text(encoding='utf-8')
        start = site.index('@kong path')
        block = site[start:site.index('# Transitional compatibility', start)].lower()
        for name in self.contract['preserve']:
            self.assertNotIn('header_up -' + name + '\n', block)
        for name in self.contract['strip']:
            if not name.endswith('*'):
                self.assertIn('header_up -' + name + '\n', block)

    def test_evidence_rejects_missing_fields_unknown_statuses_and_secrets(self):
        for field in list(self.evidence):
            bad = copy.deepcopy(self.evidence)
            del bad[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                mcr.validate_evidence(bad)
        for field, value in [('status', 'PASS'), ('authorization', 'Bearer fake'),
                             ('source_sha', 'latest'), ('captured_at', 'yesterday')]:
            bad = dict(self.evidence, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                mcr.validate_evidence(bad)

    def test_pass_requires_all_gates_readback_and_rollback_identity(self):
        evidence = copy.deepcopy(self.evidence)
        evidence['status'] = 'PASS'
        evidence['environment'] = 'staging'
        with self.assertRaises(ValueError):
            mcr.validate_evidence(evidence)
        evidence['blockers'] = []
        for gate in evidence['gates']:
            evidence['gates'][gate] = {'status': 'PASS', 'artifact_sha256': 'c' * 64}
        evidence['candidate_sha256'] = evidence['readback_sha256'] = 'a' * 64
        evidence['previous_sha256'] = evidence['rollback_readback_sha256'] = 'b' * 64
        offline = copy.deepcopy(evidence)
        offline['environment'] = 'offline'
        with self.assertRaisesRegex(ValueError, 'PASS requires runtime environment'):
            mcr.validate_evidence(offline)
        mcr.validate_evidence(evidence)
        self.assertTrue(mcr.ready(evidence))
        for field in ['readback_sha256', 'rollback_readback_sha256']:
            bad = dict(evidence, **{field: 'd' * 64})
            with self.subTest(field=field), self.assertRaises(ValueError):
                mcr.validate_evidence(bad)
        for gate in evidence['gates']:
            bad = copy.deepcopy(evidence)
            bad['gates'][gate]['status'] = 'BLOCKED'
            with self.subTest(gate=gate), self.assertRaises(ValueError):
                mcr.validate_evidence(bad)


if __name__ == '__main__':
    unittest.main()
