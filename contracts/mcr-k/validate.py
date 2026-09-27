#!/usr/bin/env python3
"""MCR-K normative contract/evidence validator. Standard library; no I/O to services."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
# PRESERVE mirrors Kong's MCR headerPolicy.doNotStrip (Kong:config/kong-mcr-routes.v1.json):
# Kong requires X-Tenant-ID on every MCR route and the X-Codestra-Event-ID/Timestamp/
# Signature triple on /platform/v1/delivery-events, so the edge must not strip them.
PRESERVE = ['authorization', 'idempotency-key', 'x-correlation-id', 'traceparent', 'tracestate',
            'x-tenant-id', 'x-causation-id', 'x-codestra-event-id', 'x-codestra-timestamp',
            'x-codestra-signature']
STRIP = ['x-user-id', 'x-username', 'x-email', 'x-roles', 'x-scopes',
         'x-authenticated-*', 'x-codestra-tenant', 'x-codestra-scopes',
         'x-codestra-gateway-secret', 'x-internal-service', 'x-admin',
         'x-consumer-*', 'x-credential-identifier', 'x-anonymous-consumer']
FORWARDED = ['forwarded', 'x-forwarded-*', 'x-real-ip']
REDACT = ['authorization', 'proxy-authorization', 'cookie', 'set-cookie',
          'access_token', 'refresh_token', 'id_token', 'password', 'secret',
          'client_secret', 'api_key', 'token', 'code', 'state', 'session_state',
          'request_body', 'response_body', 'query_string']
GATES = {'pas141', 'route_inventory', 'denials', 'kong_only', 'headers', 'redaction',
         'candidate_validation', 'pre_health', 'reload', 'readback', 'post_health',
         'rollback', 'rollback_readback', 'rollback_health'}
BLOCKERS = {'PAS141_PENDING', 'BARE_INTERNAL_UNPROVEN', 'FORWARDED_STRIPPING_UNPROVEN',
            'MCR_ROUTE_INVENTORY_UNPINNED', 'REDACTION_UNPROVEN', 'RUNTIME_NOT_EXECUTED'}
NORMATIVE = {
    'schema': 'codestra.mcr-k.edge.v1', 'phase': 'post-PAS-141-intent',
    'host': 'api.codestra.co', 'deny': ['/internal', '/internal/*', '/metrics', '/metrics/*'],
    'private_only': 'edge-404', 'mcr_prefixes': ['/platform/v1'],
    'upstream': 'CADDY_KONG_UPSTREAM', 'fallback': False,
    'preserve': PRESERVE, 'strip': STRIP, 'forwarded': FORWARDED,
    'redact': REDACT, 'live_apply_authorized': False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_contract(contract):
    # Versioned normative policy: changes require explicit version review.
    require(contract == NORMATIVE, 'MCR-K v1 policy mismatch')
    for name in contract['preserve']:
        require(not any(matches(name, p) for p in contract['strip'] + contract['forwarded']),
                'preserved header is also stripped: ' + name)


def matches(value, pattern):
    return value.startswith(pattern[:-1]) if pattern.endswith('*') else value == pattern


def expected_edge(contract, path, method, *, private_only=False):
    """Reference expectation, NOT a Caddy parser or deployed request router.

    path is the decoded canonical path (no query). Upstream normalization and
    encoded-path equivalence must be proven by the runtime denials gate.
    """
    validate_contract(contract)
    require(isinstance(path, str) and path.startswith('/') and '?' not in path, 'canonical path required')
    require(isinstance(method, str) and bool(method), 'method required')
    if private_only or any(matches(path, p) for p in contract['deny']):
        return 'edge-404'
    if any(path == p or path.startswith(p + '/') for p in contract['mcr_prefixes']):
        return 'kong-only'
    return 'out-of-scope'


def validate_observation(contract, path, method, observation, *, private_only=False):
    expected = expected_edge(contract, path, method, private_only=private_only)
    require(expected != 'out-of-scope', 'not an MCR-K probe')
    require(set(observation) == {'edge', 'upstream', 'preserved', 'client_headers_survived',
                                'redaction_pass', 'kong_failure_bypassed'}, 'observation fields')
    require(observation['edge'] == expected, 'edge destination mismatch')
    require(observation['redaction_pass'] is True, 'redaction unproven')
    require(observation['kong_failure_bypassed'] is False, 'Kong bypass')
    require(isinstance(observation['client_headers_survived'], list), 'header list required')
    for name in observation['client_headers_survived']:
        require(isinstance(name, str), 'header name required')
        require(not any(matches(name.lower(), p) for p in STRIP + FORWARDED), 'spoofable header survived')
    if expected == 'edge-404':
        require(observation['upstream'] is None, 'denial must have no upstream')
    else:
        require(observation['upstream'] == contract['upstream'], 'only Kong is allowed')
        require(isinstance(observation['preserved'], list), 'preserved header list required')
        require(all(isinstance(h, str) for h in observation['preserved']), 'header name required')
        require(set(PRESERVE) <= {h.lower() for h in observation['preserved']}, 'end-to-end header loss')


def digest(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def validate_evidence(e):
    """Closed evidence schema; only metadata, digests, enums, no raw captures."""
    require(isinstance(e, dict), 'evidence object required')
    require(set(e) == {'schema', 'status', 'environment', 'source_sha', 'captured_at',
        'candidate_sha256', 'previous_sha256', 'readback_sha256', 'rollback_readback_sha256',
        'gates', 'blockers'}, 'evidence fields mismatch (raw secrets/captures forbidden)')
    require(e['schema'] == 'codestra.mcr-k.evidence.v1', 'evidence schema')
    require(e['status'] in ('PASS', 'BLOCKED', 'FAIL'), 'evidence status')
    require(e['environment'] in ('offline', 'TEST_SYN', 'staging', 'production'), 'environment')
    require(digest(e['source_sha'], 40), 'source SHA required')
    require(isinstance(e['captured_at'], str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', e['captured_at']), 'UTC timestamp required')
    try:
        datetime.strptime(e['captured_at'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise ValueError('invalid UTC timestamp') from None
    for field in ('candidate_sha256', 'previous_sha256', 'readback_sha256', 'rollback_readback_sha256'):
        require(e[field] is None or digest(e[field]), 'invalid configuration digest')
    require(isinstance(e['gates'], dict) and set(e['gates']) == GATES, 'all evidence gates required')
    for gate in e['gates'].values():
        require(isinstance(gate, dict) and set(gate) == {'status', 'artifact_sha256'}, 'gate fields')
        require(gate['status'] in ('PASS', 'BLOCKED', 'FAIL'), 'gate status')
        require(gate['artifact_sha256'] is None or digest(gate['artifact_sha256']), 'artifact digest')
        require(gate['status'] != 'PASS' or digest(gate['artifact_sha256']), 'PASS needs artifact digest')
    require(isinstance(e['blockers'], list) and all(isinstance(b, str) and b in BLOCKERS for b in e['blockers']), 'blocker codes')
    require(len(e['blockers']) == len(set(e['blockers'])), 'duplicate blockers')
    statuses = {g['status'] for g in e['gates'].values()}
    if e['status'] == 'PASS':
        require(e['environment'] != 'offline', 'PASS requires runtime environment')
        require(statuses == {'PASS'} and not e['blockers'], 'PASS cannot hide unproven gates')
        require(all(digest(e[f]) for f in ('candidate_sha256', 'previous_sha256', 'readback_sha256', 'rollback_readback_sha256')), 'PASS needs configuration identities')
        require(e['candidate_sha256'] == e['readback_sha256'], 'candidate readback mismatch')
        require(e['previous_sha256'] == e['rollback_readback_sha256'], 'rollback readback mismatch')
    elif e['status'] == 'BLOCKED':
        require('BLOCKED' in statuses and 'FAIL' not in statuses and bool(e['blockers']), 'blocked evidence needs blockers, no hidden failures')
    else:
        require('FAIL' in statuses, 'FAIL needs failed gate')


def ready(evidence):
    validate_evidence(evidence)
    return evidence['status'] == 'PASS' and evidence['environment'] != 'offline'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, default=HERE / 'edge.v1.json')
    parser.add_argument('--evidence', type=Path, default=HERE / 'evidence.blocked.v1.json')
    parser.add_argument('--require-ready', action='store_true')
    args = parser.parse_args()
    try:
        validate_contract(json.loads(args.contract.read_text()))
        evidence = json.loads(args.evidence.read_text())
        validate_evidence(evidence)
        runtime_state = 'PASS' if ready(evidence) else evidence['status']
        print('MCR_K_CONTRACT=PASS MCR_K_EVIDENCE_SCHEMA=PASS RUNTIME=' + runtime_state)
        return 2 if args.require_ready and not ready(evidence) else 0
    except (ValueError, OSError) as exc:
        print('MCR_K_INVALID: ' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
