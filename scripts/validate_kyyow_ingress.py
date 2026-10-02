#!/usr/bin/env python3
"""Validate each Kyyow public host independently."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_HOSTS = {'app.kyyow.com', 'api.kyyow.com', 'search.kyyow.com',
                'docs.kyyow.com', 'auth.kyyow.com', 'status.kyyow.com'}
IDENTITY_HEADERS = ('X-Authenticated-Client', 'X-Authenticated-Tenant', 'X-Authenticated-Role')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(contract, site, runtime):
    require(contract['schema'] == 'kyyow.ingress.v1', 'schema mismatch')
    require(contract['principalRepository'] == 'appolon1908/Caddy', 'ingress authority mismatch')
    require(contract['identityRepository'] == 'appolon1908/Keycloak', 'identity authority mismatch')
    require(contract['activation'] == {
        'repositoryConfigurationOnly': True, 'dnsChangeAuthorized': False,
        'liveReloadAuthorized': False, 'productionCutoverAuthorized': False,
    }, 'activation must remain source only')
    require(set(contract['publicHosts']) == PUBLIC_HOSTS, 'public host family mismatch')
    # Site blocks start and end at column zero; nested directive blocks are indented.
    blocks = re.findall(r'(?m)^([^#\s{}]+)\s*\{\n(.*?)^\}', site, re.S)
    require(len(blocks) == len(PUBLIC_HOSTS), 'unexpected or duplicate site block')
    require({host for host, _ in blocks} == PUBLIC_HOSTS, 'site host family mismatch')
    for host, block in blocks:
        route = contract['publicHosts'][host]
        require('{$' + route['upstream'] + '}' in block, f'{host}: upstream mismatch')
        require(runtime.count(route['upstream'] + '=127.0.0.1:') == 1, f'{host}: runtime upstream mismatch')
        for token in ('import security_headers', 'request>headers>Authorization delete'):
            require(token in block, f'{host}: missing {token}')
        for header in IDENTITY_HEADERS:
            require(re.search(r'(?m)^\s*request_header\s+-' + re.escape(header) + r'\s*$', block), f'{host}: missing identity header stripping')
        require('header_up Authorization' not in block, f'{host}: authorization override')
        require('header_up X-Authenticated-' not in block, f'{host}: identity override')


def main():
    try:
        validate(json.loads((ROOT / 'config/kyyow-ingress.v1.json').read_text()),
                 (ROOT / 'sites/kyyow.com.caddy').read_text(),
                 (ROOT / 'config/runtime-values.example').read_text())
    except (KeyError, ValueError, OSError) as error:
        raise SystemExit(f'KYYOW_INGRESS_CONTRACT=FAIL: {error}') from error
    print('KYYOW_INGRESS_CONTRACT=PASS')


if __name__ == '__main__':
    main()
