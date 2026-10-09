from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "validate_platform_public_sites.py"


def load_module():
    spec = importlib.util.spec_from_file_location("validate_platform_public_sites", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_platform_public_sites_pass():
    m = load_module()
    contract, source, runtime = m.load()
    m.validate(contract, source, runtime)


def test_prometheus_without_edge_auth_is_rejected():
    m = load_module()
    contract, source, runtime = m.load()
    b = m.block(source, "prometheus.codestra.co")
    mutated = source.replace(
        b,
        b.replace("basic_auth {\n\t\tcodestra-admin {$CADDY_MONITORING_ADMIN_HASH}\n\t}\n", ""),
    )
    try:
        m.validate(contract, mutated, runtime)
    except m.PublicSiteError as exc:
        assert "edge authentication missing" in str(exc)
    else:
        raise AssertionError("missing Prometheus auth was accepted")


def test_crm_database_manager_exposure_is_rejected():
    m = load_module()
    contract, source, runtime = m.load()
    mutated = source.replace("\t\trespond @database_admin 403\n", "", 1)
    try:
        m.validate(contract, mutated, runtime)
    except m.PublicSiteError as exc:
        assert "database-manager" in str(exc)
    else:
        raise AssertionError("public database manager was accepted")


def test_live_ip_literal_is_rejected():
    m = load_module()
    contract, source, runtime = m.load()
    mutated = source.replace("{$CADDY_GRAFANA_UPSTREAM}", "10.0.0.220:3000", 1)
    try:
        m.validate(contract, mutated, runtime)
    except m.PublicSiteError as exc:
        assert "IP literal" in str(exc)
    else:
        raise AssertionError("live IP literal was accepted")


def test_redirect_cannot_become_proxy():
    m = load_module()
    contract, source, runtime = m.load()
    b = m.block(source, "monitoring.codestra.co")
    mutated = source.replace(
        b,
        b.replace(
            "redir https://grafana.codestra.co{uri} 302",
            "reverse_proxy {$CADDY_GRAFANA_UPSTREAM}",
        ),
    )
    try:
        m.validate(contract, mutated, runtime)
    except m.PublicSiteError as exc:
        assert "redirect" in str(exc)
    else:
        raise AssertionError("monitoring redirect proxy mutation was accepted")
