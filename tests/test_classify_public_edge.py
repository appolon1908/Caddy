import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "classify_public_edge.py"

KONG = "127.0.0.1:8000"
LEGACY = "127.0.0.1:18101"
REALTIME = "127.0.0.1:18102"
OAUTH2 = "127.0.0.1:4180"
GRAFANA = "127.0.0.1:18003"
EDITOR_HOST = "n8n-editor.invalid"
ENV = {
    KONG: "CADDY_KONG_UPSTREAM",
    LEGACY: "CADDY_LEGACY_API_UPSTREAM",
    REALTIME: "CADDY_REALTIME_UPSTREAM",
    OAUTH2: "CADDY_N8N_OAUTH2_PROXY_UPSTREAM",
    GRAFANA: "CADDY_GRAFANA_UPSTREAM",
}


def load_module():
    spec = importlib.util.spec_from_file_location("classify_public_edge", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def proxy(dial, **match):
    route = {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}]}
    if match:
        route["match"] = [match]
    return route


def respond(status, **match):
    route = {"handle": [{"handler": "static_response", "status_code": status}]}
    if match:
        route["match"] = [match]
    return route


def site(host, *routes):
    return {"match": [{"host": [host]}], "handle": [{"handler": "subroute", "routes": list(routes)}]}


def document(*sites):
    return {"apps": {"http": {"servers": {"srv0": {"routes": list(sites)}}}}}


def api_site(fallback):
    return site(
        "api.codestra.co",
        respond(404, path=["/metrics", "/metrics/*", "/internal/*"]),
        proxy(KONG, method=["GET"], path_regexp={"name": "canonical_get", "pattern": "^/platform/v1/tenants$"}),
        proxy(KONG, path=["/platform/v1*", "/v2/automation*"]),
        proxy(REALTIME, path=["/ws/agent", "/healthz"]),
        fallback,
    )


def run(doc):
    module = load_module()
    results = module.classify(module.enumerate_terminals(doc), ENV, module.load_authorities(), EDITOR_HOST)
    return results, module.summarize(results, ENV)


def test_current_edge_shape_is_fully_classified_but_reports_the_fallback():
    results, summary = run(document(api_site(proxy(LEGACY))))
    labels = [r.classification for r in results]
    assert labels == [
        "PRIVATE_OR_DENIED_404",
        "CANONICAL_CONTRACT",
        "CANONICAL_KONG_MANAGED",
        "TRANSITIONAL_APPROVED",
        "UNKNOWN_ROUTE_FALLBACK",
    ]
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 0
    assert summary["UNKNOWN_ROUTE_FALLBACK"] == 1
    assert summary["LEGACY_API_FALLBACK"] == 1


def test_retired_fallback_answers_404_and_passes_pas177_mode(tmp_path):
    import json

    module = load_module()
    adapted = tmp_path / "adapted.json"
    args = [str(adapted), "--n8n-editor-host", EDITOR_HOST]
    for dial, name in ENV.items():
        args += ["--upstream", f"{name}={dial}"]

    adapted.write_text(json.dumps(document(api_site(respond(404)))))
    _, summary = run(json.loads(adapted.read_text()))
    assert summary["UNKNOWN_ROUTE_FALLBACK"] == 0
    assert summary["LEGACY_API_FALLBACK"] == 0
    assert module.main(args + ["--require-no-fallback"]) == 0

    adapted.write_text(json.dumps(document(api_site(proxy(LEGACY)))))
    assert module.main(args) == 0
    assert module.main(args + ["--require-no-fallback"]) == 1


def test_kong_prefix_outside_the_contract_is_unclassified():
    doc = document(site("api.codestra.co", proxy(KONG, path=["/platform/v1*", "/api/v9/shadow*"])))
    _, summary = run(doc)
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 1


def test_legacy_upstream_on_a_named_path_is_unclassified():
    doc = document(site("api.codestra.co", proxy(LEGACY, path=["/api/v1/legacy-thing"])))
    _, summary = run(doc)
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 1
    assert summary["LEGACY_API_FALLBACK"] == 1


def test_unknown_upstream_and_unknown_host_are_unclassified():
    doc = document(
        site("api.codestra.co", proxy("10.0.0.5:5432", path=["/platform/v1*"])),
        site("shadow.codestra.co", proxy(KONG)),
    )
    _, summary = run(doc)
    assert summary["UNCLASSIFIED_UPSTREAMS"] == 1
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 1


def test_observability_host_may_not_reach_another_service():
    _, ok = run(document(site("graf.codestra.media", proxy(GRAFANA))))
    _, bad = run(document(site("graf.codestra.media", proxy(KONG))))
    assert ok["UNCLASSIFIED_PUBLIC_ROUTES"] == 0
    assert bad["UNCLASSIFIED_PUBLIC_ROUTES"] == 1


def test_proxy_pool_cannot_hide_an_unclassified_second_upstream(tmp_path):
    import json

    module = load_module()
    adapted = tmp_path / "adapted.json"
    args = [str(adapted), "--n8n-editor-host", EDITOR_HOST]
    for dial, name in ENV.items():
        args += ["--upstream", f"{name}={dial}"]

    # The first target is authorized; every other selectable target must be too.
    for second in (KONG, "192.0.2.9:9999"):
        route = proxy(GRAFANA)
        route["handle"][0]["upstreams"].append({"dial": second})
        adapted.write_text(json.dumps(document(site("graf.codestra.media", route))))
        assert module.main(args) == 1


def test_proxy_pool_with_only_authorized_upstreams_remains_classified():
    route = proxy(GRAFANA)
    route["handle"][0]["upstreams"].append({"dial": GRAFANA})
    results, summary = run(document(site("graf.codestra.media", route)))
    assert len(results) == 2
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 0
    assert summary["UNCLASSIFIED_UPSTREAMS"] == 0


def test_editor_host_only_reaches_oauth2_proxy():
    _, ok = run(document(site(EDITOR_HOST, respond(404, path=["/webhook-test*"]), proxy(OAUTH2))))
    _, bad = run(document(site(EDITOR_HOST, proxy(KONG))))
    assert ok["UNCLASSIFIED_PUBLIC_ROUTES"] == 0
    assert bad["UNCLASSIFIED_PUBLIC_ROUTES"] == 1


def test_disjoint_nested_host_matchers_are_unreachable_not_public():
    doc = document(site(EDITOR_HOST, respond(404, host=["prom.codestra.media"]), proxy(OAUTH2)))
    results, summary = run(doc)
    assert summary["UNREACHABLE_ROUTES"] == 1
    assert summary["UNCLASSIFIED_PUBLIC_ROUTES"] == 0
