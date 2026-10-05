"""The bounded production read-only canary: present, bound to its workflow, and read-only."""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_production_readonly_canary.sh"
WORKFLOW = (ROOT / ".github" / "workflows" / "production-readonly-canary-v2.yml").read_text(encoding="utf-8")
SOURCE = SCRIPT.read_text(encoding="utf-8")
sys.path.insert(0, str(ROOT / "scripts"))
import stage_image_config  # noqa: E402


def test_workflow_runs_the_canary_and_binds_the_shipped_configuration():
    assert "scripts/run_production_readonly_canary.sh | tee production-readonly-canary-v2.txt" in WORKFLOW
    assert "scripts/stage_image_config.py --digest" in WORKFLOW
    for name in re.findall(r"(?m)^      (CADDY_CANARY_[A-Z_]+):", WORKFLOW):
        if name not in {"CADDY_CANARY_IMAGE_DIGEST", "CADDY_CANARY_DATA_SOURCE"}:
            assert f"${{{name}:-}}" in SOURCE, name
    assert "production-canary-evidence.json" in SOURCE and "production-canary-evidence.json" in WORKFLOW


def test_canary_is_read_only_by_construction():
    code = "\n".join(line for line in SOURCE.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in (" -X ", "--request", "--data", " -d ", "POST", "PUT", "DELETE", " pull ", "compose",
                      " stop ", " kill ", " restart ", "run -d", "--detach", "caddy reload", "/load"):
        assert forbidden not in code, forbidden
    assert code.count('run_validator "$work/') == 2
    assert 'cmp -s "$work/pre.json" "$work/post.json"' in code
    assert "--network none" in code and "--read-only" in code


def _executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def harness(tmp_path):
    bash = shutil.which("bash")
    if os.name == "nt" or not bash:
        pytest.skip("requires a POSIX shell")
    root = tmp_path / "root"
    (root / "scripts").mkdir(parents=True)
    for name in ("Caddyfile",):
        shutil.copy(ROOT / name, root / name)
    for folder in ("snippets", "sites"):
        shutil.copytree(ROOT / folder, root / folder)
    for name in ("stage_image_config.py", "hash_config_tree.py"):
        shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
    config_sha = stage_image_config.digest(root)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    state = tmp_path / "state"
    state.mkdir()
    python = sys.executable
    _executable(root / "scripts" / "websocket_probe.py", "print('WEBSOCKET_CANARY=PASS')\n")
    _executable(root / "scripts" / "caddy_readonly_validator.py", f'''import json, pathlib
counter = pathlib.Path({str(state / "validator")!r})
runs = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(runs))
changed = pathlib.Path({str(state / "change_after_first")!r}).exists() and runs > 1
print(json.dumps({{"schema": "codestra.caddy-readonly-validation.v2", "container_health": "healthy",
                  "config_identity": "PASS", "config_validation": "PASS", "served_config_matches_image": True,
                  "credential_redaction": "PASS", "source_sha": "a" * 40, "image_digest": "sha256:" + "1" * 64,
                  "config_sha256": "b" * 64, "release_id": "changed" if changed else "live"}}, sort_keys=True))
''')
    _executable(bin_dir / "docker", f'''#!{python}
import json, pathlib, shutil, sys
sys.path.insert(0, {str(root / "scripts")!r})
import stage_image_config
args = sys.argv[1:]
with open({str(log)!r}, "a") as handle:
    handle.write("docker " + " ".join(args) + "\\n")
state = pathlib.Path({str(state)!r})
if args[0] == "image":
    fmt = args[args.index("--format") + 1]
    values = {{"org.opencontainers.image.source": "https://github.com/appolon1908/Caddy",
              "org.opencontainers.image.revision": "c" * 40,
              "io.codestra.caddy.config.sha256": {config_sha!r}}}
    print("65532:65532" if fmt == "{{{{.Config.User}}}}" else next(v for k, v in values.items() if k in fmt))
elif args[0] == "create":
    print("probe-id")
elif args[0] == "cp":
    destination = pathlib.Path(args[2])
    shutil.rmtree(destination, ignore_errors=True)
    stage_image_config.stage(destination, pathlib.Path({str(root)!r}))
    if (state / "tamper_image").exists():
        (destination / "Caddyfile").write_text("tampered")
elif args[0] == "run":
    sys.exit(1 if (state / "offline_invalid").exists() else 0)
elif args[0] == "inspect":
    print(json.dumps(["CADDY_PUBLIC_BIND=203.0.113.10", "CADDY_PRIVATE_INGRESS_BIND=10.40.0.1"]))
elif args[0] == "exec":
    print("CADDY_HTTP3_CANARY=PASS")
''')
    _executable(bin_dir / "curl", f'''#!{python}
import json, pathlib, sys
args = sys.argv[1:]
with open({str(log)!r}, "a") as handle:
    handle.write("curl " + " ".join(args) + "\\n")
state = pathlib.Path({str(state)!r})
url = next(a for a in args if a.startswith("http"))
path = url.split("/", 3)[3] if url.count("/") >= 3 else ""
path = "/" + path
if "--dump-header" in args:
    pathlib.Path(args[args.index("--dump-header") + 1]).write_text("strict-transport-security: max-age=31536000\\n")
if "--output" in args and args[args.index("--output") + 1] != "/dev/null":
    pathlib.Path(args[args.index("--output") + 1]).write_text(json.dumps({{"issuer": "https://auth.codestra.co/realms/codestra"}}))
if url.startswith("http://"):
    code = "308"
elif "middleware-email-events" in url:
    code = "403" if "--cert" in args else "000"
elif "automation.codestra.co" in url:
    code = "404"
elif "bao.codestra.media" in url:
    code = "403"
elif path in ("/metrics", "/metrics;x", "/internal/v1/database/health", "/not-a-contracted-route", "/api/v1/health"):
    code = "200" if (state / "expose_private").exists() and path == "/metrics;x" else "404"
elif path == "/platform/v1/kernel/describe":
    code = "401"
else:
    code = "200"
if "--write-out" in args:
    sys.stdout.write(code)
''')
    _executable(bin_dir / "openssl", "#!/bin/sh\n[ \"$1\" = s_client ] && echo 'ALPN protocol: h2'\nexit 0\n")
    script = SOURCE
    for binary, replacement in (("/usr/bin/docker", bin_dir / "docker"), ("/usr/bin/python3", python),
                                ("/usr/bin/curl", bin_dir / "curl"), ("/usr/bin/openssl", bin_dir / "openssl")):
        script = script.replace(f"={binary}\n", f"={replacement}\n")
    _executable(root / "scripts" / "run_production_readonly_canary.sh", script)
    files = {}
    for name in ("env", "client.crt", "client.key", "ca.crt"):
        files[name] = tmp_path / name
        files[name].write_text("TEST_SYN\n")
    env = {**os.environ,
           "CADDY_CANARY_IMAGE": "ghcr.io/appolon1908-hue/codestra-caddy@sha256:" + "2" * 64,
           "CADDY_CANARY_SOURCE_SHA": "c" * 40, "CADDY_CANARY_CONFIG_SHA256": config_sha,
           "CADDY_CANARY_ENV_FILE": str(files["env"]), "CADDY_CANARY_MTLS_CLIENT_CERT": str(files["client.crt"]),
           "CADDY_CANARY_MTLS_CLIENT_KEY": str(files["client.key"]), "CADDY_CANARY_MTLS_CA_CERT": str(files["ca.crt"])}

    def run(**flags):
        for flag in flags:
            (state / flag).write_text("1")
        if "writable_curl" in flags:
            (bin_dir / "curl").chmod(0o777)
        work = tmp_path / "out"
        work.mkdir(exist_ok=True)
        return subprocess.run([bash, str(root / "scripts" / "run_production_readonly_canary.sh")], cwd=work, env=env,
                              capture_output=True, text=True, timeout=120), work, log

    return run


def test_canary_passes_and_records_read_only_evidence(harness):
    result, work, log = harness()
    assert result.returncode == 0, result.stderr
    assert "CADDY_PRODUCTION_READONLY_CANARY=PASS" in result.stdout
    evidence = json.loads((work / "production-canary-evidence.json").read_text())
    assert evidence["write_requests_sent"] is False and evidence["live_runtime_unchanged"] is True
    calls = log.read_text()
    assert not re.search(r"^docker (stop|kill|restart|pull|compose|start)\b", calls, re.M)
    assert not re.search(r"^curl .*(-X|--request|--data)", calls, re.M)
    assert "docker run --rm --network none --read-only" in calls


@pytest.mark.parametrize("flag, reason", [
    ("tamper_image", "image_config_identity"),
    ("offline_invalid", "candidate_offline_validation"),
    ("expose_private", "live_private_or_unknown:/metrics;x"),
    ("change_after_first", "live_runtime_changed"),
    ("writable_curl", "trusted_binary:curl"),
])
def test_canary_fails_closed(harness, flag, reason):
    result, work, _ = harness(**{flag: True})
    assert result.returncode == 2
    assert f"CADDY_PRODUCTION_READONLY_CANARY=FAIL:{reason}" in result.stderr
    assert not (work / "production-canary-evidence.json").exists()
