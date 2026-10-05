#!/usr/bin/env python3
"""The single Caddy version authority: read it, or fetch its verified release binary."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = ROOT / "config" / "caddy-version-authority.v1.json"


def authority() -> dict:
    return json.loads(AUTHORITY_PATH.read_text(encoding="utf-8"))


def field(path: str):
    value = authority()
    for part in path.split("."):
        value = value[part]
    return value


def fetch_release_binary(destination: Path) -> Path:
    release = authority()["release_binary"]
    with urllib.request.urlopen(release["url"], timeout=120) as response:
        archive = response.read()
    actual = hashlib.sha512(archive).hexdigest()
    if actual != release["sha512"]:
        raise SystemExit(f"CADDY_RELEASE_BINARY=FAIL:sha512:{actual}")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.getmember("caddy")
        binary = bundle.extractfile(member).read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(binary)
    destination.chmod(0o755)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("field").add_argument("path")
    sub.add_parser("fetch").add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "field":
        print(field(args.path))
    else:
        print(fetch_release_binary(args.destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
