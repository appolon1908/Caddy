#!/usr/bin/env python3
"""Stage the exact /etc/caddy tree the immutable image ships.

The Dockerfile copies this staged tree verbatim, and its digest
(scripts/hash_config_tree.py) is the configuration identity carried by the image
label, the Compose runtime and the read-only validator. Only the root Caddyfile,
snippets and sites are deployable configuration; pending sites never ship.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = ("Caddyfile", "snippets/*.caddy", "sites/*.caddy")


def stage(destination: Path, root: Path = ROOT) -> list[str]:
    if destination.exists():
        shutil.rmtree(destination)
    staged: list[str] = []
    for pattern in PATTERNS:
        for source in sorted(root.glob(pattern)):
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"deployable configuration must be regular files: {source.relative_to(root)}")
            relative = source.relative_to(root)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            staged.append(relative.as_posix())
    if "Caddyfile" not in staged:
        raise ValueError("root Caddyfile missing")
    return staged


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: stage_image_config.py DESTINATION", file=sys.stderr)
        return 2
    try:
        staged = stage(Path(sys.argv[1]))
    except (OSError, ValueError) as exc:
        print(f"CADDY_IMAGE_CONFIG=FAIL:{exc}", file=sys.stderr)
        return 2
    print(f"CADDY_IMAGE_CONFIG_FILES={len(staged)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
