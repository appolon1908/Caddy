#!/usr/bin/env python3
"""Compute the deterministic digest for the deployable Caddy configuration."""
from __future__ import annotations
import hashlib
import sys
from pathlib import Path
EXCLUDED_TOP_LEVEL={"private"}
def config_tree_hash(root: Path)->str:
    root=root.resolve(strict=True); digest=hashlib.sha256(); count=0
    for path in sorted(root.rglob('*'), key=lambda item:item.as_posix()):
        relative=path.relative_to(root)
        if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL: continue
        if path.is_symlink(): raise ValueError(f"symbolic links are not permitted: {relative}")
        if not path.is_file(): continue
        payload=path.read_bytes(); name=relative.as_posix().encode('utf-8')
        digest.update(len(name).to_bytes(8,'big')); digest.update(name)
        digest.update(len(payload).to_bytes(8,'big')); digest.update(payload); count+=1
    if count==0: raise ValueError('configuration tree contains no files')
    return digest.hexdigest()
def main()->int:
    if len(sys.argv)!=2:
        print('usage: hash_config_tree.py CONFIG_ROOT', file=sys.stderr); return 2
    try: print(config_tree_hash(Path(sys.argv[1])))
    except (OSError,ValueError) as exc:
        print(f'CADDY_CONFIG_HASH=FAIL:{exc}', file=sys.stderr); return 2
    return 0
if __name__=='__main__': raise SystemExit(main())
