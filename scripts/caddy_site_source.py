"""Read site fragments as Caddy sees them: the shared access_log snippet expanded in place."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCESS_LOG = ROOT / "snippets" / "access_log.caddy"
IMPORT_RE = re.compile(r"(?m)^\timport access_log ([a-z0-9-]+)\n")


def _access_log_body() -> str:
    text = ACCESS_LOG.read_text(encoding="utf-8")
    start = text.index("(access_log) {\n") + len("(access_log) {\n")
    return text[start:text.rindex("\n}")] + "\n"


def expand(source: str) -> str:
    body = _access_log_body()
    return IMPORT_RE.sub(lambda match: body.replace("{args[0]}", match.group(1)), source)


def read_site(path: Path) -> str:
    return expand(path.read_text(encoding="utf-8"))
