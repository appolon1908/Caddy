#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CADDYFILE = ROOT / "Caddyfile"
DEFAULT_OUTPUT = ROOT / "generated" / "pas144-runtime-candidate.json"


class CandidateBuildError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


Runner = Callable[..., subprocess.CompletedProcess[str]]


class CandidateBuilder:
    def __init__(
        self,
        *,
        caddyfile: Path = DEFAULT_CADDYFILE,
        output: Path = DEFAULT_OUTPUT,
        runner: Runner = subprocess.run,
        source_sha_provider=None,
    ) -> None:
        self.caddyfile = caddyfile
        self.output = output
        self.runner = runner
        self.source_sha_provider = source_sha_provider

    def _adapt(self) -> dict[str, Any]:
        if not self.caddyfile.exists():
            raise CandidateBuildError("caddyfile_missing")
        try:
            result = self.runner(
                [
                    "caddy",
                    "adapt",
                    "--config",
                    str(self.caddyfile),
                    "--adapter",
                    "caddyfile",
                    "--pretty",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=os.environ.copy(),
            )
        except OSError as exc:
            raise CandidateBuildError("caddy_adapter_unavailable") from exc
        if result.returncode != 0:
            detail = (result.stderr or "").strip()[:512]
            raise CandidateBuildError(f"caddy_adapt_failed:{detail}")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CandidateBuildError("caddy_adapt_invalid_json") from exc
        if not isinstance(value, dict):
            raise CandidateBuildError("caddy_adapt_not_object")
        return value

    def build(self, *, check: bool = False) -> dict[str, Any]:
        candidate = self._adapt()
        text = json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        digest = hashlib.sha256(canonical_json(candidate).encode("utf-8")).hexdigest()
        if check:
            if not self.output.exists():
                raise CandidateBuildError("runtime_candidate_missing")
            try:
                existing = json.loads(self.output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise CandidateBuildError("runtime_candidate_invalid") from exc
            if existing != candidate:
                raise CandidateBuildError("runtime_candidate_drift")
        else:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".candidate.", suffix=".tmp", dir=self.output.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self.output)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        source_sha = self.source_sha_provider() if self.source_sha_provider else None
        metadata = {
            "schema": "codestra.caddy.runtime-candidate-metadata.v1",
            "candidate_sha256": digest,
            "source_sha": source_sha,
            "caddyfile_sha256": hashlib.sha256(self.caddyfile.read_bytes()).hexdigest(),
        }
        metadata_path = self.output.with_suffix(self.output.suffix + ".meta.json")
        if not check:
            metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif not metadata_path.exists() or json.loads(metadata_path.read_text(encoding="utf-8")) != metadata:
            raise CandidateBuildError("runtime_candidate_metadata_drift")
        return {
            "schema": "codestra.caddy.runtime-candidate.v1",
            "candidate_sha256": digest,
            "source_sha": source_sha,
            "metadata": metadata_path.name,
            "output": self.output.name,
            "mutation_performed": False,
        }
