#!/usr/bin/env python3
"""Build and verify immutable local Caddy evidence; never deploy or sign."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from mission5_desired_state import configuration_sha256


class ReleaseError(ValueError):
    pass


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(root), *args])


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_files(data: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        files = {}
        for member in archive:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk():
                raise ReleaseError('unsafe archive member')
            if member.isfile():
                files[member.name] = archive.extractfile(member).read()
        return files


def configuration_files(files: dict[str, bytes]) -> list[str]:
    names = ['Caddyfile', 'config/runtime-values.example']
    for directory, extension in [('config', '.json'), ('config', '.caddy'), ('snippets', '.caddy'), ('sites', '.caddy')]:
        names.extend(sorted(p for p in files if Path(p).parent.as_posix() == directory and p.endswith(extension)))
    return [p for p in names if p in files]


def configuration_digest(files: dict[str, bytes]) -> str:
    return configuration_sha256(''.join(p + '\0' + files[p].decode().replace('\r\n', '\n') + '\0' for p in configuration_files(files)))


def build_release(root: Path, output: Path, rollback_ref: str) -> dict:
    root, output = root.resolve(), output.resolve()
    if git(root, 'status', '--porcelain').strip():
        raise ReleaseError('dirty worktree cannot be sealed')
    if output.exists() or output.is_relative_to(root):
        raise ReleaseError('output must be new and outside worktree')
    source_sha = git(root, 'rev-parse', 'HEAD').decode().strip()
    rollback_sha = git(root, 'rev-parse', '--verify', rollback_ref + '^{commit}').decode().strip()
    source = git(root, 'archive', '--format=tar', source_sha)
    rollback = git(root, 'archive', '--format=tar', rollback_sha)
    files = archive_files(source)
    rollback_files = archive_files(rollback)
    configuration = io.BytesIO()
    with tarfile.open(fileobj=configuration, mode='w') as archive:
        for name in configuration_files(files):
            entry = tarfile.TarInfo(name)
            entry.size = len(files[name]); entry.mode = 0o644; entry.mtime = 0
            archive.addfile(entry, io.BytesIO(files[name]))
    created = git(root, 'show', '-s', '--format=%cI', source_sha).decode().strip()
    sbom = {
        'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
        'name': 'codestra-caddy-source', 'documentNamespace': 'https://codestra.invalid/spdx/caddy/' + source_sha,
        'creationInfo': {'created': created, 'creators': ['Tool: codestra-caddy-release']},
        'files': [{'SPDXID': 'SPDXRef-File-' + digest(name.encode())[:24], 'fileName': name,
                   'checksums': [{'algorithm': 'SHA256', 'checksumValue': digest(data)}],
                   'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'}
                  for name, data in sorted(files.items())],
    }
    artifacts = {'source.tar': source, 'configuration.tar': configuration.getvalue(), 'rollback.tar': rollback,
                 'source.spdx.json': (json.dumps(sbom, indent=2, sort_keys=True) + '\n').encode()}
    runtime = json.loads(files.get('release/pas146/caddy-staging-candidate.v1.json', b'{}')).get('immutable_runtime', {})
    manifest = {'schema': 'codestra.caddy.local-release.v1', 'source_sha': source_sha,
                'configuration_sha256': configuration_digest(files), 'rollback_source_sha': rollback_sha,
                'rollback_configuration_sha256': configuration_digest(rollback_files),
                'image_reference': runtime.get('image_reference'), 'production_apply_authorized': False,
                'signing_status': 'REQUIRES_PROTECTED_CI',
                'artifacts': {name: digest(data) for name, data in artifacts.items()}}
    if git(root, 'status', '--porcelain').strip() or git(root, 'rev-parse', 'HEAD').decode().strip() != source_sha:
        raise ReleaseError('source changed during sealing')
    output.mkdir(parents=True)
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    verify_release(output, expected_source_sha=source_sha)
    return manifest


def verify_release(output: Path, *, expected_source_sha: str) -> dict:
    manifest = json.loads((output / 'manifest.json').read_text())
    if not re.fullmatch(r'[0-9a-f]{40}', expected_source_sha) or manifest.get('source_sha') != expected_source_sha:
        raise ReleaseError('stale release source identity')
    required = {'source.tar', 'configuration.tar', 'rollback.tar', 'source.spdx.json'}
    if set(manifest.get('artifacts', {})) != required:
        raise ReleaseError('unexpected artifact set')
    for name, checksum in manifest['artifacts'].items():
        if (output / name).is_symlink() or digest((output / name).read_bytes()) != checksum:
            raise ReleaseError('artifact digest mismatch: ' + name)
    source = archive_files((output / 'source.tar').read_bytes())
    rollback = archive_files((output / 'rollback.tar').read_bytes())
    runtime = json.loads(source.get('release/pas146/caddy-staging-candidate.v1.json', b'{}')).get('immutable_runtime', {})
    image = manifest.get('image_reference')
    if image != runtime.get('image_reference') or (image is not None and not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}', image)):
        raise ReleaseError('image identity mismatch or mutable image')
    configuration = archive_files((output / 'configuration.tar').read_bytes())
    if configuration != {name: source[name] for name in configuration_files(source)}:
        raise ReleaseError('configuration bundle mismatch')
    if configuration_digest(source) != manifest['configuration_sha256'] or configuration_digest(rollback) != manifest['rollback_configuration_sha256']:
        raise ReleaseError('configuration digest mismatch')
    for name, expected in [('source.tar', expected_source_sha), ('rollback.tar', manifest['rollback_source_sha'])]:
        with tarfile.open(output / name) as archive:
            if archive.pax_headers.get('comment') != expected:
                raise ReleaseError('archive source identity mismatch')
    if manifest.get('production_apply_authorized') is not False or manifest.get('signing_status') != 'REQUIRES_PROTECTED_CI':
        raise ReleaseError('local seal cannot authorize production or claim signing')
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--rollback-ref', required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--output', type=Path, required=True)
    verify.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    result = build_release(args.root, args.output, args.rollback_ref) if args.command == 'build' else verify_release(args.output, expected_source_sha=args.source_sha)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
