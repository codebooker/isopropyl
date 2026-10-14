"""Generate the five-target updater manifest from completed release assets."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def project_version(root: Path = ROOT) -> str:
    text = (root / 'pyproject.toml').read_text(encoding='utf-8')
    matches = re.findall(r'^version = "([^"]+)"$', text, re.MULTILINE)
    if len(matches) != 1 or not VERSION.fullmatch(matches[0]):
        raise ValueError('Release version must be a stable MAJOR.MINOR.PATCH version')
    version = matches[0]
    if f'__version__ = "{version}"' not in (root / 'isopropyl/__init__.py').read_text(encoding='utf-8'):
        raise ValueError('pyproject.toml and isopropyl.__version__ disagree')
    return version


def asset_specs(version: str):
    if not VERSION.fullmatch(version):
        raise ValueError('Invalid release version')
    return (
        ('linux', 'x86_64', 'deb', f'isopropyl_{version}-1_amd64.deb'),
        ('linux', 'arm64', 'deb', f'isopropyl_{version}-1_arm64.deb'),
        ('macos', 'arm64', 'offline-wheelhouse', f'ISOpropyl-{version}-macOS-arm64.zip'),
        ('windows', 'x86_64', 'portable-zip', f'ISOpropyl-{version}-Windows-x86-64.zip'),
        ('windows', 'arm64', 'portable-zip', f'ISOpropyl-{version}-Windows-arm64.zip'),
    )


def generate(directory: Path, version: str) -> dict:
    assets = []
    specs = list(asset_specs(version))
    wheel = f'isopropyl-{version}-py3-none-any.whl'
    if (directory / wheel).exists():
        specs.extend(('linux', arch, 'wheel', wheel) for arch in ('x86_64', 'arm64'))
    for system, architecture, kind, name in specs:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f'Missing or empty release asset: {name}')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        assets.append(dict(os=system, arch=architecture, kind=kind, name=name,
                           size=path.stat().st_size, sha256=digest.hexdigest()))
    return dict(schema=1, version=version, assets=assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--tag', required=True)
    args = parser.parse_args()
    version = project_version()
    if args.tag != 'v' + version:
        parser.error('Tag must be v' + version + ', matching both project version declarations')
    if args.assets is not None:
        manifest = generate(args.assets, version)
        path = args.assets / 'isopropyl-update.json'
        path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        print(path)
    else:
        print(version)


if __name__ == '__main__':
    main()
