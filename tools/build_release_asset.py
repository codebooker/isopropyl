"""Build a versioned offline release asset on its native GitHub Actions runner."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import email
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from release_manifest import ROOT, project_version


def validate_wheelhouse(paths, version, python_version, system, architecture, platforms):
    """Reject missing dependencies, wrong wheel tags and a mismatched app version."""
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.tags import compatible_tags, cpython_tags
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version
    py = tuple(map(int, python_version.split('.')))
    tags = set(cpython_tags(py, platforms=platforms)) | set(compatible_tags(py, platforms=platforms))
    distributions = {}
    for path in paths:
        name, wheel_version, _, wheel_tags = parse_wheel_filename(path.name)
        if not tags.intersection(wheel_tags):
            continue
        with zipfile.ZipFile(path) as archive:
            metadata = [n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
            if len(metadata) != 1:
                raise ValueError('Wheel metadata must be unique: ' + path.name)
            message = email.message_from_bytes(archive.read(metadata[0]))
        if canonicalize_name(message['Name']) != name or Version(message['Version']) != wheel_version:
            raise ValueError('Wheel filename and metadata disagree: ' + path.name)
        previous = distributions.get(name)
        if previous is not None and previous['Version'] != message['Version']:
            raise ValueError('Conflicting offline dependency versions: ' + str(name))
        distributions[name] = message
    application = distributions.get('isopropyl')
    if application is None or application['Version'] != version:
        raise ValueError('Offline application version does not match release')
    environment = default_environment()
    environment.update(sys_platform=system, platform_system={'darwin':'Darwin','win32':'Windows'}[system],
                       platform_machine=architecture, python_version=python_version,
                       python_full_version=python_version+'.0', extra='')
    for message in distributions.values():
        requires_python = message.get('Requires-Python')
        if requires_python:
            from packaging.specifiers import SpecifierSet
            if Version(python_version+'.0') not in SpecifierSet(requires_python):
                raise ValueError('Incompatible Python requirement: ' + message['Name'])
        for raw in message.get_all('Requires-Dist', []):
            requirement = Requirement(raw)
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            dependency = distributions.get(canonicalize_name(requirement.name))
            if dependency is None or dependency['Version'] not in requirement.specifier:
                raise ValueError('Missing or incompatible offline dependency: ' + raw)
    # Qt 6.12 raises the minimum supported macOS version above our macOS13 floor.
    for name in ('pyqt6', 'pyqt6-qt6'):
        if name not in distributions or not Version('6.8') <= Version(distributions[name]['Version']) < Version('6.12'):
            raise ValueError('Native releases require Qt/PyQt >=6.8,<6.12')


def build_macos(wheel: Path, wheelhouse: Path, output: Path, version: str):
    from packaging.tags import mac_platforms
    platforms = list(mac_platforms((13, 0), 'arm64'))
    for py in ('3.12', '3.13'):
        command = [sys.executable, '-m', 'pip', 'download', '--only-binary=:all:',
                   '--dest', str(wheelhouse), '--python-version', py, '--implementation', 'cp',
                   '--abi', 'cp'+py.replace('.', ''), '--abi', 'abi3', '--abi', 'none']
        for tag in platforms:
            command.extend(['--platform', tag])
        subprocess.run([*command, str(wheel)], check=True)
    wheels = sorted(wheelhouse.glob('*.whl'))
    for py in ('3.12', '3.13'):
        validate_wheelhouse(wheels, version, py, 'darwin', 'arm64', platforms)
    manifest = dict(schema=1, kind='macos-venv', version=version, architecture='arm64',
                    python=['3.12','3.13'], wheels=[dict(path='wheelhouse/'+p.name,
                    sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in wheels])
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr('macos-update.json', json.dumps(manifest, indent=2)+'\n')
        for path in wheels:
            archive.write(path, 'wheelhouse/'+path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    version = project_version()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    wheel = args.wheel.resolve()
    with tempfile.TemporaryDirectory(prefix='isopropyl-release-') as temporary:
        work = Path(temporary)
        wheelhouse = work/'wheels'; wheelhouse.mkdir()
        if sys.platform == 'darwin' and platform.machine().lower() == 'arm64':
            output = args.output_dir/f'ISOpropyl-{version}-macOS-arm64.zip'
            build_macos(wheel, wheelhouse, output, version)
        elif sys.platform == 'win32':
            if sys.version_info[:2] != (3,13):
                parser.error('Windows embedded runtime bundles require Python3.13 wheel resolution')
            cpu = platform.machine().lower()
            architecture = 'arm64' if cpu in ('arm64','aarch64') else 'x86-64' if cpu in ('amd64','x86_64') else None
            if architecture is None:
                parser.error('Unsupported Windows architecture')
            subprocess.run([sys.executable, '-m', 'pip', 'download', '--only-binary=:all:',
                            '--dest', str(wheelhouse), str(wheel)], check=True)
            tag = 'win_arm64' if architecture == 'arm64' else 'win_amd64'
            validate_wheelhouse(sorted(wheelhouse.glob('*.whl')), version, '3.13', 'win32',
                                'ARM64' if architecture == 'arm64' else 'AMD64', [tag])
            qt = work/'qt'; qt.mkdir()
            for path in wheelhouse.glob('*.whl'):
                if path.name.lower().startswith(('pyqt6-', 'pyqt6_qt6-', 'pyqt6_sip-')):
                    shutil.copyfile(path, qt/path.name)
            zstd = list(wheelhouse.glob('zstandard-*.whl'))
            if len(zstd) != 1:
                raise ValueError('Exactly one native zstandard wheel is required')
            output = args.output_dir/f'ISOpropyl-{version}-Windows-{architecture}.zip'
            subprocess.run([sys.executable, str(ROOT/'tools/build_windows_portable.py'),
                            '--architecture', architecture, '--wheel', str(wheel),
                            '--qt-wheels', str(qt), '--dependency-wheels', str(wheelhouse),
                            '--zstandard-wheel', str(zstd[0]), '--output', str(output)], check=True)
        else:
            parser.error('Run on native Apple silicon macOS or supported64bit Windows')
    print(output)


if __name__ == '__main__':
    main()
