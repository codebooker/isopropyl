"""Release target completeness and offline wheel dependency validation."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_tool('release_manifest')
sys.modules['release_manifest'] = release
builder = load_tool('build_release_asset')


class ReleaseManifestTests(unittest.TestCase):
    def test_all_five_targets_and_exact_hashes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for _, _, _, name in release.asset_specs('1.2.3'):
                (directory/name).write_bytes(name.encode())
            manifest = release.generate(directory, '1.2.3')
            self.assertEqual(manifest['schema'], 1)
            self.assertEqual(len(manifest['assets']), 5)
            for row in manifest['assets']:
                payload = (directory/row['name']).read_bytes()
                self.assertEqual(row['size'], len(payload))
                self.assertEqual(row['sha256'], hashlib.sha256(payload).hexdigest())
            (directory/'isopropyl-1.2.3-py3-none-any.whl').write_bytes(b'wheel')
            expanded = release.generate(directory, '1.2.3')
            wheels = [row for row in expanded['assets'] if row['kind'] == 'wheel']
            self.assertEqual({row['arch'] for row in wheels}, {'x86_64', 'arm64'})
            self.assertEqual(len({row['name'] for row in wheels}), 1)
            (directory/manifest['assets'][0]['name']).unlink()
            with self.assertRaisesRegex(ValueError, 'Missing or empty'):
                release.generate(directory, '1.2.3')

    def test_generated_manifest_is_accepted_by_update_checker(self):
        from isopropyl.updates import REPOSITORY, parse_release
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for _, _, _, name in release.asset_specs('1.2.3'):
                (directory/name).write_bytes(name.encode())
            (directory/'isopropyl-1.2.3-py3-none-any.whl').write_bytes(b'wheel')
            manifest = release.generate(directory, '1.2.3')
            rows = {row['name']:row for row in manifest['assets']}
            payload = dict(draft=False, prerelease=False, tag_name='v1.2.3',
                html_url=REPOSITORY+'/releases/tag/v1.2.3', assets=[dict(name=name,
                size=row['size'], digest='sha256:'+row['sha256'],
                browser_download_url=REPOSITORY+'/releases/download/v1.2.3/'+name)
                for name,row in rows.items()])
            for row in manifest['assets']:
                selected = parse_release(payload, manifest, version='1.2.2',
                    host=row['os'], arch=row['arch'], kind=row['kind'])
                self.assertEqual(selected.asset.name, row['name'])

    def test_version_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root/'isopropyl').mkdir()
            (root/'pyproject.toml').write_text('version = "1.2.3"\n')
            (root/'isopropyl/__init__.py').write_text('__version__ = "1.2.2"\n')
            with self.assertRaisesRegex(ValueError, 'disagree'):
                release.project_version(root)
        for version in ('../1.2.3', '1.2.3rc1', '01.2.3', 'v1.2.3'):
            with self.assertRaises(ValueError):
                release.asset_specs(version)


class OfflineWheelhouseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def wheel(self, name, version, requirements=(), tag='py3-none-any'):
        filename = f'{name}-{version}-{tag}.whl'
        metadata = f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n'
        metadata += ''.join(f'Requires-Dist: {requirement}\n' for requirement in requirements)
        path = self.directory/filename
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(f'{name}-{version}.dist-info/METADATA', metadata)
        return path

    def validate(self):
        builder.validate_wheelhouse(list(self.directory.glob('*.whl')), '1.2.3', '3.12',
                                    'darwin', 'arm64', ['macosx_13_0_arm64'])

    def base(self):
        self.wheel('isopropyl', '1.2.3', ['PyQt6>=6.8,<6.12', 'zstandard>=0.23'])
        self.wheel('PyQt6', '6.11.0', ['PyQt6-Qt6>=6.11,<6.12'])
        self.wheel('PyQt6_Qt6', '6.11.0')

    def test_missing_or_wrong_arch_dependency_rejected(self):
        self.base()
        self.wheel('zstandard', '0.25.0', tag='cp312-cp312-win_amd64')
        with self.assertRaisesRegex(ValueError, 'zstandard'):
            self.validate()
        self.wheel('zstandard', '0.25.0', tag='cp312-cp312-macosx_13_0_arm64')
        self.validate()

    def test_incompatible_version_rejected(self):
        self.base()
        self.wheel('zstandard', '0.22.0')
        with self.assertRaisesRegex(ValueError, 'zstandard'):
            self.validate()

    def test_qt_floor_prevents_future_macos_requirement(self):
        self.wheel('isopropyl', '1.2.3')
        self.wheel('PyQt6', '6.12.0')
        self.wheel('PyQt6_Qt6', '6.12.0')
        with self.assertRaisesRegex(ValueError, 'Qt/PyQt'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
