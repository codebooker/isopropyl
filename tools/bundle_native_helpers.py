"""Import audited native tools and their licenses into a hash-checked package.

Input JSON contains platform, tools (name -> local file), licenses (local files),
and sources (upstream project -> URL/hash metadata). macOS dylibs are copied and
relocated recursively; Windows callers must provide every non-system DLL.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import hashlib
import json
import shutil
import subprocess
import struct
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()

def mac_dependencies(path):
    output = subprocess.check_output(['otool', '-L', str(path)], text=True)
    return [line.strip().split(' (', 1)[0] for line in output.splitlines()[1:]]

def _bundle(spec, root, destination):
    platform = spec['platform']
    if platform not in {'macos-arm64', 'windows-x86-64', 'windows-arm64'}:
        raise ValueError('Unsupported native helper platform')
    final_destination = root/'isopropyl/helpers'/platform
    destination.mkdir(parents=True, exist_ok=True)
    imported = {}
    def copy(source):
        source = Path(source).resolve(strict=True)
        target = destination/source.name
        if target.name in imported:
            if imported[target.name] != source:
                raise ValueError('Dependency basename collision: '+target.name)
            return target
        imported[target.name] = source
        if platform.startswith('windows'):
            with source.open('rb') as stream:
                header=stream.read(64)
                if header[:2]!=b'MZ':raise ValueError('Windows helper is not PE: '+str(source))
                offset=struct.unpack_from('<I',header,60)[0]
                if offset>1024*1024:raise ValueError('Invalid PE header offset')
                stream.seek(offset);pe=stream.read(6)
            machine=0x8664 if platform=='windows-x86-64' else 0xAA64
            if pe[:4]!=b'PE\0\0' or struct.unpack_from('<H',pe,4)[0]!=machine:
                raise ValueError('Windows helper architecture mismatch: '+str(source))
        shutil.copy2(source, target)
        target.chmod(0o755)
        if platform.startswith('macos'):
            architecture = subprocess.check_output(['lipo', '-archs', str(target)], text=True).strip()
            if architecture != 'arm64':
                raise ValueError('Mac helper must contain only ARM64: '+str(source))
            commands=subprocess.check_output(['otool','-l',str(target)],text=True)
            minimum=re.search(r'\bminos ([0-9.]+)',commands)
            if minimum and tuple((list(map(int,minimum.group(1).split('.')))+[0,0,0])[:3])>(13,0,0):
                raise ValueError('Mac helper requires newer than macOS13: '+str(source))
            for dependency in mac_dependencies(source):
                if dependency.startswith(('/usr/lib/', '/System/Library/')):
                    continue
                if dependency.startswith('@'):
                    raise ValueError('Resolve relative dylib before import: '+dependency)
                if Path(dependency).resolve() == source:
                    continue
                copied = copy(dependency)
                subprocess.run(['install_name_tool', '-change', dependency,
                                '@loader_path/'+copied.name, str(target)], check=True)
            if target.suffix == '.dylib':
                subprocess.run(['install_name_tool', '-id', '@loader_path/'+target.name, str(target)], check=True)
            subprocess.run(['codesign', '--force', '--sign', '-', str(target)], check=True)
        return target
    entries = {}
    for name, source in spec['tools'].items():
        path = copy(source)
        entries[name] = {'file': path.name, 'sha256': sha256(path)}
    for source in spec.get('dependencies', []):
        copy(source)
    if not spec.get('licenses') or not spec.get('sources'):
        raise ValueError('Upstream license texts and source provenance are required')
    license_dir = destination/'licenses'
    license_dir.mkdir(exist_ok=True)
    for label, source in spec['licenses'].items():
        if Path(label).name != label:
            raise ValueError('License label must be a basename')
        shutil.copyfile(source, license_dir/label)
    provenance = {'sources': spec['sources'], 'files': {
        str(path.relative_to(destination)): sha256(path)
        for path in sorted(destination.rglob('*')) if path.is_file() and path.name!='PROVENANCE.json'}}
    (destination/'PROVENANCE.json').write_text(json.dumps(provenance, indent=2)+'\n')
    manifest = root/'isopropyl/data/native-tools-v1.json'
    payload = json.loads(manifest.read_text()) if manifest.exists() else {'version': 1, 'platforms': {}}
    payload['platforms'][platform] = entries
    backup=final_destination.with_name('.'+platform+'-previous')
    if backup.exists():shutil.rmtree(backup)
    if final_destination.exists():final_destination.rename(backup)
    try:
        destination.rename(final_destination)
        temporary_manifest=manifest.with_suffix('.json.new')
        temporary_manifest.write_text(json.dumps(payload, indent=2, sort_keys=True)+'\n')
        temporary_manifest.replace(manifest)
    except BaseException:
        if final_destination.exists():shutil.rmtree(final_destination)
        if backup.exists():backup.rename(final_destination)
        raise
    if backup.exists():shutil.rmtree(backup)
    return final_destination

def bundle(spec, root=ROOT):
    parent=root/'isopropyl/helpers';parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.helper-stage-',dir=parent) as staging:
        return _bundle(spec,root,Path(staging))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('specification', type=Path)
    arguments = parser.parse_args()
    print(bundle(json.loads(arguments.specification.read_text())))
