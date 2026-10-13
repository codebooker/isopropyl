"""Resolve packaged native helpers, with known host-tool fallbacks for source builds."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
import os
import sys
from importlib.resources import files
from pathlib import Path

from .host_platform import validate_host
from .native_writer import NativeWriteError


def helper(name):
    host,cpu=validate_host()
    platform={'darwin':'macos','win32':'windows','linux':'linux'}[host]
    architecture='x86-64' if cpu=='x86_64' else 'arm64'
    root=Path(str(files('isopropyl')))
    manifest=root/'data/native-tools-v1.json'
    if manifest.is_file():
        try:
            payload=json.loads(manifest.read_text())
            if not isinstance(payload,dict) or payload.get('version')!=1 or not isinstance(payload.get('platforms'),dict):
                raise ValueError('invalid native helper manifest')
            entries=payload['platforms'].get(platform+'-'+architecture,{})
            if not isinstance(entries,dict):raise ValueError('invalid platform helper manifest')
            entry=entries.get(name)
            if entry:
                directory=root/'helpers'/(platform+'-'+architecture)
                filename=entry['file']
                if Path(filename).name!=filename:
                    raise ValueError('invalid helper filename')
                path=directory/filename
                provenance=json.loads((directory/'PROVENANCE.json').read_text())
                expected=provenance['files']
                if not isinstance(expected,dict):raise ValueError('invalid helper provenance')
                if expected.get(filename)!=entry['sha256']:
                    raise ValueError('helper provenance mismatch')
                for relative,digest in expected.items():
                    member=Path(relative)
                    if member.is_absolute() or '..' in member.parts:
                        raise ValueError('invalid helper dependency path')
                    candidate=directory/member
                    if candidate.is_symlink() or not candidate.is_file():
                        raise ValueError('missing helper dependency')
                    checksum=hashlib.sha256()
                    with candidate.open('rb') as stream:
                        for block in iter(lambda:stream.read(1024*1024),b''):
                            checksum.update(block)
                    if checksum.hexdigest()!=digest:
                        raise ValueError('helper dependency checksum mismatch')
                return str(path)
        except (OSError,ValueError,KeyError,TypeError,AttributeError) as error:
            raise NativeWriteError(f'Packaged {name} failed its integrity check') from error
    candidates=[]
    if host=='darwin':
        if name=='7z':candidates += [Path('/opt/homebrew/bin/7zz'),Path('/usr/local/bin/7zz')]
        if name in {'mke2fs','e2fsck','debugfs'}:candidates += [Path('/opt/homebrew/opt/e2fsprogs/sbin')/name]
        candidates += [Path('/opt/homebrew/bin')/name,Path('/opt/homebrew/sbin')/name,Path('/usr/bin')/name]
    elif host=='win32':
        aliases={'7z':('7-Zip','7z.exe'),'qemu-img':('qemu','qemu-img.exe'),'gpgv':('GnuPG/bin','gpgv.exe')}
        if name in aliases:
            folder,filename=aliases[name]
            candidates += [Path(os.environ.get(key,default))/folder/filename for key,default in
                           [('ProgramFiles',r'C:\Program Files'),('ProgramFiles(x86)',r'C:\Program Files (x86)')]]
    else:
        candidates += [Path(folder)/name for folder in ['/usr/bin','/usr/sbin','/bin','/sbin']]
    found=next((path.resolve() for path in candidates if path.is_file()),None)
    if found is None:raise NativeWriteError(f'The {name} helper is missing from this build')
    return str(found)
