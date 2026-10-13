"""Regular-file filesystem construction and independent tree verification."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path

from .helper_tools import helper
from .native_virtual import run_native_command
from .native_tree import scan_tree,consume,construct_fat32
from .native_writer import NativeWriteError


def tree_hashes(tree,writer):
    directories,files=scan_tree(tree,writer)
    return {item.path:(item.size,consume(tree,item,writer)) for item in files}


def verify_tsk(image,expected,writer,*,offset=0):
    args=[helper('fls'),'-r','-p']
    if offset:args += ['-o',str(offset//512)]
    result=run_native_command([*args,str(image)],writer,limit=16*1024*1024)
    observed={}
    for line in result.stdout.decode('utf-8',errors='strict').splitlines():
        match=re.match(r'([^ ]+) ([^:]+):\t(.*)$',line)
        if not match:continue
        kind,inode,name=match.groups()
        if kind.startswith('r/') and name in expected:
            if name in observed:raise NativeWriteError('Filesystem verification found duplicate names')
            size,digest=expected[name]
            command=[helper('icat')]
            if offset:command += ['-o',str(offset//512)]
            # Source files can exceed memory limits; spool extraction to a
            # private regular file, then hash in bounded chunks.
            from .native_stream import command_to_file
            import tempfile
            with tempfile.TemporaryDirectory(prefix='isopropyl-file-check-') as directory:
                output=Path(directory)/'file'
                command_to_file([*command,str(image),inode],output,size,writer)
                actual=hashlib.sha256()
                with output.open('rb') as stream:
                    while data:=stream.read(4*1024*1024):writer.check_cancelled();actual.update(data)
                if actual.hexdigest()!=digest:raise NativeWriteError(f'Filesystem file verification failed: {name}')
            observed[name]=True
    if set(observed)!=set(expected):raise NativeWriteError('Filesystem verification found missing files')


def verify_filesystem(image,expected,filesystem,writer,*,offset=0,label=None,cluster_size=None,sector_size=None):
    """Independent Python parsers keep verification native on every CPU."""
    from dissect.util.stream import RangeStream
    with image.open('rb') as source:
        view=RangeStream(source,offset,image.stat().st_size-offset)
        if filesystem=='ntfs':
            from dissect.ntfs import NTFS
            fs=NTFS(view)
        elif filesystem.startswith('ext'):
            from dissect.extfs import ExtFS
            fs=ExtFS(view)
        elif filesystem.startswith('fat'):
            from dissect.fat import FATFS
            fs=FATFS(view)
        else:raise NativeWriteError('No independent parser for this filesystem')
        if filesystem=='ntfs':
            labels=fs.mft.get(3).attributes.VOLUME_NAME
            actual_label=labels[0].data().decode('utf-16-le') if labels else ''
            actual_cluster=fs.cluster_size
        elif filesystem.startswith('ext'):
            actual_label=bytes(fs.sb.s_volume_name).split(b'\0',1)[0].decode('utf-8')
            actual_cluster=fs.block_size
        else:
            actual_label=fs.volume_label
            actual_cluster=fs.cluster_size
            if fs.type.name.lower()!=filesystem:
                raise NativeWriteError('Independent parser found the wrong FAT variant')
        if sector_size is not None:
            if filesystem.startswith('ext'):
                if fs.block_size<sector_size or fs.block_size%sector_size:
                    raise NativeWriteError('Independent Linux filesystem block/sector geometry failed')
            elif fs.sector_size!=sector_size:
                raise NativeWriteError('Independent filesystem logical-sector verification failed')
        expected_label=label.upper() if filesystem.startswith('fat') and label is not None else label
        if expected_label is not None and actual_label!=expected_label:
            raise NativeWriteError('Independent filesystem label verification failed')
        if cluster_size is not None and actual_cluster!=cluster_size:
            raise NativeWriteError('Independent allocation-unit verification failed')
        for name,(size,digest) in expected.items():
            writer.check_cancelled();entry=fs.mft.get('/'+name) if filesystem=='ntfs' else fs.get('/'+name)
            actual=hashlib.sha256();done=0
            with entry.open() as stream:
                while data:=stream.read(4*1024*1024):
                    writer.check_cancelled();done+=len(data)
                    if done>size:raise NativeWriteError('Filesystem entry exceeded its expected size')
                    actual.update(data)
            if done!=size or actual.hexdigest()!=digest:
                raise NativeWriteError(f'Independent filesystem verification failed: {name}')


def construct_volume(tree,image,size,filesystem,writer,progress=lambda *args:None,*,label='ISOPROPYL',cluster_size=None,sector_size=512):
    if image.exists() or image.is_symlink():raise NativeWriteError('Filesystem output already exists')
    if sector_size not in {512,1024,2048,4096}:raise NativeWriteError('Unsupported filesystem logical sector size')
    if filesystem=='fat32':
        if sector_size!=512:raise NativeWriteError('Installer FAT32 tree construction requires 512-byte sectors')
        plan=construct_fat32(tree,image,size,writer,progress,label=label,cluster_size=cluster_size)
        return plan.geometry.volume_offset,plan.geometry.volume_size,plan
    if filesystem not in {'ntfs','ext2','ext3','ext4'}:raise NativeWriteError('Unsupported file-backed filesystem')
    from .native_layout import sparse_file
    with image.open('xb') as output:sparse_file(output,size)
    image.chmod(0o600)
    expected=tree_hashes(tree,writer)
    try:
        if filesystem=='ntfs':
            args=[helper('mkntfs'),'-F','-f','-s',str(sector_size),'-p',str(1024*1024//sector_size),'-L',label]
            if cluster_size:args += ['-c',str(cluster_size)]
            progress('Formatting private NTFS image',0,1)
            run_native_command([*args,str(image)],writer)
            directories,files=scan_tree(tree,writer)
            tool=helper('ntfs-tree')
            for directory in directories[1:]:run_native_command([tool,str(image),'mkdir',directory.path],writer)
            done=0
            for item in files:
                consume(tree,item,writer)  # rebind before handing the source to the tool
                run_native_command([tool,str(image),'write',item.path,str(tree.joinpath(*item.parts))],writer)
                done+=item.size;progress('Copying installer files',done,max(1,sum(i.size for i in files)))
        else:
            args=[helper('mke2fs'),'-q','-F','-t',filesystem,'-L',label,'-d',str(tree),'-E','root_owner=0:0,lazy_itable_init=0']
            if cluster_size or sector_size>1024:args += ['-b',str(cluster_size or max(4096,sector_size))]
            progress('Formatting private Linux filesystem',0,1)
            run_native_command([*args,str(image)],writer)
        if tree_hashes(tree,writer)!=expected:raise NativeWriteError('Source tree changed during filesystem construction')
        progress('Independently verifying filesystem files',0,1)
        verify_filesystem(image,expected,filesystem,writer,label=label,cluster_size=cluster_size,sector_size=sector_size)
        progress('Independently verifying filesystem files',1,1)
        return 0,size,None
    except BaseException:
        image.unlink(missing_ok=True)
        raise
