"""Portable, identity-bound tree scanning and private FAT32 construction."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from .tree_records import StagedDirectory,StagedFile,validate_staged_component
from .portable_io import descriptor_status, path_status
from .native_writer import BLOCK,NativeWriteError,file_identity,path_file_identity
from .fat32_layout import _geometry,_mbr,_boot_sector,_fsinfo,_fat,_cluster_offset
from .fat32_tree import (_layout,_directory_content,_expected_entries,_derive_media_ids,
                        PrivateFat32BuildProfile)
from .fat_image import inspect_regular_fat32_image
from .timestamps import MIN_PORTABLE_ARCHIVE_MTIME_NS,MAX_PORTABLE_ARCHIVE_MTIME_NS

MAX_ENTRIES=65536


def ordinary(path,kind):
    info=path_status(path)
    if path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not kind(info.st_mode):
        raise NativeWriteError(f'Unsafe filesystem object: {path.name}')
    return info


def scan_tree(root,writer):
    root=Path(root).absolute()
    directories=[];files=[]
    def visit(path,parts):
        writer.check_cancelled()
        info=ordinary(path,stat.S_ISDIR)
        directories.append(StagedDirectory(parts,info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns))
        if len(parts)>32 or len(directories)+len(files)>MAX_ENTRIES:
            raise NativeWriteError('The source tree exceeds its entry or depth bound')
        entries=sorted(path.iterdir(),key=lambda p:(p.name.casefold(),p.name))
        seen=set()
        for entry in entries:
            validate_staged_component(entry.name,entry.name)
            key=entry.name.casefold()
            if key in seen:
                raise NativeWriteError('Source names collide on a portable filesystem')
            seen.add(key)
            child=parts+(entry.name,)
            status=entry.lstat()
            if stat.S_ISDIR(status.st_mode):visit(entry,child)
            else:
                ordinary(entry,stat.S_ISREG)
                with entry.open('rb') as stream:
                    opened=descriptor_status(stream.fileno())
                    if (opened.st_dev,opened.st_ino)!=(status.st_dev,status.st_ino) or opened.st_nlink!=1:
                        raise NativeWriteError('The source file is replaced or multiply linked')
                    files.append(StagedFile(child,opened.st_dev,opened.st_ino,opened.st_size,
                                            opened.st_mtime_ns,opened.st_ctime_ns,opened.st_nlink))
        after=ordinary(path,stat.S_ISDIR)
        if (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)!=(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns):
            raise NativeWriteError('A source directory changed during scanning')
    visit(root,())
    return tuple(directories),tuple(files)


def consume(root,source,writer,callback=lambda data,offset:None):
    path=root.joinpath(*source.parts)
    # Revalidate all ancestors so a path cannot traverse a replaced junction.
    parent=root
    ordinary(parent,stat.S_ISDIR)
    for component in source.parts[:-1]:
        parent=parent/component;ordinary(parent,stat.S_ISDIR)
    ordinary(path,stat.S_ISREG)
    expected=(source.device,source.inode,source.size,source.modified_ns,source.changed_ns)
    digest=hashlib.sha256();done=0
    with path.open('rb') as stream:
        if file_identity(descriptor_status(stream.fileno()))!=expected:
            raise NativeWriteError('A staged source file changed')
        while data:=stream.read(BLOCK):
            writer.check_cancelled()
            if done+len(data)>source.size or file_identity(descriptor_status(stream.fileno()))!=expected:
                raise NativeWriteError('A staged source file changed while reading')
            callback(data,done);digest.update(data);done+=len(data)
        if done!=source.size or path_file_identity(path)!=expected:
            raise NativeWriteError('A staged source file changed while reading')
    return digest.hexdigest()


def construct_fat32(root,output,size,writer,progress=lambda *args:None,*,profile=None,priority_file=None,label='ISOPROPYL',cluster_size=None):
    """Reuse Linux's allocator/serializer and independently parse the result."""
    root=Path(root).absolute();output=Path(output).absolute()
    if output.is_relative_to(root) or output.exists() or output.is_symlink():
        raise NativeWriteError('FAT32 output must be a new file outside the source tree')
    directories,files=scan_tree(root,writer)
    for item in (*directories,*files):
        if not MIN_PORTABLE_ARCHIVE_MTIME_NS<=item.modified_ns<=MAX_PORTABLE_ARCHIVE_MTIME_NS:
            raise NativeWriteError('A staged timestamp is outside the portable FAT range')
    if any(item.size>0xFFFFFFFF for item in files):
        raise NativeWriteError('A file exceeds FAT32’s maximum size')
    hashes=tuple(consume(root,item,writer) for item in files)
    if scan_tree(root,writer)!=(directories,files):
        raise NativeWriteError('The staging tree changed while hashing')
    geometry=_geometry(size,cluster_size,maximum=2*1024**4)
    planned_dirs,planned_files,allocated=_layout(geometry,directories,files,hashes,priority_file=priority_file)
    signature,volume_id=_derive_media_ids(geometry,planned_dirs,planned_files)
    try:
        volume_label=label.upper().encode('ascii').ljust(11,b' ')
    except UnicodeEncodeError as error:raise NativeWriteError('FAT label must contain ASCII characters') from error
    if len(volume_label)!=11 or any(char in label for char in '*?.,;:/\\|+=<>[]"'):
        raise NativeWriteError('Invalid FAT volume label')
    plan=SimpleNamespace(geometry=geometry,directories=planned_dirs,files=planned_files,
        allocated_clusters=allocated,disk_signature=signature,volume_id=volume_id,
        profile=profile or PrivateFat32BuildProfile.GENERIC,volume_label=volume_label)
    try:
        with output.open('x+b') as image:
            output.chmod(0o600)
            from .native_layout import sparse_file
            sparse_file(image,size)
            def write(data,offset):
                writer.check_cancelled();image.seek(offset);image.write(data)
            write(_mbr(plan),0)
            boot,info=_boot_sector(plan),_fsinfo(plan)
            for sector,data in [(0,boot),(1,info),(6,boot),(7,info)]:write(data,geometry.volume_offset+sector*512)
            for n in range(2):
                start=geometry.volume_offset+(32+n*geometry.sectors_per_fat)*512
                for offset,table in fat_chunks(plan,writer.check_cancelled):write(table,start+offset)
            for directory in planned_dirs:write(_directory_content(plan,directory),_cluster_offset(geometry,directory.first_cluster))
            done=0;total=max(1,sum(item.size for item in files))
            for item in planned_files:
                start=_cluster_offset(geometry,item.first_cluster) if item.cluster_count else 0
                if consume(root,item.source,writer,lambda data,offset,start=start:write(data,start+offset))!=item.sha256:
                    raise NativeWriteError('A source changed while constructing FAT32')
                done+=item.source.size;progress('Constructing filesystem',done,total)
            if scan_tree(root,writer)!=(directories,files):
                raise NativeWriteError('The source tree changed during construction')
            image.flush();os.fsync(image.fileno())
            progress('Independently verifying filesystem',0,1)
            parsed=inspect_regular_fat32_image(image.fileno(),cancel_check=writer.check_cancelled,maximum_image_bytes=2*1024**4,maximum_fat_bytes=1024**3)
            if parsed.entries!=_expected_entries(plan) or parsed.content_bytes!=sum(item.size for item in files):
                raise NativeWriteError('FAT32 filesystem verification failed')
        progress('Independently verifying filesystem',1,1)
        return plan
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def fat_chunks(plan,cancel_check=lambda:None):
    """Serialize FAT tables in bounded chunks, including mandatory zeros."""
    import struct
    size=plan.geometry.sectors_per_fat*512
    allocations=(*plan.directories,*plan.files)
    for offset in range(0,size,BLOCK):
        cancel_check();data=bytearray(min(BLOCK,size-offset))
        first=offset//4;last=(offset+len(data))//4
        if offset==0:struct.pack_into('<II',data,0,0x0ffffff8,0x0fffffff)
        for item in allocations:
            end=item.first_cluster+item.cluster_count
            for cluster in range(max(first,item.first_cluster),min(last,end)):
                following=cluster+1 if cluster+1<end else 0x0fffffff
                struct.pack_into('<I',data,(cluster-first)*4,following)
        yield offset,bytes(data)
