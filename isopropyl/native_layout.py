"""Portable MBR/GPT composition from verified regular filesystem images."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import binascii
import hashlib
import os
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from .native_writer import BLOCK,NativeWriteError,file_identity,path_file_identity
from .partition_tables import PARTITION_TABLE_CAPTURE_BYTES,inspect_partition_tables_capture

MIB=1024*1024
GUIDS={'efi':'c12a7328-f81f-11d2-ba4b-00a0c93ec93b','fat32':'c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
       'ntfs':'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7','exfat':'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',
       'ext2':'0fc63daf-8483-4772-8e79-3d69d8477de4','ext3':'0fc63daf-8483-4772-8e79-3d69d8477de4',
       'ext4':'0fc63daf-8483-4772-8e79-3d69d8477de4','data':'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'}
MBR_TYPES={'efi':0xEF,'fat32':0x0C,'fat16':0x0E,'fat12':0x01,'ntfs':0x07,'exfat':0x07,'udf':0x07,'ext2':0x83,'ext3':0x83,'ext4':0x83,'data':0x07}


@dataclass(frozen=True)
class Volume:
    path: Path
    source_offset: int
    size: int
    filesystem: str
    label: str='ISOPROPYL'
    metadata_ranges: tuple=()
    gpt_type: str | None=None


def sparse_file(stream,size):
    if os.name=='nt':
        import ctypes,msvcrt
        from ctypes import wintypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.DeviceIoControl.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
        count=wintypes.DWORD()
        if not kernel.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()),0x900C4,None,0,None,0,ctypes.byref(count),None):
            raise OSError('Could not mark private image as sparse')
    stream.truncate(size)
    if sys.platform=='darwin' and size:
        # APFS ftruncate initially retains zero/unwritten allocation; explicit
        # punching makes SEEK_DATA/HOLE distinguish those from zero metadata.
        import fcntl
        fcntl.fcntl(stream.fileno(),99,struct.pack('=IIqq',0,0,0,size))


def _gpt_header(current,alternate,last_usable,disk_id,table_lba,table_crc,sector_size=512):
    result=bytearray(sector_size)
    struct.pack_into('<8sIIIIQQQQ16sQIII',result,0,b'EFI PART',0x10000,92,0,0,current,alternate,2+(128*128+sector_size-1)//sector_size,
                     last_usable,disk_id,table_lba,128,128,table_crc)
    struct.pack_into('<I',result,16,binascii.crc32(result[:92])&0xFFFFFFFF)
    return bytes(result)


def compose_disk(volumes,output,total_size,partition_table,writer,progress=lambda *args:None,*,active=False,sector_size=512):
    if sector_size not in {512,1024,2048,4096}:raise NativeWriteError('Unsupported partition sector size')
    if partition_table not in {'mbr','gpt'} or not 1<=len(volumes)<=4 or total_size%sector_size:
        raise NativeWriteError('Unsupported partition layout')
    starts=[];end=MIB
    for volume in volumes:
        if volume.size<=0 or volume.size%sector_size or volume.source_offset%sector_size or volume.filesystem not in MBR_TYPES:
            raise NativeWriteError('Invalid filesystem image geometry')
        start=((end+MIB-1)//MIB)*MIB;starts.append(start);end=start+volume.size
    last_lba=total_size//sector_size-1
    table_sectors=(128*128+sector_size-1)//sector_size
    reserve=(table_sectors+1)*sector_size if partition_table=='gpt' else 0
    if end>total_size-reserve:raise NativeWriteError('The partition layout exceeds the selected target')
    mbr=bytearray(sector_size);mbr[510:512]=b'\x55\xaa';struct.pack_into('<I',mbr,440,uuid.uuid4().int&0xFFFFFFFF)
    if partition_table=='mbr':
        for index,(volume,start) in enumerate(zip(volumes,starts)):
            if start//sector_size>0xFFFFFFFF or volume.size//sector_size>0xFFFFFFFF:raise NativeWriteError('MBR layout exceeds its sector bounds')
            slot=446+index*16;mbr[slot]=0x80 if active and index==0 else 0;mbr[slot+4]=MBR_TYPES[volume.filesystem]
            mbr[slot+1:slot+4]=b'\xfe\xff\xff';mbr[slot+5:slot+8]=b'\xfe\xff\xff'
            struct.pack_into('<II',mbr,slot+8,start//sector_size,volume.size//sector_size)
    else:
        mbr[450]=0xEE;struct.pack_into('<II',mbr,454,1,min(last_lba,0xFFFFFFFF))
        mbr[440:446]=bytes(6);mbr[447:450]=b'\x00\x02\x00';mbr[451:454]=b'\xff\xff\xff'
    try:
        with output.open('x+b') as image:
            output.chmod(0o600);sparse_file(image,total_size);image.seek(0);image.write(mbr)
            if partition_table=='gpt':
                table=bytearray(128*128)
                for index,(volume,start) in enumerate(zip(volumes,starts)):
                    slot=index*128;kind=volume.gpt_type or GUIDS.get(volume.filesystem,GUIDS['data'])
                    struct.pack_into('<16s16sQQQ',table,slot,uuid.UUID(kind).bytes_le,uuid.uuid4().bytes_le,
                                     start//sector_size,(start+volume.size)//sector_size-1,0)
                    name=volume.label.encode('utf-16-le')[:72];table[slot+56:slot+56+len(name)]=name
                crc=binascii.crc32(table)&0xFFFFFFFF;disk_id=uuid.uuid4().bytes_le
                image.seek(2*sector_size);image.write(table)
                image.seek((last_lba-table_sectors)*sector_size);image.write(table)
                image.seek(sector_size);image.write(_gpt_header(1,last_lba,last_lba-table_sectors-1,disk_id,2,crc,sector_size))
                image.seek(last_lba*sector_size);image.write(_gpt_header(last_lba,1,last_lba-table_sectors-1,disk_id,last_lba-table_sectors,crc,sector_size))
            total=sum(v.size for v in volumes);done=0
            for volume,start in zip(volumes,starts):
                identity=path_file_identity(volume.path)
                with volume.path.open('rb',buffering=0) as source:
                    if volume.source_offset+volume.size>identity[2]:raise NativeWriteError('Filesystem image is truncated')
                    from .native_sparse import iter_allocated_ranges,merge_ranges
                    if volume.metadata_ranges:
                        ranges=merge_ranges(volume.metadata_ranges,volume.size)
                    elif volume.filesystem in {'fat12','fat16','fat32','exfat','ntfs','ext2','ext3','ext4','udf'}:
                        from .native_fsmetadata import metadata_ranges
                        ranges=metadata_ranges(volume.path,volume.filesystem,writer,offset=volume.source_offset,size=volume.size)
                    else:
                        allocated=[(offset-volume.source_offset,length) for offset,length in
                                   iter_allocated_ranges(source.fileno(),start=volume.source_offset,length=volume.size,cancel_check=writer.check_cancelled)]
                        ranges=merge_ranges(allocated,volume.size)
                    for offset,length in ranges:
                        copied=0
                        while copied<length:
                            writer.check_cancelled();source.seek(volume.source_offset+offset+copied)
                            data=source.read(min(BLOCK,length-copied))
                            if not data:raise NativeWriteError('Filesystem image ended unexpectedly')
                            # Explicit zero metadata must remain allocated in the
                            # final sparse image for quick-restore semantics.
                            image.seek(start+offset+copied);image.write(data)
                            copied+=len(data);done+=len(data);progress('Composing partition layout',done,total)
                    if file_identity(os.fstat(source.fileno()))!=identity:raise NativeWriteError('Filesystem source changed during composition')
            image.flush();os.fsync(image.fileno())
            size=min(total_size,PARTITION_TABLE_CAPTURE_BYTES);image.seek(0);prefix=image.read(size)
            image.seek(total_size-size);tail=image.read(size)
            inspected=inspect_partition_tables_capture(prefix,tail,total_size)
            if partition_table=='mbr' and sector_size!=512:
                from .partition_tables import _CapturedReader,_parse_mbr
                parsed_mbr=_parse_mbr(_CapturedReader(prefix,tail,total_size),sector_size)
                if not parsed_mbr.valid:raise NativeWriteError('Independent logical-sector MBR verification failed')
            if partition_table=='gpt' and sector_size in {1024,2048}:
                from .partition_tables import _CapturedReader,_parse_gpt_candidate
                candidate=_parse_gpt_candidate(_CapturedReader(prefix,tail,total_size),sector_size)
                if not candidate.valid:raise NativeWriteError('Independent logical-sector GPT verification failed: '+'; '.join(candidate.issues))
            elif not inspected.valid or not inspected.complete or inspected.malformed:
                raise NativeWriteError('Independent partition-table verification failed: '+'; '.join(inspected.issues))
        return tuple(starts)
    except BaseException:
        output.unlink(missing_ok=True);raise
