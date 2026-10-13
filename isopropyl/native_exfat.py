"""Portable empty exFAT construction with independently checked metadata."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import secrets
import struct
from .native_layout import sparse_file
from .native_writer import NativeWriteError


def checksum(data, *, boot=False):
    value = 0
    for index, byte in enumerate(data):
        if boot and index in {106, 107, 112}: continue
        value = (((value & 1) << 31) | (value >> 1)) + byte
        value &= 0xffffffff
    return value


def create_exfat(image, size, writer, *, label='ISOPROPYL', cluster_size=None,sector_size=512):
    if sector_size not in {512,1024,2048,4096}:raise NativeWriteError('Unsupported exFAT logical sector size')
    if size < 8*1024*1024 or size % sector_size:
        raise NativeWriteError('exFAT requires an aligned volume of at least 8 MiB')
    allocation = cluster_size or (4096 if size < 256*1024*1024 else 32768 if size < 32*1024**3 else 131072)
    if allocation < sector_size or allocation > 32*1024*1024 or allocation & (allocation-1):
        raise NativeWriteError('Invalid exFAT allocation unit')
    name = label.encode('utf-16-le')
    if len(name)>22 or any(char in label for char in '"*/:<>?\\|'):
        raise NativeWriteError('exFAT labels support at most 11 UTF-16 characters')
    sectors = size//sector_size; spc = allocation//sector_size; fat_start = 128
    fat_sectors = ((sectors//spc+2)*4+sector_size-1)//sector_size
    heap = ((fat_start+fat_sectors+spc-1)//spc)*spc
    count = (sectors-heap)//spc
    if not 1 <= count <= 0xfffffff5: raise NativeWriteError('Invalid exFAT cluster count')
    bitmap_size = (count+7)//8
    bitmap_clusters = (bitmap_size+allocation-1)//allocation
    # Uncompressed BMP upcase table is valid exFAT and avoids locale-dependent
    # compressed-run interpretation. Multi-character mappings stay unchanged.
    upcase = bytearray()
    for code in range(65536):
        upper = chr(code).upper()
        mapped = ord(upper) if len(upper)==1 and ord(upper)<=65535 else code
        upcase.extend(struct.pack('<H', mapped))
    upcase_clusters = (len(upcase)+allocation-1)//allocation
    root_cluster = 2+bitmap_clusters+upcase_clusters
    if root_cluster-1 > count: raise NativeWriteError('exFAT metadata exceeds volume capacity')
    def fat_chunks():
        for position in range(0,fat_sectors*sector_size,4*1024*1024):
            writer.check_cancelled();data=bytearray(min(4*1024*1024,fat_sectors*sector_size-position))
            first=position//4;last=first+len(data)//4
            if position==0:struct.pack_into('<II',data,0,0xfffffff8,0xffffffff)
            for start,length in [(2,bitmap_clusters),(2+bitmap_clusters,upcase_clusters),(root_cluster,1)]:
                for cluster in range(max(start,first),min(start+length,last)):
                    struct.pack_into('<I',data,(cluster-first)*4,0xffffffff if cluster==start+length-1 else cluster+1)
            yield position,bytes(data)
    def bitmap_chunks():
        marked=root_cluster-1;whole,remainder=divmod(marked,8)
        for position in range(0,bitmap_clusters*allocation,4*1024*1024):
            writer.check_cancelled();data=bytearray(min(4*1024*1024,bitmap_clusters*allocation-position))
            prefix=max(0,min(len(data),whole-position))
            if prefix:data[:prefix]=b'\xff'*prefix
            if remainder and position<=whole<position+len(data):data[whole-position]=(1<<remainder)-1
            yield position,bytes(data)
    boot = bytearray(12*sector_size)
    boot[:3]=b'\xeb\x76\x90';boot[3:11]=b'EXFAT   '
    struct.pack_into('<QQIIIIIIHHBBBBB',boot,64,0,sectors,fat_start,fat_sectors,heap,count,root_cluster,
                     secrets.randbits(32),0x100,0,sector_size.bit_length()-1,spc.bit_length()-1,1,0x80,0)
    boot[510:512]=b'\x55\xaa'
    for sector in range(1,9):boot[(sector+1)*sector_size-4:(sector+1)*sector_size]=b'\x00\x00\x55\xaa'
    value=checksum(boot[:11*sector_size],boot=True)
    boot[11*sector_size:]=struct.pack('<I',value)*(sector_size//4)
    root = bytearray(allocation)
    root[0]=0x83;root[1]=len(name)//2;root[2:2+len(name)]=name
    root[32]=0x81;struct.pack_into('<IQ',root,52,2,bitmap_size)
    root[64]=0x82;struct.pack_into('<I',root,68,checksum(upcase));struct.pack_into('<IQ',root,84,2+bitmap_clusters,len(upcase))
    def offset(cluster):return heap*sector_size+(cluster-2)*allocation
    with image.open('x+b') as output:
        image.chmod(0o600);sparse_file(output,size)
        for position,data in [(0,boot),(12*sector_size,boot),(offset(2+bitmap_clusters),upcase),(offset(root_cluster),root)]:
            writer.check_cancelled();output.seek(position);output.write(data)
        for position,data in fat_chunks():
            output.seek(fat_start*sector_size+position);output.write(data)
        for position,data in bitmap_chunks():
            output.seek(offset(2)+position);output.write(data)
        output.flush();os.fsync(output.fileno())
    verify_exfat(image, label, writer,expected_sector_size=sector_size)
    return 0,size,None


def verify_exfat(image, label, writer,*,expected_sector_size=None):
    """Read fields and resolve allocations independently from their serializer."""
    with image.open('rb') as source:
        initial=source.read(512);sector_size=1 << initial[108]
        if expected_sector_size is not None and expected_sector_size!=sector_size:raise NativeWriteError('exFAT requested logical-sector verification failed')
        if sector_size not in {512,1024,2048,4096}:raise NativeWriteError('Invalid exFAT logical sector size')
        source.seek(0);boot=source.read(12*sector_size);backup=source.read(12*sector_size)
        if boot != backup or boot[3:11] != b'EXFAT   ' or boot[510:512] != b'\x55\xaa':
            raise NativeWriteError('exFAT boot-region verification failed')
        value=checksum(boot[:11*sector_size],boot=True)
        if boot[11*sector_size:] != struct.pack('<I',value)*(sector_size//4):raise NativeWriteError('exFAT boot checksum failed')
        sectors=struct.unpack_from('<Q',boot,72)[0]
        fat,_,heap,count,root=struct.unpack_from('<IIIII',boot,80)
        cluster_bytes=1 << (boot[108]+boot[109])
        if sectors*sector_size != image.stat().st_size or count != (sectors-heap)//(cluster_bytes//sector_size):
            raise NativeWriteError('exFAT capacity verification failed')
        def read_cluster(cluster,size):
            if not 2<=cluster<=count+1:raise NativeWriteError('exFAT allocation points outside volume')
            source.seek(heap*sector_size+(cluster-2)*cluster_bytes);data=source.read(size)
            if len(data)!=size:raise NativeWriteError('exFAT metadata is truncated')
            writer.check_cancelled();return data
        directory=read_cluster(root,cluster_bytes)
        if directory[0]!=0x83 or directory[2:2+directory[1]*2].decode('utf-16-le')!=label:
            raise NativeWriteError('exFAT label verification failed')
        if directory[32]!=0x81 or directory[64]!=0x82 or any(directory[96:]):
            raise NativeWriteError('exFAT root directory verification failed')
        cluster,length=struct.unpack_from('<IQ',directory,52)
        if length!=(count+7)//8:raise NativeWriteError('exFAT allocation bitmap capacity failed')
        source.seek(heap*sector_size+(cluster-2)*cluster_bytes)
        done=0;marked=root-1;whole,remainder=divmod(marked,8)
        while done<length:
            writer.check_cancelled();amount=min(4*1024*1024,length-done);data=source.read(amount)
            if len(data)!=amount:raise NativeWriteError('exFAT allocation bitmap is truncated')
            expected=bytearray(amount);prefix=max(0,min(amount,whole-done))
            if prefix:expected[:prefix]=b'\xff'*prefix
            if remainder and done<=whole<done+amount:expected[whole-done]=(1<<remainder)-1
            if data!=expected:raise NativeWriteError('exFAT allocation bitmap verification failed')
            done+=amount
        cluster,length=struct.unpack_from('<IQ',directory,84)
        data=read_cluster(cluster,length)
        if checksum(data)!=struct.unpack_from('<I',directory,68)[0]:raise NativeWriteError('exFAT upcase checksum failed')
        source.seek(fat*sector_size+root*4)
        if source.read(4)!=b'\xff'*4:raise NativeWriteError('exFAT root allocation verification failed')
