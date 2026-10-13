"""Empty FAT12/16/32 volumes using the selected logical sector geometry."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import struct
import uuid
from .native_writer import NativeWriteError,BLOCK
from .native_layout import sparse_file


def create_small_fat(image,size,kind,writer,*,label='ISOPROPYL',cluster_size=None,sector_size=512):
    if kind not in {'fat12','fat16','fat32'} or sector_size not in ({512,1024,2048,4096} if kind=='fat32' else {512,4096}) or size%sector_size or size<1024*1024:
        raise NativeWriteError('Invalid empty FAT geometry')
    bits={'fat12':12,'fat16':16,'fat32':32}[kind]
    maximum={12:4084,16:65524,32:0x0fffffee}[bits]
    minimum={12:16,16:4085,32:65525}[bits]
    reserved=32 if bits==32 else 1
    root_sectors=0 if bits==32 else (512*32+sector_size-1)//sector_size
    total=size//sector_size
    choices=[cluster_size//sector_size] if cluster_size else [1,2,4,8,16,32,64,128]
    geometry=None
    for clusters in choices:
        if clusters not in {1,2,4,8,16,32,64,128}:continue
        sectors_per_fat=1
        for _ in range(64):
            count=(total-reserved-root_sectors-2*sectors_per_fat)//clusters
            needed=(((count+2)*bits+7)//8+sector_size-1)//sector_size
            if needed<=sectors_per_fat:break
            sectors_per_fat=needed
        count=(total-reserved-root_sectors-2*sectors_per_fat)//clusters
        if minimum<=count<=maximum:
            geometry=clusters,sectors_per_fat,count;break
    if geometry is None:raise NativeWriteError('The selected drive/allocation unit does not fit this FAT variant')
    clusters,sectors_per_fat,count=geometry
    try:volume_label=label.upper().encode('ascii').ljust(11,b' ')
    except UnicodeEncodeError as error:raise NativeWriteError('FAT label must be ASCII') from error
    if len(volume_label)!=11 or any(char in label for char in '*?.,;:/\\|+=<>[]"') or any(ord(c)<32 for c in label):
        raise NativeWriteError('Invalid FAT label')
    boot=bytearray(sector_size);boot[:3]=b'\xeb\x58\x90' if bits==32 else b'\xeb\x3c\x90';boot[3:11]=b'ISOPROPY'
    struct.pack_into('<H',boot,11,sector_size);boot[13]=clusters;struct.pack_into('<H',boot,14,reserved)
    boot[16]=2;struct.pack_into('<H',boot,17,0 if bits==32 else 512)
    struct.pack_into('<H',boot,19,total if total<=65535 and bits!=32 else 0);boot[21]=0xF8
    struct.pack_into('<H',boot,22,0 if bits==32 else sectors_per_fat)
    struct.pack_into('<HHI',boot,24,63,255,1024*1024//sector_size)
    struct.pack_into('<I',boot,32,total if total>65535 or bits==32 else 0)
    identity=uuid.uuid4().int&0xFFFFFFFF
    if bits==32:
        struct.pack_into('<I',boot,36,sectors_per_fat);struct.pack_into('<I',boot,44,2)
        struct.pack_into('<HH',boot,48,1,6);boot[64]=0x80;boot[66]=0x29
        struct.pack_into('<I',boot,67,identity);boot[71:82]=volume_label;boot[82:90]=b'FAT32   '
    else:
        boot[36]=0x80;boot[38]=0x29;struct.pack_into('<I',boot,39,identity)
        boot[43:54]=volume_label;boot[54:62]=kind.upper().encode().ljust(8,b' ')
    boot[510:512]=b'\x55\xaa'
    root=bytearray(clusters*sector_size if bits==32 else root_sectors*sector_size)
    root[:11]=volume_label;root[11]=8
    metadata=[(0,bytes(boot))]
    if bits==32:
        info=bytearray(sector_size);struct.pack_into('<I',info,0,0x41615252)
        struct.pack_into('<III',info,484,0x61417272,count-1,3);struct.pack_into('<I',info,508,0xaa550000)
        metadata += [(sector_size,bytes(info)),(6*sector_size,bytes(boot)),(7*sector_size,bytes(info))]
    table_size=sectors_per_fat*sector_size
    with image.open('x+b') as output:
        image.chmod(0o600);sparse_file(output,size)
        for position,data in metadata:writer.check_cancelled();output.seek(position);output.write(data)
        # Reserved sectors, FAT free entries and directory padding are all
        # mandatory zero metadata; emit bounded chunks even when all-zero.
        if bits==32:
            for position in range(0,reserved*sector_size,sector_size):
                if position not in dict(metadata):output.seek(position);output.write(bytes(sector_size))
        for copy in range(2):
            for position in range(0,table_size,BLOCK):
                writer.check_cancelled();data=bytearray(min(BLOCK,table_size-position))
                if position==0:
                    data[:3 if bits==12 else 4 if bits==16 else 12]=b'\xf8\xff\xff' if bits==12 else b'\xf8\xff\xff\xff' if bits==16 else struct.pack('<III',0x0ffffff8,0x0fffffff,0x0fffffff)
                output.seek((reserved+copy*sectors_per_fat)*sector_size+position);output.write(data)
        output.seek((reserved+2*sectors_per_fat)*sector_size);output.write(root)
        output.flush();os.fsync(output.fileno())
    return tuple(metadata)
