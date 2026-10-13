"""Device-free, independently parsed metadata for a blank MBR/FAT32 drive."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import secrets
import struct
import tempfile
from types import SimpleNamespace

from . import fat32_layout as fat
from .fat_image import inspect_regular_fat32_image
from .native_writer import NativeWriteError


def blank_fat32(size, cancel_check=lambda: None):
    """Return fixed metadata extents; all other bytes in the image are zero."""
    cancel_check()
    geometry = fat._geometry(size, maximum=2*1024**4)
    plan = SimpleNamespace(geometry=geometry, disk_signature=secrets.randbelow(0xFFFFFFFE)+1,
                           volume_id=secrets.randbelow(0xFFFFFFFE)+1, allocated_clusters=1,
                           directories=(SimpleNamespace(first_cluster=2,cluster_count=1),), files=())
    boot, info = fat._boot_sector(plan), fat._fsinfo(plan)
    table=struct.pack('<III',0x0ffffff8,0x0fffffff,0x0fffffff)
    metadata = [(0, fat._mbr(plan))]
    for sector, data in [(0,boot),(1,info),(6,boot),(7,info)]:
        metadata.append((geometry.volume_offset+sector*512,data))
    for number in range(2):
        metadata.append((geometry.volume_offset+(32+number*geometry.sectors_per_fat)*512,table))
    root = bytearray(geometry.cluster_bytes)
    root[:11] = fat.VOLUME_LABEL
    root[11] = 0x08
    metadata.append((fat._cluster_offset(geometry,2),bytes(root)))
    # Independent parser checks a sparse regular image without mounting it or
    # depending on either host's filesystem-formatting commands.
    with tempfile.TemporaryFile() as image:
        from .native_layout import sparse_file
        sparse_file(image,size)
        for offset, data in metadata:
            cancel_check(); image.seek(offset); image.write(data)
        image.flush()
        inspected = inspect_regular_fat32_image(image.fileno(),cancel_check=cancel_check,maximum_image_bytes=2*1024**4,maximum_fat_bytes=1024**3)
        if inspected.entries or inspected.content_bytes:
            raise NativeWriteError('Blank FAT32 metadata failed independent validation')
    return tuple(sorted(metadata))


def formatted_chunk(metadata, offset, size):
    data = bytearray(size)
    for start, payload in metadata:
        left, right = max(offset,start), min(offset+size,start+len(payload))
        if left < right:
            data[left-offset:right-offset] = payload[left-start:right-start]
    return bytes(data)
