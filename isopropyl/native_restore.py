"""Prepare and verify native restore filesystems before opening a target."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import tempfile
from pathlib import Path

from .native_writer import BLOCK, NativeWriteError
from .native_layout import MIB, Volume, compose_disk

FILESYSTEMS = ('fat12','fat16','fat32','exfat','ntfs','udf','ext2','ext3','ext4')


def validate_restore_options(size, filesystem, partition_table, label, cluster_size,*,logical_sector_size=512):
    if filesystem not in FILESYSTEMS or partition_table not in {'mbr','gpt'}:
        raise NativeWriteError('Choose a supported restore filesystem and MBR or GPT')
    from .formatting import Filesystem,restore_filesystem_geometry_supported,restore_allocation_unit_sizes,validate_label
    try:validate_label(Filesystem(filesystem),label)
    except ValueError as error:raise NativeWriteError(str(error)) from error
    if not restore_filesystem_geometry_supported(Filesystem(filesystem),size,logical_sector_size,partition_table):
        raise NativeWriteError('The selected filesystem does not support this drive size')
    if cluster_size is not None and filesystem!='udf' and cluster_size not in restore_allocation_unit_sizes(Filesystem(filesystem),size,logical_sector_size,partition_table):
        raise NativeWriteError('The selected allocation size does not support this filesystem geometry')
    if size < 4*MIB or size%512:
        raise NativeWriteError('The restore target must contain at least 4 MiB of complete sectors')
    if not isinstance(label,str) or '\x00' in label or any(ord(c)<32 for c in label):
        raise NativeWriteError('The volume label contains invalid characters')
    limit=11 if filesystem.startswith('fat') or filesystem=='exfat' else 16 if filesystem.startswith('ext') else 32 if filesystem=='ntfs' else 126
    if len(label.encode('utf-16-le'))//2>limit:
        raise NativeWriteError(f'{filesystem.upper()} volume labels are limited to {limit} characters')
    if filesystem.startswith('ext') and len(label.encode('utf-8'))>16:
        raise NativeWriteError('Linux filesystem labels are limited to 16 UTF-8 bytes')
    if cluster_size is not None and (not isinstance(cluster_size,int) or cluster_size<512 or cluster_size & (cluster_size-1)):
        raise NativeWriteError('Allocation size must be a power of two of at least 512 bytes')
    if filesystem.startswith('ext') and cluster_size not in {None,1024,2048,4096}:
        raise NativeWriteError('Linux filesystem block size must be 1024, 2048 or 4096 bytes')
    if filesystem=='udf' and cluster_size not in {None,logical_sector_size}:
        raise NativeWriteError('UDF block size must match the target logical sector size')


def prepare_restore_image(plan, workspace, writer, progress=lambda *args:None):
    """Return a sparse regular whole-drive image whose empty FS is inspected."""
    from .native_filesystems import construct_volume, verify_filesystem
    sector=getattr(getattr(getattr(plan,'target',None),'device',None),'logical_sector_size',512)
    validate_restore_options(plan.size,plan.filesystem,plan.partition_table,plan.label,plan.cluster_size,logical_sector_size=sector)
    table_sectors=(128*128+sector-1)//sector
    reserve=(table_sectors+1)*sector if plan.partition_table=='gpt' else 0
    volume_size=((plan.size-MIB-reserve)//sector)*sector
    tree=workspace/'empty-tree';tree.mkdir(mode=0o700)
    image=workspace/'volume.img';kind=plan.filesystem
    if kind in {'fat12','fat16'} or kind=='fat32' and sector!=512:
        from .native_small_fat import create_small_fat
        create_small_fat(image,volume_size,kind,writer,label=plan.label,cluster_size=plan.cluster_size,sector_size=sector)
        verify_filesystem(image,{},kind,writer,label=plan.label,cluster_size=plan.cluster_size,sector_size=sector)
        offset,size=0,volume_size
    elif kind=='exfat':
        from .native_exfat import create_exfat
        offset,size,_=create_exfat(image,volume_size,writer,label=plan.label,cluster_size=plan.cluster_size,sector_size=sector)
    elif kind=='udf':
        from .helper_tools import helper
        from .native_virtual import run_native_command
        from .native_layout import sparse_file
        with image.open('xb') as output:sparse_file(output,volume_size)
        block=plan.cluster_size or sector
        run_native_command([helper('mkudffs'),'--utf8','--media-type=hd','--blocksize='+str(block),
                            '--label='+plan.label,str(image)],writer)
        verify_udf(image,block,writer,label=plan.label)
        offset,size=0,volume_size
    else:
        # FAT32 constructor includes its own 1-MiB MBR prefix. Only its
        # verified partition range is copied into the requested final layout.
        requested=volume_size+MIB if kind=='fat32' else volume_size
        offset,size,_=construct_volume(tree,image,requested,kind,writer,progress,label=plan.label,cluster_size=plan.cluster_size,sector_size=sector)
    output=workspace/'restore.img'
    from .native_fsmetadata import metadata_ranges
    required=metadata_ranges(image,kind,writer,offset=offset,size=size)
    starts=compose_disk([Volume(image,offset,size,kind,plan.label,required,'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' if kind.startswith('fat') else None)],output,plan.size,plan.partition_table,writer,progress,active=getattr(plan,'operation','restore')=='format_fat32',sector_size=sector)
    # Filesystem allocation is authoritative even on filesystems that report
    # every unwritten zero extent as SEEK_DATA (some APFS implementations).
    import json
    extents=[(starts[0]+position,length) for position,length in required]
    extents += [(0,2*sector),(plan.size-sector,sector)]
    if plan.partition_table=='gpt':extents += [(0,(table_sectors+2)*sector),(plan.size-reserve,reserve)]
    (workspace/'restore-ranges.json').write_text(json.dumps(extents),encoding='utf-8')
    image.unlink()
    return output


def verify_udf(image,block,writer,*,label=None):
    """Inspect mirrored UDF anchors, descriptor tags and their CRCs."""
    import binascii
    import struct
    with image.open('rb') as source:
        def descriptor(sector,location=None):
            expected_location=location
            source.seek(sector*block);data=source.read(block);writer.check_cancelled()
            if len(data)!=block or sum(data[:4]+data[5:16])%256!=data[4]:
                raise NativeWriteError('UDF descriptor tag checksum failed')
            ident,version=struct.unpack_from('<HH',data)
            crc,length,location=struct.unpack_from('<HHI',data,8)
            if version not in {2,3} or location!=(sector if expected_location is None else expected_location) or length>block-16 or binascii.crc_hqx(data[16:16+length],0)!=crc:
                raise NativeWriteError('UDF descriptor location or CRC failed')
            return ident,data
        sectors=image.stat().st_size//block
        anchors=[descriptor(sector) for sector in (256,sectors-257,sectors-1)]
        if any(ident!=2 for ident,_ in anchors):raise NativeWriteError('UDF anchor verification failed')
        extent=anchors[0][1][16:32]
        if any(data[16:32]!=extent for _,data in anchors):raise NativeWriteError('UDF mirrored anchors disagree')
        length,start=struct.unpack_from('<II',extent)
        if length<=0 or start*block+length>image.stat().st_size:raise NativeWriteError('UDF descriptor extent exceeds volume')
        types=set();descriptors={}
        for sector in range(start,start+(length+block-1)//block):
            ident,data=descriptor(sector);types.add(ident);descriptors[ident]=data
            if ident==8:break
        if not {1,5,6,8}.issubset(types):raise NativeWriteError('UDF volume descriptor sequence is incomplete')
        logical=descriptors[6];partition=descriptors[5]
        if struct.unpack_from('<I',logical,212)[0]!=block:
            raise NativeWriteError('UDF logical block size differs from requested size')
        dstring=logical[84:212];length=dstring[-1]
        if length<1 or length>127:raise NativeWriteError('UDF label encoding is invalid')
        encoded=dstring[1:length]
        actual_label=encoded.decode('latin1') if dstring[0]==8 else encoded.decode('utf-16-be') if dstring[0]==16 else None
        if label is not None and actual_label!=label:raise NativeWriteError('UDF label verification failed')
        start,count=struct.unpack_from('<II',partition,188)
        if start+count>sectors:raise NativeWriteError('UDF partition exceeds volume capacity')
        fsd_position=struct.unpack_from('<I',logical,252)[0]
        ident,fileset=descriptor(start+fsd_position,fsd_position)
        if ident!=256:raise NativeWriteError('UDF file set descriptor is missing')
        root_position=struct.unpack_from('<I',fileset,404)[0]
        ident,root=descriptor(start+root_position,root_position)
        if ident not in {261,266} or root[27]!=4:
            raise NativeWriteError('UDF root directory is missing')
        if struct.unpack_from('<H',root,34)[0]&7 != 3:
            raise NativeWriteError('UDF empty root directory must use inline allocation')
        base=176 if ident==261 else 216
        attributes=struct.unpack_from('<I',root,base-8)[0]
        allocated=struct.unpack_from('<I',root,base-4)[0]
        information=struct.unpack_from('<Q',root,56)[0]
        data=root[base+attributes:base+attributes+allocated]
        if len(data)!=allocated or information!=allocated:
            raise NativeWriteError('UDF root directory allocation is inconsistent')
        position=0
        while position<len(data):
            if len(data)-position<38:raise NativeWriteError('UDF directory entry is truncated')
            entry=data[position:];name_length=entry[19];implementation=struct.unpack_from('<H',entry,36)[0]
            length=(38+implementation+name_length+3)//4*4
            if length>len(entry) or struct.unpack_from('<H',entry)[0]!=257 or not entry[18]&8 or name_length:
                raise NativeWriteError('UDF restored filesystem is not empty')
            position+=length


def run_restore(plan, writer, progress):
    from .native_tools import _locked_target, _read_exact
    with tempfile.TemporaryDirectory(prefix='isopropyl-restore-',dir=writer.temp_directory) as directory:
        image=prepare_restore_image(plan,Path(directory),writer,progress)
        sector=plan.target.device.logical_sector_size
        target=writer.revalidate(plan)
        with image.open('rb',buffering=0) as source,writer.opener(target,writer.host) as disk:
            _locked_target(writer,plan)
            # Keep MBR and GPT activation headers absent until payload
            # readback succeeds. A failed/cancelled restore stays inactive.
            # Invalidate old GPT headers too when restoring an MBR layout.
            positions=[0,sector,plan.size-sector]
            headers={}
            for offset in positions:
                source.seek(offset);headers[offset]=source.read(sector)
                if len(headers[offset])!=sector:raise NativeWriteError('The private restore image is truncated')
                disk.seek(offset);writer.write_started=True;writer.write_all(disk,bytes(sector))
            from .native_sparse import iter_allocated_ranges,merge_ranges
            if plan.quick:
                import json
                allocation_map=image.parent/'restore-ranges.json'
                if allocation_map.is_file():
                    extents=json.loads(allocation_map.read_text(encoding='utf-8'))
                else:extents=list(iter_allocated_ranges(source.fileno(),cancel_check=writer.check_cancelled))
                # Erase stale backup GPT signatures even for an MBR restore.
                extents.extend([(0,2*sector),(plan.size-sector,sector)])
                extents=merge_ranges([(position//sector*sector,((position+length+sector-1)//sector-position//sector)*sector) for position,length in extents],plan.size)
            else:extents=((0,plan.size),)
            written=sector*len(positions);skipped=plan.size-sum(length for _,length in extents)
            for range_start,range_size in extents:
              offset=range_start;range_end=range_start+range_size
              while offset<range_end:
                  writer.check_cancelled()
                  if offset in headers:offset+=sector;continue
                  boundary=min((position for position in positions if position>offset),default=range_end)
                  size=min(BLOCK,range_end-offset,boundary-offset)
                  source.seek(offset);expected=source.read(size)
                  if len(expected)!=size:raise NativeWriteError('The private restore image is truncated')
                  disk.seek(offset)
                  same=plan.quick and _read_exact(disk,size,writer)==expected
                  if same:skipped+=size
                  else:
                      _locked_target(writer,plan);disk.seek(offset);writer.write_started=True
                      writer.write_all(disk,expected);written+=size
                  offset+=size;progress('Restoring drive',offset,plan.size)
            disk.flush()
            for range_start,range_size in extents:
              offset=range_start;range_end=range_start+range_size
              while offset<range_end:
                  writer.check_cancelled();disk.seek(offset)
                  if offset in headers:
                      size=sector
                      if any(_read_exact(disk,size,writer)):
                          raise NativeWriteError('An inactive restore activation header changed; activation headers were not published')
                  else:
                      boundary=min((position for position in positions if position>offset),default=range_end)
                      size=min(BLOCK,range_end-offset,boundary-offset);source.seek(offset)
                      if _read_exact(disk,size,writer)!=source.read(size):
                          raise NativeWriteError(f'Restored filesystem readback failed at byte {offset}; activation headers were not published')
                  offset+=size;progress('Verifying restored drive',offset,plan.size)
            _locked_target(writer,plan)
            for offset in sorted(positions,reverse=True):
                writer.check_cancelled();disk.seek(offset);writer.write_all(disk,headers[offset]);disk.flush()
                disk.seek(offset)
                if _read_exact(disk,sector,writer)!=headers[offset]:
                    raise NativeWriteError('Restore activation-header verification failed')
            _locked_target(writer,plan)
    skipped_label='preserved / already matching' if plan.quick else 'already matching'
    return f'{plan.filesystem.upper()} / {plan.partition_table.upper()} restore verified ({"metadata only; unused data preserved" if plan.quick else str(plan.size)+" bytes overwritten"}). Written: {written}; {skipped_label}: {skipped}. Eject and reconnect the drive.'
