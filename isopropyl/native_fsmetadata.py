"""Filesystem-owned ranges, including required metadata containing all zeros."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import struct
from .native_sparse import merge_ranges
from .native_writer import NativeWriteError


class _RangeView:
    def __init__(self,source,offset,size):self.source,self.offset,self.size,self.position=source,offset,size,0
    def seek(self,offset,whence=0):
        position=offset if whence==0 else self.position+offset if whence==1 else self.size+offset
        if not 0<=position<=self.size:raise NativeWriteError('Filesystem metadata seek exceeds volume')
        self.position=position;return position
    def tell(self):return self.position
    def read(self,size=-1):
        size=self.size-self.position if size<0 else min(size,self.size-self.position)
        self.source.seek(self.offset+self.position);data=self.source.read(size);self.position+=len(data);return data


def bitmap_ranges(data,unit,base,limit,*,allocated=True):
    first=None;position=0
    for byte in data:
        if position>=limit:break
        value=byte if allocated else byte^255
        if value==255 and position+8<=limit:
            if first is None:first=position
            position+=8;continue
        if value==0:
            if first is not None:yield base+first*unit,(position-first)*unit;first=None
            position+=min(8,limit-position);continue
        for bit in range(min(8,limit-position)):
            if value&(1<<bit):
                if first is None:first=position
            elif first is not None:
                yield base+first*unit,(position-first)*unit;first=None
            position+=1
    if first is not None:yield base+first*unit,(position-first)*unit


def metadata_ranges(image,filesystem,writer,*,offset=0,size=None):
    """Read independent FS allocation metadata rather than infer zeros as free."""
    size=size if size is not None else image.stat().st_size-offset
    ranges=[]
    with image.open('rb') as original:
        source=_RangeView(original,offset,size)
        if filesystem.startswith('fat'):
            source.seek(0);boot=source.read(512)
            sector=struct.unpack_from('<H',boot,11)[0];cluster=boot[13]*sector
            reserved=struct.unpack_from('<H',boot,14)[0];fats=boot[16]
            fat=struct.unpack_from('<H',boot,22)[0] or struct.unpack_from('<I',boot,36)[0]
            root_entries=struct.unpack_from('<H',boot,17)[0]
            data_start=(reserved+fats*fat+(root_entries*32+sector-1)//sector)*sector
            ranges.append((0,data_start))
            if filesystem=='fat32':
                count=(size-data_start)//cluster
                first=None
                for position in range(2,count+2,1024*1024):
                    writer.check_cancelled();entries=min(1024*1024,count+2-position)
                    source.seek(reserved*sector+position*4);data=source.read(entries*4)
                    if len(data)!=entries*4:raise NativeWriteError('FAT allocation table is truncated')
                    if not any(data):
                        if first is not None:ranges.append((data_start+(first-2)*cluster,(position-first)*cluster));first=None
                        continue
                    for index,(value,) in enumerate(struct.iter_unpack('<I',data)):
                        number=position+index
                        if value&0x0fffffff:
                            if first is None:first=number
                        elif first is not None:
                            ranges.append((data_start+(first-2)*cluster,(number-first)*cluster));first=None
                if first is not None:ranges.append((data_start+(first-2)*cluster,(count+2-first)*cluster))
        elif filesystem=='exfat':
            source.seek(0);boot=source.read(512)
            fat,length,heap,count,root=struct.unpack_from('<IIIII',boot,80)
            unit=1 << (boot[108]+boot[109]);sector=1 << boot[108]
            ranges.extend([(0,24*sector),(fat*sector,length*sector),(heap*sector+(root-2)*unit,unit)])
            source.seek(heap*sector+(root-2)*unit);directory=source.read(unit)
            bitmap_cluster,bitmap_length=struct.unpack_from('<IQ',directory,52)
            upcase_cluster,upcase_length=struct.unpack_from('<IQ',directory,84)
            ranges.extend([(heap*sector+(bitmap_cluster-2)*unit,(bitmap_length+unit-1)//unit*unit),
                           (heap*sector+(upcase_cluster-2)*unit,(upcase_length+unit-1)//unit*unit)])
        elif filesystem=='ntfs':
            from dissect.ntfs import NTFS
            fs=NTFS(source);unit=fs.cluster_size;count=size//unit
            ranges.extend([(0,unit),(size-fs.sector_size,fs.sector_size)])
            with fs.mft.get(6).open() as bitmap:
                base=0
                while base<count:
                    writer.check_cancelled();data=bitmap.read(min(1024*1024,(count-base+7)//8))
                    if not data:raise NativeWriteError('NTFS allocation bitmap is truncated')
                    ranges.extend(bitmap_ranges(data,unit,base*unit,min(len(data)*8,count-base)))
                    base+=len(data)*8
        elif filesystem.startswith('ext'):
            from dissect.extfs import ExtFS
            fs=ExtFS(source);sb=fs.sb;unit=fs.block_size
            table_blocks=(fs.groups_count*fs._group_desc_size+unit-1)//unit
            reserved=int(sb.s_reserved_gdt_blocks)
            ranges.append((0,fs.groups_offset+table_blocks*unit))
            def power(value,base):
                if value<1:return False
                while value%base==0:value//=base
                return value==1
            for group in range(fs.groups_count):
                writer.check_cancelled();desc=fs._read_group_desc(group)
                def field(name):
                    if hasattr(desc,name+'_lo'):return getattr(desc,name+'_lo') | getattr(desc,name+'_hi',0)<<32
                    return getattr(desc,name)
                bitmap=field('bg_block_bitmap');inodes=field('bg_inode_bitmap');table=field('bg_inode_table')
                inode_blocks=(sb.s_inodes_per_group*sb.s_inode_size+unit-1)//unit
                ranges.extend([(bitmap*unit,unit),(inodes*unit,unit),(table*unit,inode_blocks*unit)])
                start=sb.s_first_data_block+group*sb.s_blocks_per_group
                sparse=bool(sb.s_feature_ro_compat&1)
                has_super=not sparse or group in {0,1} or any(power(group,base) for base in [3,5,7])
                if sb.s_feature_compat&0x200:
                    has_super=group==0 or group in sb.s_backup_bgs
                if has_super:ranges.append((start*unit,(1+table_blocks+reserved)*unit))
                if getattr(desc,'bg_flags',0)&2:continue
                source.seek(bitmap*unit);data=source.read(unit)
                blocks=min(sb.s_blocks_per_group,fs.block_count-start)
                ranges.extend(bitmap_ranges(data,unit,start*unit,blocks))
        elif filesystem=='udf':
            # Locate the logical block size through valid UDF anchors.
            block=None
            for candidate in (512,1024,2048,4096):
                source.seek(256*candidate);anchor=source.read(candidate)
                if len(anchor)==candidate and anchor[:2]==b'\x02\x00' and sum(anchor[:4]+anchor[5:16])%256==anchor[4]:
                    block=candidate;break
            if block is None:raise NativeWriteError('UDF allocation parser found no anchor')
            sequence_length,sequence_start=struct.unpack_from('<II',anchor,16)
            partition=None
            for sector in range(sequence_start,sequence_start+(sequence_length+block-1)//block):
                source.seek(sector*block);descriptor=source.read(block)
                if descriptor[:2]==b'\x05\x00':partition=descriptor;break
            if partition is None:raise NativeWriteError('UDF allocation parser found no partition descriptor')
            start,count=struct.unpack_from('<II',partition,188)
            bitmap_length,bitmap_position=struct.unpack_from('<II',partition,64)
            source.seek((start+bitmap_position)*block);header=source.read(24)
            if header[:2]!=b'\x08\x01':raise NativeWriteError('UDF unallocated-space bitmap is missing')
            bits,bytes_count=struct.unpack_from('<II',header,16)
            if bits!=count or bytes_count!=(count+7)//8:raise NativeWriteError('UDF bitmap capacity is inconsistent')
            ranges.extend([(0,start*block),((start+count)*block,size-(start+count)*block)])
            done=0
            while done<bytes_count:
                writer.check_cancelled();data=source.read(min(1024*1024,bytes_count-done))
                if not data:raise NativeWriteError('UDF bitmap is truncated')
                ranges.extend(bitmap_ranges(data,block,(start+done*8)*block,min(len(data)*8,count-done*8),allocated=False))
                done+=len(data)
        else:raise NativeWriteError('No metadata allocation parser for this filesystem')
    return merge_ranges(ranges,size)
