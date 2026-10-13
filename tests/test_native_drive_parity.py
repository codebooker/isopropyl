# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import os
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from tests.test_native_tools import ToolTests
from isopropyl.native_tools import build_tool_plan, run_tool
from isopropyl.native_writer import NativeWriteError


class NativeDriveParityTests(ToolTests):
    def test_read_only_sparse_backup_and_source_mutation(self):
        self.target=replace(self.target,device=replace(self.target.device,read_only=True))
        self.disk=io.BytesIO(bytes(self.target.device.size))
        output=self.root/'sparse.img'
        plan=build_tool_plan('backup',self.target,destination=output,sparse=True)
        self.assertEqual(run_tool(plan,plan.confirmation,self.writer),hashlib.sha256(bytes(4096)).hexdigest())
        self.assertEqual(output.stat().st_size,4096)
        self.assertFalse(self.writer.write_started)
        self.writer.used=False;output.unlink();self.disk=io.BytesIO(b'A'*4096)
        def mutate(stage,*args):
            if stage=='Verifying backup file':self.disk.getbuffer()[0]=66
        with self.assertRaisesRegex(NativeWriteError,'source changed'):
            run_tool(plan,plan.confirmation,self.writer,progress=mutate)
        self.assertFalse(output.exists())

    def test_fast_zero_skips_only_scanned_zero_chunks(self):
        self.disk=io.BytesIO(bytes(4096))
        plan=build_tool_plan('fast_zero',self.target)
        message=run_tool(plan,plan.confirmation,self.writer)
        self.assertIn('already zero: 4096',message)
        self.assertFalse(self.writer.write_started)
        self.writer.used=False;self.disk=io.BytesIO(b'X'*4096)
        self.assertIn('Written: 4096',run_tool(plan,plan.confirmation,self.writer))
        self.assertEqual(self.disk.getvalue(),bytes(4096))

    def test_quick_capacity_small_drive_and_aliased_drive(self):
        plan=build_tool_plan('capacity',self.target)
        self.assertIn('not a full capacity certification',run_tool(plan,plan.confirmation,self.writer))
        self.assertTrue(self.writer.write_started)
        size=8*1024*1024
        self.target=replace(self.target,device=replace(self.target.device,size=size))
        class Alias:
            def __init__(self):self.data=bytearray(1024*1024);self.offset=0
            def seek(self,offset):self.offset=offset%len(self.data)
            def write(self,data):self.data[:len(data)]=data;return len(data)
            def read(self,size):return bytes(self.data[:size])
            def flush(self):pass
        self.disk=Alias();self.writer.used=False
        plan=build_tool_plan('capacity',self.target)
        with self.assertRaisesRegex(NativeWriteError,'aliased capacity'):run_tool(plan,plan.confirmation,self.writer)

    def test_selected_surface_pass_count_and_complete_probe(self):
        for passes in range(1,5):
            self.writer.used=False;stages=[]
            plan=build_tool_plan('surface',self.target,passes=passes,capacity_first=True)
            result=run_tool(plan,plan.confirmation,self.writer,progress=lambda stage,*args:stages.append(stage))
            self.assertIn('full-drive write/read passes succeeded',result)
            full_stages={stage for stage in stages if stage.startswith('Surface test')}
            self.assertEqual(len(full_stages),passes*2)
            self.assertTrue(any(stage.startswith('Quick capacity') for stage in stages))
        with self.assertRaisesRegex(NativeWriteError,'one through four'):
            build_tool_plan('surface',self.target,passes=0)

    def test_portable_exfat_is_recognized_by_independent_sleuthkit(self):
        from isopropyl.native_exfat import create_exfat
        from isopropyl.native_virtual import run_native_command
        from isopropyl.helper_tools import helper
        try:tool=helper('fsstat')
        except NativeWriteError:self.skipTest('SleuthKit helper unavailable')
        image=self.root/'exfat.img';writer=SimpleNamespace(check_cancelled=lambda:None)
        create_exfat(image,64*1024*1024,writer,label='FLASH',cluster_size=8192)
        output=run_native_command([tool,str(image)],writer).stdout.decode()
        self.assertIn('File System Type: exFAT',output)
        self.assertIn('Volume Label (from root directory): FLASH',output)
        self.assertIn('Cluster Size: 8192',output)

    def test_small_fat_variants_are_recognized_by_independent_sleuthkit(self):
        from isopropyl.native_small_fat import create_small_fat
        from isopropyl.native_virtual import run_native_command
        from isopropyl.helper_tools import helper
        try:tool=helper('fsstat')
        except NativeWriteError:self.skipTest('SleuthKit helper unavailable')
        writer=SimpleNamespace(check_cancelled=lambda:None)
        for kind,size in [('fat12',2*1024*1024),('fat16',32*1024*1024)]:
            image=self.root/(kind+'.img');create_small_fat(image,size,kind,writer,label='FLASH')
            output=run_native_command([tool,str(image)],writer).stdout.decode()
            self.assertIn('File System Type: '+kind.upper(),output)
            self.assertIn('FLASH',output)

    def test_failed_restore_readback_does_not_publish_partition_header(self):
        from isopropyl.native_restore import run_restore
        from unittest.mock import patch
        self.target=replace(self.target,device=replace(self.target.device,size=4*1024*1024))
        class Corrupt(io.BytesIO):
            def read(self,size=-1):
                offset=self.tell();data=super().read(size)
                return bytes([255])*len(data) if offset>=512 else data
        self.disk=Corrupt(bytes(self.target.device.size))
        plan=build_tool_plan('restore',self.target,filesystem='fat12',quick=False)
        def prepare(plan,workspace,*args):
            image=workspace/'restore.img';image.write_bytes(b'A'*512+bytes(plan.size-512));return image
        with patch('isopropyl.native_restore.prepare_restore_image',prepare):
            with self.assertRaisesRegex(NativeWriteError,'activation headers were not published'):
                run_restore(plan,self.writer,lambda *args:None)
        self.assertEqual(self.disk.getvalue()[:512],bytes(512))

    def test_restore_quick_writes_required_zero_metadata(self):
        from isopropyl.native_restore import run_restore
        from unittest.mock import patch
        self.target=replace(self.target,device=replace(self.target.device,size=4*1024*1024))
        expected=b'A'*512+bytes(self.target.device.size-512)
        self.disk=io.BytesIO(b'X'*self.target.device.size)
        plan=build_tool_plan('restore',self.target,filesystem='fat12',quick=True)
        def prepare(plan,workspace,*args):
            image=workspace/'restore.img';image.write_bytes(expected);return image
        with patch('isopropyl.native_restore.prepare_restore_image',prepare):
            self.assertIn('restore verified',run_restore(plan,self.writer,lambda *args:None))
        self.assertEqual(self.disk.getvalue(),expected)


class SparseRestoreTests(ToolTests):
    def test_quick_restore_preserves_holes_but_clears_zero_metadata(self):
        from unittest.mock import patch
        from isopropyl.native_restore import run_restore
        from isopropyl.native_layout import sparse_file
        size=8*1024*1024
        self.target=replace(self.target,device=replace(self.target.device,size=size))
        self.disk=io.BytesIO(b'X'*size)
        plan=build_tool_plan('restore',self.target,filesystem='fat12',quick=True)
        def prepare(plan,workspace,*args):
            image=workspace/'restore.img'
            with image.open('x+b') as output:
                sparse_file(output,size)
                output.seek(1024*1024);output.write(bytes(65536))
                output.seek(0);output.write(b'A'*512)
            import json
            (workspace/'restore-ranges.json').write_text(json.dumps([(0,1024),(1024*1024,65536),(size-512,512)]))
            return image
        with patch('isopropyl.native_restore.prepare_restore_image',prepare):
            result=run_restore(plan,self.writer,lambda *args:None)
        self.assertIn('unused data preserved',result)
        self.assertEqual(self.disk.getvalue()[:512],b'A'*512)
        self.assertEqual(self.disk.getvalue()[1024*1024:1024*1024+65536],bytes(65536))
        self.assertEqual(self.disk.getvalue()[4*1024*1024:4*1024*1024+65536],b'X'*65536)
        self.assertEqual(self.disk.getvalue()[-512:],bytes(512))

    def test_actual_quick_fat_restore_preserves_free_space(self):
        import json
        from isopropyl.native_restore import prepare_restore_image,run_restore
        size=64*1024*1024
        self.target=replace(self.target,device=replace(self.target.device,size=size))
        self.disk=io.BytesIO(b'X'*size)
        plan=build_tool_plan('restore',self.target,filesystem='fat32',quick=True)
        result=run_restore(plan,self.writer,lambda *args:None)
        self.assertIn('unused data preserved',result)
        self.assertEqual(self.disk.getvalue()[32*1024*1024:32*1024*1024+65536],b'X'*65536)
        # Unallocated FAT entries belong to required zero-filled metadata.
        self.assertEqual(self.disk.getvalue()[1024*1024+32*512+4096:1024*1024+32*512+8192],bytes(4096))

    def test_two_tib_geometry_and_large_table_use_bounded_native_serializer(self):
        from isopropyl.native_tree import construct_fat32
        from isopropyl.fat32_layout import _geometry,PrivateFat32Error
        from isopropyl.fat_image import inspect_regular_fat32_image,FatImageError
        size=2*1024**4
        with self.assertRaises(PrivateFat32Error):_geometry(size)
        tree=self.root/'tree';tree.mkdir()
        image=self.root/'large.img'
        writer=SimpleNamespace(check_cancelled=lambda:None)
        plan=construct_fat32(tree,image,size,writer)
        self.assertEqual(plan.geometry.image_size,size)
        with image.open('rb') as source:
            with self.assertRaises(FatImageError):inspect_regular_fat32_image(source.fileno())
            actual=inspect_regular_fat32_image(source.fileno(),maximum_image_bytes=size,maximum_fat_bytes=1024**3)
        self.assertEqual(actual.content_bytes,0)
        self.assertEqual(actual.filesystem_offset+actual.filesystem_size,size)


class OpticalParityTests(unittest.TestCase):
    def test_optical_capture_is_read_only_and_no_overwrite(self):
        from isopropyl.native_optical import NativeOpticalSource,build_optical_plan,run_optical
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=NativeOpticalSource('/dev/disk3',4096,'Disc','optical-id','darwin')
            plan=build_optical_plan(source,root/'capture.iso')
            class ReadOnly(io.BytesIO):
                def write(self,*args):raise AssertionError('optical source must never be written')
            @contextmanager
            def opener(source):yield ReadOnly(b'O'*4096),4096
            writer=SimpleNamespace(used=False,check_cancelled=lambda:None)
            checksum=run_optical(plan,writer,confirmation=plan.confirmation,discovery=lambda host:[source],opener=opener)
            self.assertEqual((root/'capture.iso').read_bytes(),b'O'*4096)
            self.assertEqual(checksum,hashlib.sha256(b'O'*4096).hexdigest())
            with self.assertRaisesRegex(NativeWriteError,'exists'):build_optical_plan(source,root/'capture.iso')

    def test_optical_changed_media_never_publishes(self):
        from isopropyl.native_optical import NativeOpticalSource,build_optical_plan,run_optical
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=NativeOpticalSource('/dev/disk3',4096,'Disc','optical-id','darwin')
            plan=build_optical_plan(source,root/'capture.iso');current=[source]
            @contextmanager
            def opener(source):yield io.BytesIO(b'O'*4096),4096
            writer=SimpleNamespace(used=False,check_cancelled=lambda:None)
            def progress(stage,*args):
                if stage=='Verifying optical capture':current[0]=replace(source,hardware_id='changed')
            with self.assertRaisesRegex(NativeWriteError,'media changed'):
                run_optical(plan,writer,confirmation=plan.confirmation,discovery=lambda host:current,opener=opener,progress=progress)
            self.assertEqual(list(root.iterdir()),[])

class RestoreImageParityTests(unittest.TestCase):
    def test_composed_boot_offsets_match_both_partition_starts(self):
        import struct
        from isopropyl.native_layout import Volume,compose_disk,MIB
        from isopropyl.native_small_fat import create_small_fat
        from isopropyl.native_exfat import create_exfat,checksum
        from isopropyl.native_filesystems import construct_volume,verify_filesystem
        writer=SimpleNamespace(check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);tree=root/'tree';tree.mkdir()
            for sector in (512,4096):
                for kind in ('fat12','fat16','fat32','ntfs','exfat'):
                    with self.subTest(sector=sector,filesystem=kind):
                        size=(4 if kind=='fat12' else 128 if kind=='fat16' else
                              512 if kind=='fat32' and sector==4096 else 64)*MIB
                        source=root/f'{kind}-{sector}.img'
                        if kind.startswith('fat'):create_small_fat(source,size,kind,writer,sector_size=sector)
                        elif kind=='exfat':create_exfat(source,size,writer,sector_size=sector)
                        else:
                            try:construct_volume(tree,source,size,kind,writer,sector_size=sector)
                            except NativeWriteError as error:
                                if 'helper is missing' in str(error):continue
                                raise
                        before=None
                        with source.open('rb') as stream:
                            if kind=='exfat':before=hashlib.sha256(stream.read(24*sector)).digest();stream.seek(0)
                            boot=stream.read(sector)
                            self.assertEqual(struct.unpack_from('<Q' if kind=='exfat' else '<I',boot,64 if kind=='exfat' else 28)[0],0)
                        output=root/f'{kind}-{sector}-disk.img'
                        starts=compose_disk([Volume(source,0,size,kind),Volume(source,0,size,kind)],
                                            output,2*size+3*MIB,'gpt',writer,sector_size=sector)
                        for start in starts:
                            with output.open('rb') as stream:
                                stream.seek(start);boot=stream.read(sector)
                                self.assertEqual(struct.unpack_from('<Q' if kind=='exfat' else '<I',boot,64 if kind=='exfat' else 28)[0],start//sector)
                                if kind=='exfat':
                                    stream.seek(start);primary=stream.read(12*sector);backup=stream.read(12*sector)
                                    self.assertEqual(primary,backup)
                                    expected=checksum(primary[:11*sector],boot=True)
                                    self.assertEqual(primary[11*sector:],struct.pack('<I',expected)*(sector//4))
                                elif kind in {'fat32','ntfs'}:
                                    backup_offset=struct.unpack_from('<H',boot,50)[0]*sector if kind=='fat32' else size-sector
                                    stream.seek(start+backup_offset);self.assertEqual(stream.read(sector),boot)
                            if kind!='exfat':verify_filesystem(output,{},kind,writer,offset=start,sector_size=sector)
                        if before is not None:
                            with source.open('rb') as stream:self.assertEqual(hashlib.sha256(stream.read(24*sector)).digest(),before)

    def test_opaque_efi_helper_is_preserved_byte_for_byte(self):
        from isopropyl.native_layout import Volume,compose_disk,MIB
        writer=SimpleNamespace(check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'efi.img';data=os.urandom(MIB);source.write_bytes(data)
            output=root/'disk.img'
            start,=compose_disk([Volume(source,0,MIB,'efi')],output,3*MIB,'gpt',writer)
            with output.open('rb') as stream:stream.seek(start);self.assertEqual(stream.read(MIB),data)

    def test_actual_empty_restore_images_have_independent_partition_maps(self):
        try: import dissect.fat, dissect.extfs, dissect.ntfs
        except ImportError: self.skipTest('Native independent filesystem parsers are not installed')
        from isopropyl.native_restore import prepare_restore_image
        from isopropyl.partition_tables import inspect_partition_tables_capture,PARTITION_TABLE_CAPTURE_BYTES
        writer=SimpleNamespace(check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            for kind in ['fat12','fat16','fat32','exfat','ntfs','ext2','ext3','ext4']:
                workspace=Path(directory)/kind;workspace.mkdir()
                plan=SimpleNamespace(size=(4 if kind=='fat12' else 128 if kind=='fat16' else 64)*1024*1024,
                     filesystem=kind,partition_table='gpt',label='FLASH',cluster_size=None)
                try:image=prepare_restore_image(plan,workspace,writer)
                except NativeWriteError as error:
                    if 'helper is missing' in str(error):continue
                    raise
                with image.open('rb') as stream:
                    prefix=stream.read(PARTITION_TABLE_CAPTURE_BYTES)
                    stream.seek(plan.size-len(prefix));tail=stream.read(len(prefix))
                inspected=inspect_partition_tables_capture(prefix,tail,plan.size)
                self.assertTrue(inspected.valid,kind)
                self.assertFalse(inspected.malformed,kind)
                self.assertEqual(image.stat().st_size,plan.size)

    def test_actual_qemu_vhd_and_vhdx_backup_roundtrip(self):
        from isopropyl.native_tools import export_private_backup
        from isopropyl.native_virtual import qemu_tool,run_native_command
        try:tool=qemu_tool()
        except NativeWriteError:self.skipTest('QEMU unavailable')
        writer=SimpleNamespace(host=__import__('sys').platform,check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=root/'source.img'
            with raw.open('wb') as stream:
                stream.write(b'HEADER'*512);stream.truncate(8*1024*1024)
                stream.seek(4*1024*1024);stream.write(b'SECOND'*512)
            for suffix,fmt in [('.vhd','vpc'),('.vhdx','vhdx')]:
                destination=root/('backup'+suffix)
                export_private_backup(raw,destination,writer,lambda *args:None)
                run_native_command([str(tool.path),'compare','-q','-f','raw','-F',fmt,str(raw),str(destination)],writer)
                self.assertTrue(destination.is_file())
                with self.assertRaises(FileExistsError):export_private_backup(raw,destination,writer,lambda *args:None)

    def test_udf_metadata_label_and_empty_root_are_independently_inspected(self):
        from isopropyl.native_restore import verify_udf
        from isopropyl.native_virtual import run_native_command
        from isopropyl.helper_tools import helper
        try:tool=helper('mkudffs')
        except NativeWriteError:
            candidate=Path('/tmp/isopropyl-mac-udftools/mkudffs')
            if not candidate.is_file():self.skipTest('mkudffs helper unavailable')
            tool=str(candidate)
        writer=SimpleNamespace(check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            for block in [512,1024,2048,4096]:
                image=Path(directory)/(str(block)+'.img')
                with image.open('xb') as output:output.truncate(64*1024*1024)
                run_native_command([tool,'--utf8','--media-type=hd','--blocksize='+str(block),'--label=FLASH',str(image)],writer)
                verify_udf(image,block,writer,label='FLASH')
                with self.assertRaisesRegex(NativeWriteError,'label verification'):
                    verify_udf(image,block,writer,label='OTHER')
                with image.open('r+b') as output:output.seek(256*block+4);output.write(b'\xff')
                with self.assertRaisesRegex(NativeWriteError,'checksum'):
                    verify_udf(image,block,writer,label='FLASH')

class WindowsUnbufferedTests(unittest.TestCase):
    def test_disk_buffers_are_aligned_and_retained_for_native_io(self):
        import ctypes
        from ctypes import wintypes
        from isopropyl.native_disk_io import WindowsDisk
        calls=[]
        def read(handle,address,size,count,overlapped):
            self.assertEqual(address%65536,0)
            ctypes.memmove(address,b'R'*size,size);count._obj.value=size;calls.append('read');return True
        def write(handle,address,size,count,overlapped):
            self.assertEqual(address%65536,0)
            self.assertEqual(ctypes.string_at(address,size),b'W'*size)
            count._obj.value=size;calls.append('write');return True
        api=SimpleNamespace(c=ctypes,w=wintypes,check=lambda result:result,
                            kernel=SimpleNamespace(ReadFile=read,WriteFile=write))
        disk=WindowsDisk(api,100)
        self.assertEqual(disk.read(512),b'R'*512)
        self.assertEqual(disk.write(b'W'*512),512)
        self.assertEqual(calls,['read','write'])

class NativeLogicalSectorTests(ToolTests):
    def test_four_kib_tools_use_aligned_io(self):
        self.target=replace(self.target,device=replace(self.target.device,logical_sector_size=4096,size=8192))
        class Aligned(io.BytesIO):
            def read(self,size=-1):
                if self.tell()%4096 or size%4096:raise AssertionError('unaligned read')
                return super().read(size)
            def write(self,data):
                if self.tell()%4096 or len(data)%4096:raise AssertionError('unaligned write')
                return super().write(data)
            def seek(self,offset,*args):
                if offset%4096:raise AssertionError('unaligned seek')
                return super().seek(offset,*args)
        for operation in ['zero','fast_zero','surface','capacity']:
            self.writer.used=False;self.disk=Aligned(b'X'*8192)
            plan=build_tool_plan(operation,self.target,passes=1)
            run_tool(plan,plan.confirmation,self.writer)

    def test_four_kib_restore_activations_and_metadata_are_aligned(self):
        try:import dissect.fat
        except ImportError:self.skipTest("Native FAT parser is unavailable")
        from isopropyl.native_restore import run_restore
        size=64*1024*1024
        self.target=replace(self.target,device=replace(self.target.device,logical_sector_size=4096,size=size))
        class Aligned(io.BytesIO):
            def read(self,size=-1):
                if self.tell()%4096 or size%4096:raise AssertionError('unaligned read')
                return super().read(size)
            def write(self,data):
                if self.tell()%4096 or len(data)%4096:raise AssertionError('unaligned write')
                return super().write(data)
            def seek(self,offset,*args):
                if offset%4096:raise AssertionError('unaligned seek')
                return super().seek(offset,*args)
        self.disk=Aligned(b'X'*size)
        plan=build_tool_plan('restore',self.target,filesystem='fat12',partition_table='gpt',quick=True)
        run_restore(plan,self.writer,lambda *args:None)
        data=self.disk.getvalue()
        self.assertEqual(data[4096:4104],b'EFI PART')
        self.assertEqual(data[-4096:-4088],b'EFI PART')
        self.assertEqual(data[32*1024*1024:32*1024*1024+4096],b'X'*4096)

    def test_all_four_kib_filesystems_have_verified_gpt_maps_and_bpbs(self):
        try:import dissect.fat,dissect.ntfs,dissect.extfs
        except ImportError:self.skipTest('Native independent parsers unavailable')
        from isopropyl.native_restore import prepare_restore_image
        from isopropyl.partition_tables import inspect_partition_tables_capture,PARTITION_TABLE_CAPTURE_BYTES
        writer=SimpleNamespace(check_cancelled=lambda:None)
        for kind in ['fat12','fat16','fat32','exfat','ntfs','udf','ext2','ext3','ext4']:
            workspace=self.root/kind;workspace.mkdir()
            size=(128 if kind=='fat16' else 512 if kind=='fat32' else 64)*1024*1024
            target=replace(self.target,device=replace(self.target.device,size=size,logical_sector_size=4096))
            plan=build_tool_plan('restore',target,filesystem=kind,partition_table='gpt',label='FLASH')
            try:image=prepare_restore_image(plan,workspace,writer)
            except NativeWriteError as error:
                if 'helper is missing' in str(error):continue
                raise
            with image.open('rb') as source:
                prefix=source.read(PARTITION_TABLE_CAPTURE_BYTES);source.seek(size-len(prefix));tail=source.read(len(prefix))
                source.seek(1024*1024);boot=source.read(512)
            table=inspect_partition_tables_capture(prefix,tail,size)
            self.assertTrue(table.valid,kind);self.assertEqual(table.sector_size,4096,kind)
            if kind.startswith('fat') or kind=='ntfs':self.assertEqual(int.from_bytes(boot[11:13],'little'),4096)
            elif kind=='exfat':self.assertEqual(1<<boot[108],4096)
