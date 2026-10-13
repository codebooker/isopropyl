# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import NativeWriter,NativeWriteError,build_plan
from isopropyl.native_media import NativeMediaOptions,build_media_plan,prepare_media_image,_persistence,_windows_bios
from isopropyl.native_tree import construct_fat32
from isopropyl.partition_tables import inspect_partition_tables_capture,PARTITION_TABLE_CAPTURE_BYTES
from isopropyl.native_layout import MIB
from tests.test_uefi import make_pe

class NativeMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'test.iso';self.source.write_bytes(bytes(2048))
        self.target=NativeDevice(Device('/dev/disk2',600*MIB,'Flash','','usb','SERIAL','','disk2',True,True,False,(),(),512),hardware_id='hardware')
        self.writer=NativeWriter(host='darwin')
    def test_invalid_selections_fail_before_preparation(self):
        for options in (NativeMediaOptions(mode='unsafe'),NativeMediaOptions(firmware='bios',partition_table='gpt'),NativeMediaOptions(persistence_size=MIB),NativeMediaOptions(cluster_size=3)):
            with self.assertRaises(NativeWriteError):build_media_plan(self.source,self.target,options)
    def test_real_fat32_gpt_composition_with_independent_file_parser(self):
        inspection=SimpleNamespace(has_mbr=False,has_gpt=False,is_iso9660=True,has_windows_installer=False,architectures=('x64',))
        def extract(source,tree,writer,progress):
            (tree/'EFI/BOOT').mkdir(parents=True);(tree/'EFI/BOOT/BOOTX64.EFI').write_bytes(make_pe())
            (tree/'payload.txt').write_bytes(b'installer payload');return inspection,()
        plan=build_media_plan(self.source,self.target,NativeMediaOptions(mode='iso',partition_table='gpt',label='MEDIA',cluster_size=512))
        workspace=self.root/'workspace';workspace.mkdir(mode=0o700)
        with patch('isopropyl.images.inspect_image',return_value=inspection),patch('isopropyl.native_extract.extract_iso',side_effect=extract):
            image=prepare_media_image(plan,workspace,self.writer)
        with image.open('rb') as stream:
            prefix=stream.read(PARTITION_TABLE_CAPTURE_BYTES);stream.seek(-PARTITION_TABLE_CAPTURE_BYTES,2);tail=stream.read()
        parsed=inspect_partition_tables_capture(prefix,tail,image.stat().st_size)
        self.assertTrue(parsed.valid);self.assertEqual(parsed.kind,'gpt');self.assertEqual(image.stat().st_size,self.target.device.size)
        self.assertFalse((workspace/'files').exists());self.assertFalse((workspace/'main.fs').exists())
    def test_exact_casper_policy_and_transformation(self):
        tree=self.root/'tree'
        for name,payload in {'.disk/info':b'Ubuntu 24.04.1 LTS amd64','casper/vmlinuz':b'kernel','casper/filesystem.squashfs':b'fs','casper/initrd':b'initrd','EFI/BOOT/BOOTX64.EFI':make_pe(),'boot/grub/grub.cfg':b'linux /casper/vmlinuz boot=casper ---\n'}.items():
            path=tree/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(payload)
        options=NativeMediaOptions(persistence_size=256*MIB,persistence_release='24.04')
        profile=_persistence(tree,options,self.writer)
        self.assertEqual(profile.partition_label,'writable');self.assertIn(b'persistent ---',(tree/'boot/grub/grub.cfg').read_bytes())
        with self.assertRaises(Exception):_persistence(tree,replace(options,persistence_release='22.04'),self.writer)
    def test_windows_bios_patch_regular_image(self):
        from isopropyl.windows_bios_pbr import MODERN_BOOTMGR_ENTRY_STUB
        tree=self.root/'tree';tree.mkdir();(tree/'bootmgr').write_bytes(MODERN_BOOTMGR_ENTRY_STUB+bytes(1024))
        image=self.root/'bios.img';plan=construct_fat32(tree,image,512*MIB,self.writer)
        _windows_bios(image,tree,plan.geometry.volume_offset,plan.geometry.volume_size,self.writer)
        with image.open('rb') as stream:
            self.assertNotEqual(stream.read(440),bytes(440));stream.seek(plan.geometry.volume_offset);boot=stream.read(512)
        self.assertEqual(boot[-2:],b'\x55\xaa')

    def test_auto_unpartitioned_raw_image_preserves_disk_bytes(self):
        source=self.root/'raw.img';data=b'R'*2048;source.write_bytes(data)
        plan=build_media_plan(source,self.target)
        workspace=self.root/'raw-work';workspace.mkdir(mode=0o700)
        image=prepare_media_image(plan,workspace,self.writer)
        self.assertEqual(image.suffix,'.img');self.assertEqual(image.read_bytes(),data)

    def test_plan_preview_explains_raw_auto_without_target_access(self):
        from isopropyl.native_media import describe_media_plan
        source=self.root/'raw.img';source.write_bytes(bytes(2048));plan=build_media_plan(source,self.target)
        with patch('isopropyl.native_writer.open_disk') as disk:
            detail=describe_media_plan(plan,self.writer)
        self.assertIn('Resolved method: DD',detail);self.assertIn('Flash',detail);disk.assert_not_called()

class FallbackTests(unittest.TestCase):
    def test_staged_fallback_rejects_wrong_machine_and_nonapplication(self):
        from isopropyl.native_media import _validate_staged_fallbacks
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'EFI/BOOT/BOOTX64.EFI';path.parent.mkdir(parents=True)
            for payload in (make_pe(machine=0xAA64),make_pe(subsystem=11),b'not executable'):
                path.write_bytes(payload)
                with self.assertRaises(NativeWriteError):_validate_staged_fallbacks(root,NativeWriter())
            path.write_bytes(make_pe());self.assertEqual(_validate_staged_fallbacks(root,NativeWriter()),('x64',))
