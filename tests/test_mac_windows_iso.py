# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import plistlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.mac_windows_iso import (
    build_windows_plan,
    collect_files,
    compose_fat32,
    customize_tree,
    installer_profile,
    prepare_windows_image,
    verify_loader,
)
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import NativeWriteError, NativeWriter
from isopropyl.windows import WindowsCustomization, generate_autounattend


def loader_bytes(machine=0x8664):
    from tests.test_uefi import make_pe
    return make_pe(machine=machine)


def make_tree(root):
    for name,data in {'setup.exe':b'setup','sources/boot.wim':b'boot',
                      'sources/install.wim':b'install','EFI/Boot/bootx64.efi':loader_bytes()}.items():
        path = root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)


@unittest.skipUnless(os.name=='posix','FAT32 descriptor construction uses POSIX APIs')
class WindowsIsoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = NativeDevice(Device('/dev/disk8',1024**3,'USB','','usb','123','','disk8',
                                         True,True,False,(),(),512))
        self.writer = NativeWriter(host='darwin')

    def test_fat32_builder_preserves_every_file_and_supports_uefi_paths(self):
        from isopropyl.fat_image import inspect_regular_fat32_image
        tree = self.root/'tree'; tree.mkdir(); make_tree(tree)
        workspace = self.root/'workspace'; workspace.mkdir()
        image = compose_fat32(tree,workspace,self.root/'installer.img',self.target.device.size,self.writer,lambda *a:None)
        with image.open('rb') as source:
            parsed = inspect_regular_fat32_image(source.fileno())
        paths = {entry.path.casefold() for entry in parsed.entries if not entry.is_directory}
        self.assertEqual(paths,{'setup.exe','sources/boot.wim','sources/install.wim','efi/boot/bootx64.efi'})

    def test_custom_answer_file_is_architecture_specific_and_verified_in_fat32(self):
        from isopropyl.fat_image import inspect_regular_fat32_image
        tree = self.root/'tree'; tree.mkdir(); make_tree(tree)
        iso = self.root/'windows.iso'; iso.write_bytes(bytes(512))
        options = WindowsCustomization(bypass_hardware_requirements=True,disable_fast_startup=True,system_locale='en-US')
        plan = build_windows_plan(iso,self.target,customization=options)
        files = collect_files(tree); index,_,install = installer_profile(files)
        customize_tree(plan,tree,index,install,0xAA64,iso,self.root,self.writer,lambda *a:None)
        self.assertEqual((tree/'autounattend.xml').read_text(),generate_autounattend(options,'arm64'))
        workspace = self.root/'workspace'; workspace.mkdir()
        image = compose_fat32(tree,workspace,self.root/'installer.img',self.target.device.size,self.writer,lambda *a:None)
        with image.open('rb') as stream:
            parsed = inspect_regular_fat32_image(stream.fileno())
        self.assertTrue(any(entry.path == 'autounattend.xml' for entry in parsed.entries))
        self.assertFalse(self.writer.write_started)

    def test_existing_answer_file_is_never_overwritten_even_with_different_case(self):
        tree = self.root/'tree'; tree.mkdir(); make_tree(tree)
        answer = tree/'Autounattend.XML'; answer.write_text('original')
        iso = self.root/'windows.iso'; iso.write_bytes(bytes(512))
        plan = build_windows_plan(iso,self.target,customization=WindowsCustomization(reduce_data_collection=True))
        index,(_,machine),install = installer_profile(collect_files(tree))
        with self.assertRaisesRegex(NativeWriteError,'already contains'):
            customize_tree(plan,tree,index,install,machine,iso,self.root,self.writer,lambda *a:None)
        self.assertEqual(answer.read_text(),'original')

    def test_real_device_is_never_used_during_preparation(self):
        iso = self.root/'windows.iso'; iso.write_bytes(bytes(512))
        plan = build_windows_plan(iso,self.target)
        work = self.root/'work'; work.mkdir()
        from types import SimpleNamespace
        inspection=SimpleNamespace(has_mbr=False,has_gpt=False,is_iso9660=True,has_windows_installer=True,architectures=('x64',))
        def extract(source,tree,writer,progress):
            tree.mkdir();make_tree(tree);return inspection,()
        with patch('isopropyl.images.inspect_image',return_value=inspection),patch('isopropyl.native_extract.extract_iso',side_effect=extract),patch('isopropyl.native_writer.open_disk') as disk:
            image = prepare_windows_image(plan,work,self.writer)
        self.assertTrue(image.is_file());disk.assert_not_called()

    def test_non_windows_iso_is_rejected(self):
        with self.assertRaises(NativeWriteError):
            installer_profile([(Path('readme.txt'),10)])

    def test_wrong_loader_architecture_is_rejected(self):
        path = self.root/'boot.efi'; path.write_bytes(loader_bytes(0xAA64))
        with self.assertRaises(NativeWriteError):
            verify_loader(path,0x8664)
        verify_loader(path,0xAA64)

    def test_symlinks_are_rejected_before_copy(self):
        (self.root/'alias').symlink_to('/etc/passwd')
        with self.assertRaises(NativeWriteError):
            collect_files(self.root)

    def test_target_too_small_never_creates_an_image(self):
        tree = self.root/'tree'; tree.mkdir(); make_tree(tree)
        workspace = self.root/'workspace'; workspace.mkdir()
        with self.assertRaises(NativeWriteError):
            compose_fat32(tree,workspace,self.root/'image.img',1024,self.writer,lambda *a:None)
        self.assertFalse((self.root/'image.img').exists())

    def test_multisource_profile_uses_shared_four_wim_and_esd_policy(self):
        from isopropyl.mac_windows_iso import installer_candidates
        tree=self.root/'multiple';tree.mkdir();make_tree(tree)
        for name in ('alternate/sources/install.wim','third/sources/install.wim','fourth/sources/install.wim','sources/install.esd'):
            path=tree/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'other')
        files=collect_files(tree);candidates,count=installer_candidates(files)
        self.assertEqual(len(candidates),4);self.assertEqual(count,5)
        self.assertEqual(installer_profile(files)[2],'sources/install.wim')
        self.assertEqual(installer_profile(files,'alternate/sources/install.wim')[2],'alternate/sources/install.wim')
        with self.assertRaisesRegex(NativeWriteError,'supported bound catalog'):installer_profile(files,'sources/install.esd')
        path=tree/'fifth/sources/install.wim';path.parent.mkdir(parents=True);path.write_bytes(b'extra')
        with self.assertRaisesRegex(NativeWriteError,'unsafe or unsupported'):installer_profile(collect_files(tree))

    def test_selected_nested_wim_requires_exact_answer_path_and_metadata(self):
        from isopropyl.wim import WimEdition,WimSelection
        tree=self.root/'multiple';tree.mkdir();make_tree(tree)
        member=tree/'alternate/sources/install.wim';member.parent.mkdir(parents=True);member.write_bytes(b'other')
        edition=WimEdition(1,'Pro','Pro','Professional','amd64',10,0,26100,1)
        selection=WimSelection('alternate/sources/install.wim',5,(edition,),1)
        iso=self.root/'windows.iso';iso.write_bytes(bytes(512))
        index,(_,machine),install=installer_profile(collect_files(tree),selection.source_name)
        options=WindowsCustomization(install_image=selection)
        plan=build_windows_plan(iso,self.target,customization=options)
        with self.assertRaisesRegex(NativeWriteError,'exact answer-file WIM path'):
            customize_tree(plan,tree,index,install,machine,iso,self.root,self.writer,lambda *a:None)
        options=WindowsCustomization(install_image=selection,install_image_path=selection.source_name)
        plan=build_windows_plan(iso,self.target,customization=options)
        with patch('isopropyl.mac_windows_iso.wim_tool',return_value='wimlib'),patch('isopropyl.mac_windows_iso.run_tool',return_value=b'xml'),patch('isopropyl.wim.parse_wim_info_xml',return_value=(edition,)):
            customize_tree(plan,tree,index,install,machine,iso,self.root,self.writer,lambda *a:None)
        self.assertIn('alternate\\sources\\install.wim',(tree/'autounattend.xml').read_text())
        self.assertEqual((tree/'sources/install.wim').read_bytes(),b'install')

    def test_alternate_or_multisource_large_wim_is_not_split(self):
        from isopropyl.mac_windows_iso import split_large_install
        tree=self.root/'multiple';tree.mkdir();make_tree(tree)
        alternate=tree/'alternate/sources/install.wim';alternate.parent.mkdir(parents=True);alternate.write_bytes(b'other')
        index,_,install=installer_profile(collect_files(tree),'alternate/sources/install.wim')
        with patch('isopropyl.mac_windows_iso.FAT_LIMIT',1),patch('isopropyl.mac_windows_iso.wim_tool') as tool:
            with self.assertRaisesRegex(NativeWriteError,'nested or multi-source'):
                split_large_install(tree,index,install,self.writer,lambda *a:None)
        tool.assert_not_called();self.assertEqual(alternate.read_bytes(),b'other')

    def test_installer_looking_directory_cannot_hide_behind_valid_wim(self):
        tree=self.root/'multiple';tree.mkdir();make_tree(tree)
        (tree/'alternate/sources/install.wim').mkdir(parents=True)
        with self.assertRaisesRegex(NativeWriteError,'regular file'):collect_files(tree)
