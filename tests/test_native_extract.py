# SPDX-License-Identifier: AGPL-3.0-or-later
import tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from isopropyl.native_extract import extract_iso
from isopropyl.native_writer import NativeWriter
from isopropyl.images import ImageCatalogScan
from tests.test_fat_image import make_fat,write_container
from isopropyl.fat_image import FatType

class ExtractTests(unittest.TestCase):
    def test_embedded_efi_files_are_reconstructed_with_shared_merge_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'embedded.iso';tree=root/'files'
            write_container(source,make_fat(FatType.FAT12))
            with patch('isopropyl.images.inspect_image',return_value=SimpleNamespace()),patch('isopropyl.images.scan_image_catalog',return_value=ImageCatalogScan((),True,None)):
                _,entries=extract_iso(source,tree,NativeWriter())
            self.assertEqual((tree/'EFI/BOOT/BOOTX64.EFI').read_bytes(),b'MZ!')
            self.assertIn('EFI/BOOT/BOOTX64.EFI',[item.path for item in entries])
    def test_embedded_file_collision_is_refused_before_staging(self):
        from tests.test_fat_image import write_plural_container
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'embedded.iso';tree=root/'files'
            boot_catalog,_=write_plural_container(source,make_fat(FatType.FAT12),make_fat(FatType.FAT12,payload=b'BAD'))
            with patch('isopropyl.images.inspect_image',return_value=SimpleNamespace()),patch('isopropyl.images.scan_image_catalog',return_value=ImageCatalogScan((),True,None)),patch('isopropyl.eltorito.inspect_eltorito_file',return_value=boot_catalog):
                with self.assertRaisesRegex(RuntimeError,'differing files'):
                    extract_iso(source,tree,NativeWriter())
            self.assertFalse(tree.exists())
