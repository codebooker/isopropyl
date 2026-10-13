# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl import windows_media as media
from isopropyl.devices import Device
from isopropyl.mac_windows_iso import build_windows_plan
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import NativeWriteError, NativeWriter
from isopropyl.windows import WindowsCustomization, generate_autounattend
from tests.test_mac_windows_iso import make_tree


def fixed_vhd(path, body):
    footer = bytearray(512)
    footer[:8] = b"conectix"
    struct.pack_into(">Q", footer, 48, len(body))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    path.write_bytes(body + footer)


class WindowsMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso = self.root / "windows.iso"
        self.iso.write_bytes(bytes(512))
        self.target = NativeDevice(
            Device(
                r"\\.\PhysicalDrive999",
                1024**3,
                "TEST",
                "",
                "usb",
                "SERIAL",
                "",
                "999",
                True,
                True,
                False,
                (),
                (),
                512,
            )
        )
        self.writer = NativeWriter(host="win32")
        self.optical = self.root / "optical"
        self.optical.mkdir()
        make_tree(self.optical)
        self.volume = self.root / "volume"
        self.volume.mkdir()
        self.commands = []
        self.detached = []
        self.privileges = patch("isopropyl.native_disk_io.require_privileges")
        self.privileges.start()
        self.addCleanup(self.privileges.stop)

    def ps(self, script, image, writer, **kwargs):
        self.commands.append((script, image))
        self.assertNotIn(self.target.device.path, script)
        self.assertNotEqual(str(image), self.target.device.path)
        if script == media.MOUNT_ISO:
            return json.dumps({"Root": "optical"}).encode()
        if script == media.MOUNT_VHD:
            return json.dumps({"Root": "volume"}).encode()
        if script == media.DETACH:
            self.detached.append(image)
            return b""
        self.fail("Unexpected script")

    def root_result(self, payload):
        return self.root / json.loads(payload)["Root"]

    def tool(self, args, *unused, **kwargs):
        self.assertNotIn(self.target.device.path, " ".join(args))
        if str(args[0]).endswith("diskpart.exe"):
            script = Path(args[2]).read_text()
            self.assertNotIn("select disk", script.lower())
            path = Path(script.split('file="', 1)[1].split('"', 1)[0])
            body = bytes(2048)
            fixed_vhd(path, body)
            return b""
        if str(args[0]).endswith("dism.exe"):
            output = Path(
                next(
                    arg.split(":", 1)[1] for arg in args if arg.startswith("/SWMFile:")
                )
            )
            output.write_bytes(b"a" * 2048)
            output.with_name("install2.swm").write_bytes(b"b" * 2048)
            return b""
        self.fail("Unexpected tool")

    def prepare(self, options=WindowsCustomization()):
        import shutil
        from types import SimpleNamespace
        workspace=self.root/'work';workspace.mkdir(mode=0o700)
        plan=build_windows_plan(self.iso,self.target,customization=options)
        inspection=SimpleNamespace(has_mbr=False,has_gpt=False,is_iso9660=True,has_windows_installer=True,architectures=('x64',))
        def extract(source,tree,writer,progress):
            shutil.copytree(self.optical,tree);return inspection,()
        with patch('isopropyl.images.inspect_image',return_value=inspection),patch('isopropyl.native_extract.extract_iso',side_effect=extract):
            result=media.prepare_windows_image(plan,workspace,self.writer)
        return result,workspace

    def test_private_image_preparation_never_receives_physical_target(self):
        from isopropyl.fat_image import inspect_regular_fat32_image
        options=WindowsCustomization(disable_fast_startup=True,system_locale='en-US')
        with patch('isopropyl.native_writer.open_disk') as disk:
            result,work=self.prepare(options)
        disk.assert_not_called()
        expected=generate_autounattend(options,'amd64').encode()
        import hashlib
        from isopropyl.native_filesystems import verify_filesystem
        verify_filesystem(result,{'autounattend.xml':(len(expected),hashlib.sha256(expected).hexdigest())},'fat32',self.writer,offset=1024*1024)
        self.assertFalse((work/'input.iso').exists());self.assertFalse((work/'files').exists());self.assertFalse(self.writer.write_started)

    def test_split_wim_parts_are_copied_and_original_is_removed(self):
        from isopropyl.mac_windows_iso import split_large_install
        (self.optical/'sources/install.esd').write_bytes(bytes(4096))
        (self.optical/'sources/install.wim').unlink()
        commands=[]
        def run(args,*a,**k):
            commands.append(args)
            if args[1]=='export':Path(args[4]).write_bytes(b'wim')
            if args[1]=='split':
                Path(args[3]).write_bytes(b'a'*2048);Path(args[3]).with_name('install2.swm').write_bytes(b'b'*2048)
            return b'xml'
        with patch('isopropyl.mac_windows_iso.FAT_LIMIT',4095),patch('isopropyl.mac_windows_iso.wim_tool',return_value='wimlib'),patch('isopropyl.mac_windows_iso.run_tool',side_effect=run),patch('isopropyl.wim.parse_wim_info_xml',return_value=('edition',)):
            split_large_install(self.optical,{'sources/install.esd':Path('sources/install.esd')},'sources/install.esd',self.writer,lambda *a:None)
        self.assertFalse((self.optical/'sources/install.esd').exists());self.assertTrue((self.optical/'sources/install2.swm').exists())
        self.assertEqual([c[1] for c in commands],['info','export','info','split','info','verify'])

    def test_fixed_vhd_footer_size_and_checksum_are_required(self):
        source = self.root / "private.vhd"
        fixed_vhd(source, b"A" * 512)
        self.assertEqual(
            media.strip_fixed_vhd(
                source, self.root / "valid.img", self.writer, lambda *a: None
            ).read_bytes(),
            b"A" * 512,
        )
        data = bytearray(source.read_bytes())
        data[-1] ^= 1
        source.write_bytes(data)
        with self.assertRaisesRegex(NativeWriteError, "checksum"):
            media.strip_fixed_vhd(
                source, self.root / "bad.img", self.writer, lambda *a: None
            )
        self.assertFalse((self.root / "bad.img").exists())

    def test_cancelled_writer_cannot_skip_virtual_disk_cleanup(self):
        self.writer.cancel()
        with patch.object(media, "invoke_ps") as invoke:
            media.detach(self.root / "private.vhd")
        invoke.call_args.args[2].check_cancelled()
        self.assertEqual(invoke.call_args.args[0], media.DETACH)

    def test_preparation_failure_never_starts_a_usb_write(self):
        with patch('isopropyl.native_filesystems.construct_volume',side_effect=NativeWriteError('verification failed')),patch('isopropyl.native_writer.open_disk') as disk:
            with self.assertRaisesRegex(NativeWriteError,'verification'):self.prepare()
        disk.assert_not_called();self.assertFalse(self.writer.write_started)
        self.assertFalse((self.root/'work/installer.img').exists())

    def test_root_result_rejects_arbitrary_paths_and_device_names(self):
        for root in [r"\\.\PhysicalDrive2", r"C:\Windows", "/dev/disk8", ""]:
            with self.assertRaises(NativeWriteError):
                media.root_from_result(json.dumps({"Root": root}))

    def test_windows_metadata_is_validated_and_normalized(self):
        payload = [
            {
                "Index": 1,
                "Name": "Windows 11 Pro",
                "Description": "Pro",
                "Edition": "Professional",
                "Architecture": 9,
                "Major": 10,
                "Minor": 0,
                "Build": 26100,
                "Revision": 1742,
                "ExpandedBytes": 1000,
            }
        ]
        with patch.object(
            media, "invoke_ps", return_value=json.dumps(payload).encode()
        ):
            editions = media.inspect_wim(self.iso, self.writer)
        self.assertEqual(editions[0].architecture, "amd64")
        self.assertEqual(editions[0].version, "10.0.26100.1742")

    @unittest.skipUnless(os.name == "nt", "PowerShell parser requires Windows")
    def test_preparation_scripts_parse_without_executing_any_storage_command(self):
        payload = self.root / "scripts.json"
        payload.write_text(
            json.dumps(
                [media.MOUNT_ISO, media.MOUNT_VHD, media.DETACH, media.WIM_INFO]
            ),
            encoding="utf-8",
        )
        checker = (
            media.PS_HEADER
            + """
foreach ($script in (Get-Content -Raw -LiteralPath $ImagePath | ConvertFrom-Json)) {
  $tokens = $null; $parseErrors = $null
  [Management.Automation.Language.Parser]::ParseInput($script,[ref]$tokens,[ref]$parseErrors) | Out-Null
  if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
}
'Parsed without execution'
"""
        )
        self.assertIn(
            b"Parsed without execution", media.invoke_ps(checker, payload, self.writer)
        )

    def test_inspection_selected_member_returns_its_metadata_and_all_candidates(self):
        from isopropyl.wim import WimEdition
        alternate=self.optical/'alternate/sources/install.wim'
        alternate.parent.mkdir(parents=True);alternate.write_bytes(b'alternate')
        edition=WimEdition(1,'Windows Pro','Pro','Professional','amd64',10,0,26100,1)
        def extract(source,tree,writer,progress=lambda *a:None):
            import shutil
            shutil.copytree(self.optical,tree)
            return None,()
        with patch('isopropyl.native_extract.extract_iso',side_effect=extract),patch('isopropyl.mac_windows_iso.wim_tool',return_value='wimlib'),patch('isopropyl.windows_media.run_tool',return_value=b'xml') as command,patch('isopropyl.wim.parse_wim_info_xml',return_value=(edition,)):
            metadata=media.inspect_windows_source(self.iso,self.writer,selected_member='alternate/sources/install.wim')
        self.assertEqual(metadata.install_path,'alternate/sources/install.wim')
        self.assertEqual(metadata.install_size,len(b'alternate'))
        self.assertEqual(metadata.install_source_count,2)
        self.assertEqual({c.path for c in metadata.install_candidates},{'sources/install.wim','alternate/sources/install.wim'})
        self.assertTrue(command.call_args.args[0][2].endswith('alternate/sources/install.wim'))
