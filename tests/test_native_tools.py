# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import BLOCK, NativeCancelled, NativeWriteError, NativeWriter
from isopropyl.native_tools import build_tool_plan, run_tool


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.target=NativeDevice(Device('/dev/disk2',4096,'Flash','','usb','SERIAL','','disk2',True,True,False,(),(),512))
        self.disk=io.BytesIO(b'A'*4096);self.opened=0
        @contextmanager
        def opener(*args):
            self.opened+=1
            yield self.disk
        self.writer=NativeWriter(host='win32',discovery=lambda *args,**kwargs:[self.target],opener=opener,privilege_check=lambda host:None)

    def test_zero_verifies_every_byte_and_surface_tests_all_passes(self):
        plan=build_tool_plan('zero',self.target)
        self.assertIn('zero',run_tool(plan,plan.confirmation,self.writer))
        self.assertEqual(self.disk.getvalue(),bytes(4096))
        self.writer.used=False
        plan=build_tool_plan('surface',self.target)
        stages=[]
        self.assertIn('four',run_tool(plan,plan.confirmation,self.writer,progress=lambda s,*args:stages.append(s)))
        self.assertEqual(len(set(stages)),8)

    def test_backup_publishes_verified_full_image_without_writing_disk(self):
        output=self.root/'backup.img';plan=build_tool_plan('backup',self.target,destination=output)
        checksum=run_tool(plan,plan.confirmation,self.writer)
        self.assertEqual(output.read_bytes(),b'A'*4096)
        self.assertEqual(checksum,hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertFalse(self.writer.write_started)
        self.assertEqual(list(self.root.iterdir()),[output])

    def test_existing_destination_and_destination_on_target_are_rejected(self):
        output=self.root/'backup.img';output.touch()
        with self.assertRaisesRegex(NativeWriteError,'exists'):build_tool_plan('backup',self.target,destination=output)
        output.unlink()
        target=replace(self.target,device=replace(self.target.device,mountpoints=(str(self.root),)))
        with self.assertRaisesRegex(NativeWriteError,'different drive'):build_tool_plan('backup',target,destination=output)

    def test_cancelled_backup_has_no_published_or_partial_file(self):
        output=self.root/'backup.img';plan=build_tool_plan('backup',self.target,destination=output)
        with self.assertRaises(NativeCancelled):
            run_tool(plan,plan.confirmation,self.writer,progress=lambda *args:self.writer.cancel())
        self.assertFalse(output.exists());self.assertEqual(list(self.root.iterdir()),[])

    def test_changed_identity_and_declined_confirmation_never_open_disk(self):
        plan=build_tool_plan('zero',self.target)
        with self.assertRaisesRegex(NativeWriteError,'confirmed'):run_tool(plan,'yes',self.writer)
        self.writer.used=False
        self.writer.discovery=lambda *args,**kwargs:[replace(self.target,hardware_id='reconnected')]
        with self.assertRaisesRegex(NativeWriteError,'identity'):run_tool(plan,plan.confirmation,self.writer)
        self.assertEqual(self.opened,0)

    def test_corrupt_readback_is_reported_as_failed_drive(self):
        class BadDisk(io.BytesIO):
            def read(self,size=-1):return bytes([255])*size
        self.disk=BadDisk(bytes(4096))
        plan=build_tool_plan('zero',self.target)
        with self.assertRaisesRegex(NativeWriteError,'verification failed'):run_tool(plan,plan.confirmation,self.writer)
        self.assertTrue(self.writer.write_started)

    def test_counterfeit_aliasing_cannot_pass_address_specific_surface_pattern(self):
        # Firmware wraps every 4 MiB back onto one physical region, while
        # reporting twice that capacity. Constant pattern passes cannot catch it.
        self.target=replace(self.target,device=replace(self.target.device,size=BLOCK*2))
        class AliasedDisk:
            def __init__(self):self.data=bytearray(BLOCK);self.position=0
            def seek(self,pos):self.position=pos%BLOCK
            def write(self,data):
                self.data[self.position:self.position+len(data)]=data
                self.position=(self.position+len(data))%BLOCK
                return len(data)
            def read(self,size):
                data=bytes(self.data[self.position:self.position+size]);self.position=(self.position+size)%BLOCK
                return data
            def flush(self):pass
        self.disk=AliasedDisk();plan=build_tool_plan('surface',self.target)
        with self.assertRaisesRegex(NativeWriteError,'false capacity'):run_tool(plan,plan.confirmation,self.writer)

    def test_target_reconnection_before_backup_publication_discards_output(self):
        output=self.root/'backup.img';plan=build_tool_plan('backup',self.target,destination=output)
        def progress(stage,*args):
            if stage=='Verifying backup file':
                self.writer.discovery=lambda *args,**kwargs:[replace(self.target,hardware_id='new')]
        with self.assertRaisesRegex(NativeWriteError,'identity'):run_tool(plan,plan.confirmation,self.writer,progress=progress)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_fat32_format_has_valid_filesystem_and_erases_old_data(self):
        from isopropyl.fat_image import inspect_regular_fat32_image
        size=64*1024*1024
        self.target=replace(self.target,device=replace(self.target.device,size=size))
        self.disk=io.BytesIO(b'X'*size)
        plan=build_tool_plan('format_fat32',self.target)
        self.assertIn('FAT32',run_tool(plan,plan.confirmation,self.writer))
        self.disk.seek(0)
        with tempfile.TemporaryFile() as image:
            image.write(self.disk.read());image.flush()
            parsed=inspect_regular_fat32_image(image.fileno())
        self.assertEqual(parsed.content_bytes,0)
        self.assertEqual(parsed.entries,())
        self.assertEqual(self.disk.getvalue()[-BLOCK:],bytes(BLOCK))

    def test_changed_volume_set_never_writes(self):
        self.writer.discovery=lambda *args,**kwargs:[replace(self.target,volumes=('new',))]
        plan=build_tool_plan('zero',self.target)
        with self.assertRaisesRegex(NativeWriteError,'volume set'):run_tool(plan,plan.confirmation,self.writer)
        self.assertFalse(self.writer.write_started)
