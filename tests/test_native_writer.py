# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import (
    NativeCancelled,
    NativeWriteError,
    NativeWriter,
    build_plan,
)


class FakeDisk(io.BytesIO):
    def __init__(self, size):
        super().__init__(b'X'*size)
        self.writes = 0
        self.corrupt = False
        self.short = False
    def write(self, data):
        self.writes += 1
        return super().write(data[:512] if self.short else data)
    def read(self, size=-1):
        data = super().read(size)
        return bytes(len(data)) if self.corrupt else data


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'test.img'
        self.content = b'A'*2048
        self.path.write_bytes(self.content)
        self.target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb',
            'SERIAL', '', 'disk2', True, True, False, (), (), 512), hardware_id='hardware')
        self.disk = FakeDisk(4096)
        self.opened = 0
        @contextmanager
        def opener(target, host):
            self.opened += 1
            yield self.disk
        self.discovery = Mock(return_value=[self.target])
        self.writer = NativeWriter(host='darwin', discovery=self.discovery, opener=opener,
            privilege_check=lambda host: None, temp_directory=self.directory.name)
        self.plan = build_plan(self.path, self.target)

    def run_write(self, **kwargs):
        return self.writer.run(self.plan, self.plan.confirmation, **kwargs)

    def test_write_readback_and_stale_metadata_cleanup(self):
        stages = []
        self.assertEqual(self.run_write(progress=lambda s,d,t: stages.append(s)), hashlib.sha256(self.content).hexdigest())
        self.assertEqual(self.disk.getvalue(), self.content + bytes(2048))
        self.assertEqual(set(stages), {'Staging image', 'Writing', 'Verifying'})
        self.assertEqual(self.opened, 1)

    def test_short_writes_are_completed_without_skipping_bytes(self):
        self.disk.short = True
        self.run_write()
        self.assertEqual(self.disk.getvalue()[:2048], self.content)
        self.assertGreater(self.disk.writes, 2)

    def test_confirmation_refusal_never_opens_target(self):
        with self.assertRaisesRegex(NativeWriteError, 'confirmation'):
            self.writer.run(self.plan, 'yes')
        self.assertEqual(self.opened, 0)

    def test_source_change_before_staging_never_opens_target(self):
        self.path.write_bytes(b'B'*2048)
        with self.assertRaisesRegex(NativeWriteError, 'source image changed'):
            self.run_write()
        self.assertEqual(self.opened, 0)

    def test_path_creation_time_difference_does_not_look_like_content_change(self):
        actual = self.path.lstat()
        by_path = SimpleNamespace(st_mode=actual.st_mode, st_size=actual.st_size,
                                  st_ctime_ns=actual.st_ctime_ns-1000)
        with patch.object(Path,'lstat',return_value=by_path):
            plan = build_plan(self.path,self.target)
        self.assertEqual(plan,self.plan)

    def test_preserved_mtime_cannot_hide_a_change_during_staging(self):
        import os
        original = self.path.stat()
        def change(*args):
            self.path.write_bytes(b'B'*len(self.content))
            os.utime(self.path,ns=(original.st_atime_ns,original.st_mtime_ns))
        with self.assertRaisesRegex(NativeWriteError,'source image changed'):
            self.run_write(progress=change)
        self.assertEqual(self.opened,0)

    def test_source_change_during_staging_never_opens_target(self):
        def progress(*args):
            self.path.write_bytes(b'B'*2048)
        with self.assertRaisesRegex(NativeWriteError, 'source image changed'):
            self.run_write(progress=progress)
        self.assertEqual(self.opened, 0)

    def test_target_identity_change_before_unmount_fails_closed(self):
        other = replace(self.target, hardware_id='replacement')
        self.discovery.side_effect = [[self.target], [other]]
        with self.assertRaisesRegex(NativeWriteError, 'identity'):
            self.run_write()
        self.assertEqual(self.opened, 0)

    def test_change_after_open_performs_no_write(self):
        other = replace(self.target, hardware_id='replacement')
        self.discovery.side_effect = [[self.target], [self.target], [other]]
        with self.assertRaises(NativeWriteError):
            self.run_write()
        self.assertEqual(self.disk.writes, 0)

    def test_changed_volume_set_performs_no_write(self):
        self.writer.host = 'win32'
        self.discovery.side_effect = [[self.target], [self.target], [replace(self.target, volumes=('new',))]]
        with self.assertRaisesRegex(NativeWriteError, 'volume set'):
            self.run_write()
        self.assertEqual(self.disk.writes, 0)

    def test_mac_exclusive_lock_hides_apfs_topology_without_changing_disk(self):
        self.target = replace(self.target, hardware_id='physical:apfs-uuids',
                              physical_hardware_id='physical', volumes=('/dev/disk3',))
        self.plan = build_plan(self.path, self.target)
        locked = replace(self.target, hardware_id='physical:()', volumes=())
        self.discovery.side_effect = [[self.target], [self.target], [locked], [locked]]
        self.assertEqual(self.run_write(), hashlib.sha256(self.content).hexdigest())

    def test_mac_reconnect_while_locked_performs_no_write(self):
        self.target = replace(self.target, hardware_id='physical:apfs-uuids', physical_hardware_id='physical')
        self.plan = build_plan(self.path, self.target)
        replacement = replace(self.target, hardware_id='replacement:()', physical_hardware_id='replacement')
        self.discovery.side_effect = [[self.target], [self.target], [replacement]]
        with self.assertRaisesRegex(NativeWriteError, 'identity'):
            self.run_write()
        self.assertEqual(self.disk.writes, 0)

    def test_checksum_mismatch_never_opens_target(self):
        self.plan = build_plan(self.path, self.target, expected_sha256='0'*64)
        with self.assertRaisesRegex(NativeWriteError, 'SHA-256'):
            self.run_write()
        self.assertEqual(self.opened, 0)

    def test_verification_corruption_is_failure(self):
        self.disk.corrupt = True
        with self.assertRaisesRegex(NativeWriteError, 'verification failed'):
            self.run_write()
        self.assertTrue(self.writer.write_started)

    def test_cancel_before_write_never_opens_target(self):
        self.writer.cancel()
        with self.assertRaises(NativeCancelled):
            self.run_write()
        self.assertEqual(self.opened, 0)

    def test_cancel_after_write_reports_incomplete_target(self):
        def progress(stage, *args):
            if stage == 'Writing':
                self.writer.cancel()
        with self.assertRaisesRegex(NativeCancelled, 'incomplete'):
            self.run_write(progress=progress)

    def test_unsupported_geometry_and_images_fail_before_open(self):
        for size in [0, 511, 513, 8192]:
            self.path.write_bytes(b'A'*size)
            with self.assertRaises(NativeWriteError):
                build_plan(self.path, self.target)
        self.path.write_bytes(self.content)
        for device in [replace(self.target.device, read_only=True),
                       replace(self.target.device, logical_sector_size=4096),
                       replace(self.target.device, removable=False)]:
            with self.assertRaises(NativeWriteError):
                build_plan(self.path, replace(self.target, device=device))

    def test_nonhybrid_iso_never_unmounts(self):
        iso = self.path.with_suffix('.iso')
        iso.write_bytes(self.content)
        with self.assertRaisesRegex(NativeWriteError, 'partition map'):
            build_plan(iso, self.target)
        self.assertEqual(self.opened, 0)

    def test_hybrid_iso_is_supported(self):
        iso = self.path.with_suffix('.iso')
        content = bytearray(2048)
        content[510:512] = b'\x55\xaa'
        content[450] = 0x83
        content[454:458] = (1).to_bytes(4, 'little')
        content[458:462] = (3).to_bytes(4, 'little')
        iso.write_bytes(content)
        self.plan = build_plan(iso, self.target)
        self.run_write()

    def test_one_shot_writer_cannot_repeat(self):
        self.run_write()
        with self.assertRaisesRegex(NativeWriteError, 'once'):
            self.run_write()

    def test_mounted_mac_volume_aborts_after_open_without_write(self):
        self.discovery.return_value = [replace(self.target, device=replace(self.target.device, mountpoints=('/Volumes/USB',)))]
        with self.assertRaisesRegex(NativeWriteError, 'mounted'):
            self.run_write()
        self.assertEqual(self.disk.writes, 0)

    def test_zero_progress_write_is_not_retried(self):
        self.disk.write = Mock(return_value=0)
        with self.assertRaisesRegex(NativeWriteError, 'invalid'):
            self.run_write()
        self.disk.write.assert_called_once()

    def test_worker_private_source_reuses_bound_file_without_snapshot_space(self):
        self.path.chmod(0o600)
        self.plan=build_plan(self.path,self.target)
        self.writer._worker_private_source=True
        with patch('isopropyl.native_writer.tempfile.TemporaryFile') as temporary,patch('isopropyl.native_writer.shutil.disk_usage',return_value=SimpleNamespace(free=0)):
            result=self.run_write()
        temporary.assert_not_called()
        self.assertEqual(result,hashlib.sha256(self.content).hexdigest())
        self.assertEqual(self.path.read_bytes(),self.content)

    def test_final_full_hash_detects_body_mutation_after_activation(self):
        self.writer.final_verification=True
        mutated=False
        def progress(stage,done,total):
            nonlocal mutated
            if stage=='Writing' and done==total and not mutated:
                # This stage follows the mandatory payload hash and publication
                # of the MBR; corrupt bytes outside the activation header.
                if self.disk.getvalue()[:512]==self.content[:512]:
                    self.disk.seek(512);self.disk.write(b'Z'*512);mutated=True
        with self.assertRaisesRegex(NativeWriteError,'Final verification failed'):
            self.run_write(progress=progress)
        self.assertTrue(mutated);self.assertTrue(self.writer.write_started)

    def test_optional_final_full_hash_reports_an_additional_verification_stage(self):
        self.writer.final_verification=True;stages=[]
        result=self.run_write(progress=lambda s,d,t:stages.append(s))
        self.assertEqual(result,hashlib.sha256(self.content).hexdigest())
        self.assertIn('Final verification',stages);self.assertIn('Verifying',stages)
