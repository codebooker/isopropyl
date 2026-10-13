# SPDX-License-Identifier: AGPL-3.0-or-later
import errno
import os
import struct
import sys
import unittest
from unittest.mock import Mock, patch

from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_disk_io import open_disk
from tests.test_native_devices import VOLUME


class NativeDiskTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'O_EXLOCK'), 'macOS authorized disk open')
    def test_authorized_descriptor_still_rejects_internal_disk(self):
        target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                    'disk2', True, True, False, (), (), 512))
        status = Mock(st_mode=0o020600, st_rdev=22)
        with patch('isopropyl.native_disk_io.command'), \
                patch('isopropyl.native_disk_io.os.open', side_effect=PermissionError(errno.EPERM, 'denied')), \
                patch('isopropyl.native_disk_io.authorized_mac_open', return_value=10) as authorized, \
                patch('isopropyl.native_disk_io.os.lstat', return_value=status), \
                patch('isopropyl.native_disk_io.os.fstat', return_value=status), \
                patch('isopropyl.native_disk_io.os.stat', return_value=status), \
                patch('isopropyl.native_disk_io.os.close') as closing, \
                patch('fcntl.ioctl', side_effect=[struct.pack('=I',512), struct.pack('=Q',8), struct.pack('=Q',0)]):
            with self.assertRaisesRegex(OSError, 'external location'):
                with open_disk(target, 'darwin'):
                    self.fail('internal authorized descriptor accepted')
        authorized.assert_called_once_with('/dev/rdisk2', os.O_RDWR | os.O_EXLOCK | os.O_NONBLOCK)
        closing.assert_called_once_with(10)

    @unittest.skipUnless(sys.platform == 'darwin', 'Apple authopen descriptor transport')
    def test_real_authopen_only_opens_a_temporary_regular_file(self):
        import tempfile

        from isopropyl.native_disk_io import authorized_mac_open
        with tempfile.NamedTemporaryFile() as source:
            source.write(b'probe'); source.flush()
            descriptor = authorized_mac_open(source.name, os.O_RDWR | os.O_EXLOCK | os.O_NONBLOCK)
            try:
                self.assertEqual(os.read(descriptor, 5), b'probe')
                self.assertEqual(os.fstat(descriptor).st_ino, os.fstat(source.fileno()).st_ino)
                self.assertFalse(os.get_inheritable(descriptor))
            finally:
                os.close(descriptor)

    def test_apfs_busy_container_aborts_before_physical_unmount_or_open(self):
        target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                    'disk2', True, True, False, (), (), 512), ('/dev/disk3',))
        with patch.dict(sys.modules,{'fcntl':Mock()}), patch('isopropyl.native_disk_io.command', side_effect=OSError('busy APFS volume')) as command, \
                patch('isopropyl.native_disk_io.os.open') as opening:
            with self.assertRaisesRegex(OSError, 'busy APFS'):
                with open_disk(target, 'darwin'):
                    self.fail('busy APFS container accepted')
            command.assert_called_once_with(['/usr/sbin/diskutil', 'unmountDisk', '/dev/disk3'])
            opening.assert_not_called()

    @unittest.skipUnless(hasattr(os, 'O_EXLOCK'), 'macOS exclusive open test')
    def test_apfs_unmounts_container_then_physical_disk_before_open(self):
        target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                    'disk2', True, True, False, (), (), 512), ('/dev/disk3',))
        with patch('isopropyl.native_disk_io.command') as command, \
                patch('isopropyl.native_disk_io.os.open', side_effect=OSError('mock open')):
            with self.assertRaisesRegex(OSError, 'mock open'):
                with open_disk(target, 'darwin'):
                    self.fail('unexpected disk open')
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['/usr/sbin/diskutil', 'unmountDisk', '/dev/disk3'],
            ['/usr/sbin/diskutil', 'unmountDisk', '/dev/disk2'],
        ])

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS flush contract')
    def test_mac_flush_uses_complete_synchronize_structure(self):
        from isopropyl.native_disk_io import MacDisk
        with patch('os.fsync') as syncing, patch('fcntl.ioctl') as ioctl:
            MacDisk(10).flush()
        syncing.assert_called_once_with(10)
        ioctl.assert_called_once_with(10, 0x80186416, bytes(24))

    @unittest.skipUnless(sys.platform == 'win32', 'Win32 ABI requires Windows')
    def test_real_windows_api_has_pointer_sized_handle_declarations(self):
        import ctypes

        from isopropyl.native_disk_io import WindowsApi
        api = WindowsApi()
        self.assertEqual(ctypes.sizeof(api.kernel.CreateFileW.restype), 8)
        self.assertEqual(ctypes.sizeof(api.kernel.SetFilePointerEx.argtypes[1]), 8)

    def setUp(self):
        privileges = patch('isopropyl.native_disk_io.os.geteuid', return_value=0, create=True)
        privileges.start()
        self.addCleanup(privileges.stop)
        self.target = NativeDevice(Device(r'\\.\PhysicalDrive2', 4096, 'Flash', '', 'usb',
            '123', '', '2', True, True, False, (), (), 512), (VOLUME,), 'usb123')
        self.api = Mock()
        self.api.open.side_effect = [100, 200]
        self.api.control.side_effect = self.control
        self.calls = []

    def control(self, handle, code, size=0):
        self.calls.append((handle, code))
        if code == 0x2D1080:
            return struct.pack('<III', 7, 2, 1)
        if code == 0x7405C:
            return struct.pack('<q', 4096)
        if code == 0x70000:
            return bytes(20) + struct.pack('<I', 512)
        return b''

    def test_backup_opens_every_windows_handle_read_only_and_holds_source_locks(self):
        from isopropyl.native_disk_io import open_read_disk
        with patch('isopropyl.native_disk_io.WindowsApi',return_value=self.api):
            with open_read_disk(self.target,'win32') as disk:
                self.assertEqual(disk.handle,200)
                self.api.kernel.CloseHandle.assert_not_called()
                self.assertIn((100,0x90018),self.calls)
                self.assertIn((100,0x90020),self.calls)
                self.api.kernel.WriteFile.assert_not_called()
        self.assertEqual([call.kwargs for call in self.api.open.call_args_list],[{'read_only':True},{'read_only':True}])
        self.assertEqual([call.args[0] for call in self.api.kernel.CloseHandle.call_args_list],[200,100])

    def test_all_windows_volume_locks_held_until_exit(self):
        with patch('isopropyl.native_disk_io.WindowsApi', return_value=self.api):
            with open_disk(self.target, 'win32') as disk:
                self.assertEqual(disk.handle, 200)
                self.api.kernel.CloseHandle.assert_not_called()
                self.assertIn((100, 0x90018), self.calls)
                self.assertIn((100, 0x90020), self.calls)
            self.assertEqual([call.args[0] for call in self.api.kernel.CloseHandle.call_args_list], [200, 100])

    def test_volume_lock_failure_closes_volume_without_opening_disk(self):
        def fail(handle, code, size=0):
            if code == 0x90018:
                raise OSError('busy volume')
            return self.control(handle, code, size)
        self.api.control.side_effect = fail
        with patch('isopropyl.native_disk_io.WindowsApi', return_value=self.api):
            with self.assertRaisesRegex(OSError, 'busy volume'):
                with open_disk(self.target, 'win32'):
                    self.fail('must not acquire a writable disk')
        self.api.open.assert_called_once_with(VOLUME.rstrip('\\'))
        self.api.kernel.CloseHandle.assert_called_once_with(100)

    def test_wrong_physical_disk_is_rejected_before_lock(self):
        self.api.control.return_value = struct.pack('<III', 7, 3, 1)
        self.api.control.side_effect = None
        with patch('isopropyl.native_disk_io.WindowsApi', return_value=self.api):
            with self.assertRaisesRegex(OSError, 'another physical disk'):
                with open_disk(self.target, 'win32'):
                    self.fail('wrong disk accepted')
        self.api.control.assert_called_once_with(100, 0x2D1080, 12)

    def test_mac_unmount_failure_never_opens_raw_device(self):
        target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                    'disk2', True, True, False, (), (), 512))
        with patch.dict(sys.modules,{'fcntl':Mock()}), patch('isopropyl.native_disk_io.command', side_effect=RuntimeError('busy')), \
                patch('isopropyl.native_disk_io.os.open') as opening:
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                with open_disk(target, 'darwin'):
                    self.fail('unmount failure accepted')
            opening.assert_not_called()

    @unittest.skipUnless(hasattr(os, 'O_EXLOCK'), 'macOS exclusive open test')
    def test_mac_internal_handle_is_rejected_and_closed(self):
        target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                    'disk2', True, True, False, (), (), 512))
        status = Mock(st_mode=0o020600, st_rdev=22)
        with patch('isopropyl.native_disk_io.command'), \
                patch('isopropyl.native_disk_io.os.open', return_value=10), \
                patch('isopropyl.native_disk_io.os.fstat', return_value=status), \
                patch('isopropyl.native_disk_io.os.stat', return_value=status), \
                patch('isopropyl.native_disk_io.os.close') as closing, \
                patch('fcntl.ioctl', side_effect=[struct.pack('=I',512), struct.pack('=Q',8), struct.pack('=Q',0)]):
            with self.assertRaisesRegex(OSError, 'external location'):
                with open_disk(target, 'darwin'):
                    self.fail('internal handle accepted')
            closing.assert_called_once_with(10)
