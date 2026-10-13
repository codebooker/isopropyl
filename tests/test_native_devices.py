# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import plistlib
import subprocess
import unittest
from unittest.mock import patch

from isopropyl.devices import DeviceDiscoveryError, list_devices
from isopropyl.native_devices import (
    WIN_DISK,
    command,
    discover,
    mac_apfs_mapping,
    mac_system_disks,
    parse_mac_device,
    parse_windows,
)

VOLUME = '\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\'


def windows_row(**changes):
    return dict(Number=2, Size=8*1024**3, Model='Flash', Serial='123', UniqueId='usb123',
                BusType='USB', IsBoot=False, IsSystem=False, IsOffline=False,
                IsReadOnly=False, LogicalSectorSize=512, Removable=True,
                AccessPaths=['E:\\', VOLUME], **changes)


def mac_row():
    return dict(DeviceIdentifier='disk2', WholeDisk=True, Internal=False,
                VirtualOrPhysical='Physical', BusProtocol='USB', RemovableMedia=True,
                WritableMedia=True, TotalSize=8*1024**3, DeviceBlockSize=512,
                DeviceTreePath='IOService:/usb/test', MediaName='Flash')


class DiscoveryTests(unittest.TestCase):
    def test_windows_discovery_suppresses_console_and_keeps_output_capture(self):
        with patch('isopropyl.native_devices.sys.platform', 'win32'), \
                patch('subprocess.CREATE_NO_WINDOW', 0x08000000, create=True), \
                patch('isopropyl.native_devices.subprocess.run', return_value=
                      subprocess.CompletedProcess([], 0, b'disks', b'')) as run:
            self.assertEqual(command(['powershell.exe', '-NoProfile']), b'disks')
        run.assert_called_once_with(['powershell.exe', '-NoProfile'], check=False,
                                    capture_output=True, timeout=30, shell=False,
                                    creationflags=0x08000000)

    def test_other_hosts_do_not_receive_windows_process_flags(self):
        with patch('isopropyl.native_devices.sys.platform', 'darwin'), \
                patch('isopropyl.native_devices.subprocess.run', return_value=
                      subprocess.CompletedProcess([], 0, b'disks', b'')) as run:
            command(['/usr/sbin/diskutil', 'list'])
        self.assertNotIn('creationflags', run.call_args.kwargs)

    def apfs_fixture(self):
        parts = [{'DeviceIdentifier': 'disk2s2', 'Content': 'Apple_APFS'}]
        container = {
            'ContainerReference': 'disk3', 'APFSContainerUUID': 'container-id',
            'PhysicalStores': [{'DeviceIdentifier': 'disk2s2'}],
            'Volumes': [{'DeviceIdentifier': 'disk3s1', 'APFSVolumeUUID': 'volume-id'}],
        }
        info = {'DeviceIdentifier': 'disk3s1', 'ParentWholeDisk': 'disk3',
                'MountPoint': '/Volumes/USB'}
        return parts, {'Containers': [container]}, info

    def test_apfs_synthesized_volumes_map_to_physical_usb(self):
        parts, apfs, volume = self.apfs_fixture()
        def runner(argv, **kwargs):
            if argv[1] == 'apfs':
                value = apfs
            elif argv[1] == 'list':
                value = {'AllDisksAndPartitions': [{'DeviceIdentifier': 'disk2', 'Partitions': parts}]}
            elif argv[-1] in {'/', '/System/Volumes/Data'}:
                value = {'ParentWholeDisk': 'disk0'}
            elif argv[-1] == 'disk2':
                value = mac_row()
            elif argv[-1] == 'disk3s1':
                value = volume
            else:
                value = {'DeviceIdentifier': 'disk2s2', 'MountPoint': ''}
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps(value), b'')
        with patch('isopropyl.native_devices.mac_registry_id', return_value=42):
            found = discover(host='darwin', runner=runner)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].device.path, '/dev/disk2')
            self.assertEqual(found[0].device.mountpoints, ('/Volumes/USB',))
            self.assertEqual(found[0].volumes, ('/dev/disk3',))
            self.assertIn('volume-id', found[0].hardware_id)
            volume['MountPoint'] = '/'
            self.assertEqual(discover(host='darwin', runner=runner), [])

    def test_missing_ambiguous_and_multi_store_apfs_mapping_excluded(self):
        parts, apfs, _ = self.apfs_fixture()
        self.assertIsNone(mac_apfs_mapping(parts, {'Containers': []}))
        self.assertIsNone(mac_apfs_mapping(parts, {'Containers': apfs['Containers'] * 2}))
        apfs['Containers'][0]['PhysicalStores'].append({'DeviceIdentifier': 'disk4s2'})
        self.assertIsNone(mac_apfs_mapping(parts, apfs))

    def test_apfs_volume_parent_mismatch_rejected(self):
        parts, apfs, volume = self.apfs_fixture()
        volume['ParentWholeDisk'] = 'disk4'
        runner = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, plistlib.dumps(volume), b'')
        with self.assertRaisesRegex(ValueError, 'mapping changed'):
            mac_apfs_mapping(parts, apfs, runner=runner)

    def test_windows_volume_guids_and_identity(self):
        found = parse_windows(json.dumps([windows_row()]))
        self.assertEqual(found[0].device.path, r'\\.\PhysicalDrive2')
        self.assertTrue(WIN_DISK.fullmatch(found[0].device.path))
        self.assertEqual(found[0].volumes, (VOLUME,))
        self.assertEqual(found[0].device.mountpoints, ('E:\\',))
        self.assertEqual(found[0].hardware_id, 'usb123')

    def test_windows_system_disks_are_excluded_even_on_usb(self):
        for key, value in [('IsBoot', True), ('IsSystem', True), ('IsOffline', True),
                           ('BusType', 'NVMe'), ('IsBoot', None), ('IsSystem', 'False')]:
            row = windows_row()
            row[key] = value
            self.assertEqual(parse_windows(json.dumps([row]), True), [])

    def test_fixed_windows_disk_requires_opt_in(self):
        row = windows_row()
        row['Removable'] = False
        self.assertEqual(parse_windows(json.dumps([row])), [])
        self.assertEqual(len(parse_windows(json.dumps([row]), True)), 1)

    def test_invalid_windows_metadata_fails_closed(self):
        for key, value in [('Number', '../../evil'), ('Number', True), ('Size', -1),
                           ('LogicalSectorSize', 0), ('AccessPaths', ['E:\\'])]:
            row = windows_row()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse_windows(json.dumps([row]))

    def test_apfs_startup_physical_stores_are_forbidden(self):
        self.assertEqual(mac_system_disks(dict(ParentWholeDisk='disk3',
            APFSPhysicalStores=[{'APFSPhysicalStore':'disk0s2'}, {'APFSPhysicalStore':'disk4s1'}])),
            {'disk0', 'disk3', 'disk4'})

    def test_mac_selection_and_mounts(self):
        found = parse_mac_device(mac_row(), [dict(DeviceIdentifier='disk2s1', MountPoint='/Volumes/USB')], set(), False)
        self.assertEqual(found.device.path, '/dev/disk2')
        self.assertEqual(found.device.mountpoints, ('/Volumes/USB',))
        for key, value in [('Internal', True), ('Internal', None), ('WholeDisk', False),
                           ('VirtualOrPhysical', 'Virtual'), ('DeviceIdentifier', 'disk2s1'),
                           ('BusProtocol', 'PCI')]:
            row = mac_row()
            row[key] = value
            self.assertIsNone(parse_mac_device(row, [], set(), True))
        self.assertIsNone(parse_mac_device(mac_row(), [], {'disk2'}, True))
        self.assertIsNone(parse_mac_device(mac_row(), [{'MountPoint':'/'}], set(), True))

    def test_native_dispatch_uses_no_lsblk(self):
        with patch('isopropyl.devices.sys.platform', 'win32'), \
                patch('isopropyl.native_devices.discover', return_value=[]) as probe:
            self.assertEqual(list_devices(), [])
            probe.assert_called_once_with(False, runner=None)

    def test_native_command_failures_are_bounded(self):
        for result in [subprocess.CompletedProcess([], 1, b'', b'no access'),
                       subprocess.CompletedProcess([], 0, b'x'*(2*1024*1024+1), b'')]:
            with self.assertRaises(DeviceDiscoveryError):
                command(['tool'], runner=lambda *a, result=result, **k: result)
        with self.assertRaises(DeviceDiscoveryError):
            command(['tool'], runner=unittest.mock.Mock(side_effect=subprocess.TimeoutExpired('tool',30)))

    def test_mac_no_devices_and_startup_queries(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            value = {'AllDisksAndPartitions': []} if argv[1] == 'list' else {'ParentWholeDisk': 'disk0'}
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps(value), b'')
        self.assertEqual(discover(host='darwin', runner=runner), [])
        self.assertEqual([c[-1] for c in calls[:2]], ['/', '/System/Volumes/Data'])

    def test_duplicate_windows_disk_identity_is_rejected(self):
        result = subprocess.CompletedProcess([], 0, json.dumps([windows_row(), windows_row()]).encode(), b'')
        with self.assertRaisesRegex(DeviceDiscoveryError, 'invalid data'):
            discover(host='win32', runner=lambda *a, **k: result)

    def test_windows_sd_is_supported_only_with_explicit_removable_metadata(self):
        row=windows_row();row['BusType']='SD'
        self.assertEqual(parse_windows(json.dumps([row]))[0].device.transport,'sd')
        row['Removable']=False
        self.assertEqual(parse_windows(json.dumps([row]),True),[])
        row['Removable']=True;row['BusType']='MMC'
        self.assertEqual(parse_windows(json.dumps([row]),True),[])
