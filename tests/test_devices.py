import json
# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
from unittest.mock import patch

from isopropyl.devices import (
    Device, format_size, image_is_on_device, list_devices, parse_lsblk,
    path_is_on_device,
)


class DeviceTests(unittest.TestCase):
    def test_filters_fixed_loop_and_root_disk(self):
        payload = {"blockdevices": [
            {"path": "/dev/nvme0n1", "type": "disk", "size": 1000, "rm": False,
             "hotplug": False, "tran": "nvme", "mountpoints": [None],
             "children": [{"path": "/dev/nvme0n1p1", "type": "part", "mountpoints": ["/"]}]},
            {"path": "/dev/sdb", "type": "disk", "size": 8000000000, "rm": True,
             "hotplug": True, "tran": "usb", "model": "Flash", "vendor": "Acme",
             "serial": "ABC", "wwn": None, "maj:min": "8:16",
             "mountpoints": [None], "ro": False,
             "children": [{"path": "/dev/sdb1", "type": "part", "mountpoints": ["/media/usb"]}]},
            {"path": "/dev/loop0", "type": "loop", "size": 10, "rm": False,
             "hotplug": False, "tran": None, "mountpoints": [None]},
        ]}
        found = parse_lsblk(json.dumps(payload))
        self.assertEqual([d.path for d in found], ["/dev/sdb"])
        self.assertEqual(found[0].partitions, ("/dev/sdb1",))
        self.assertEqual(found[0].identity, ("/dev/sdb", 8000000000, "ABC", "", "Flash", "8:16"))

    def test_root_usb_is_never_a_target(self):
        payload = {"blockdevices": [{
            "path": "/dev/sda", "type": "disk", "size": 100, "rm": True,
            "hotplug": True, "tran": "usb", "mountpoints": ["/"], "ro": False,
        }]}
        self.assertEqual(parse_lsblk(json.dumps(payload)), [])

    def test_usb_hard_drives_require_explicit_opt_in(self):
        payload = {"blockdevices": [{
            "path": "/dev/sdc", "type": "disk", "size": 2_000_000_000_000,
            "rm": False, "hotplug": True, "tran": "usb", "model": "Backup SSD",
            "mountpoints": [], "ro": False,
        }]}
        self.assertEqual(parse_lsblk(json.dumps(payload)), [])
        self.assertEqual(
            [device.path for device in parse_lsblk(json.dumps(payload), include_usb_hdds=True)],
            ["/dev/sdc"],
        )

    def test_decimal_sizes(self):
        self.assertEqual(format_size(2_500_000_000), "2.5 GB")

    def test_stable_denylist_id_prefers_wwn_then_transport_serial(self):
        base = Device(
            "/dev/sdb", 100, "Flash", "", "usb", "SERIAL", "WWN", "8:16",
            True, True, False, (), (),
        )
        self.assertEqual(base.stable_id, "wwn:wwn")
        self.assertEqual(Device(**{**base.__dict__, "wwn": ""}).stable_id, "serial:usb:serial")
        self.assertIsNone(Device(**{**base.__dict__, "wwn": "", "serial": ""}).stable_id)

    @patch("isopropyl.devices.subprocess.run")
    def test_lsblk_is_explicitly_requested_as_a_tree(self, run):
        run.return_value.stdout = '{"blockdevices": []}'
        list_devices()
        command = run.call_args.args[0]
        self.assertIn("--tree", command)

    @patch("isopropyl.devices.os.stat")
    def test_detects_image_stored_on_target_partition(self, stat):
        values = {
            "/media/usb/image.iso": (2049, 0),
            "/dev/sdb": (0, 2048),
            "/dev/sdb1": (0, 2049),
        }
        stat.side_effect = lambda path: type(
            "Info", (), {"st_dev": values[str(path)][0], "st_rdev": values[str(path)][1]}
        )()
        device = Device(
            "/dev/sdb", 100, "Flash", "", "usb", "S", "", "8:16",
            True, True, False, ("/media/usb",), ("/dev/sdb1",),
        )
        self.assertTrue(image_is_on_device("/media/usb/image.iso", device))

    @patch("isopropyl.devices.os.path.exists", side_effect=lambda path: path == "/media/usb")
    @patch("isopropyl.devices.os.stat")
    def test_detects_prospective_backup_on_source_drive(self, stat, _exists):
        values = {
            "/media/usb": (2049, 0),
            "/dev/sdb": (0, 2048),
            "/dev/sdb1": (0, 2049),
        }
        stat.side_effect = lambda path: type(
            "Info", (), {"st_dev": values[str(path)][0], "st_rdev": values[str(path)][1]}
        )()
        device = Device(
            "/dev/sdb", 100, "Flash", "", "usb", "S", "", "8:16",
            True, True, False, ("/media/usb",), ("/dev/sdb1",),
        )
        self.assertTrue(path_is_on_device("/media/usb/backup.img", device))


if __name__ == "__main__":
    unittest.main()
