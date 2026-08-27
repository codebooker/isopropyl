import json
# SPDX-License-Identifier: AGPL-3.0-or-later
import subprocess
import unittest
from unittest.mock import patch

from isopropyl.devices import (
    MAX_DEVICE_DISCOVERY_OUTPUT, Device, DeviceDiscoveryError, SizeUnitMode,
    format_size, image_is_on_device, list_devices, parse_lsblk, path_is_on_device,
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
             "mountpoints": [None], "ro": False, "log-sec": 4096,
             "children": [{"path": "/dev/sdb1", "type": "part", "mountpoints": ["/media/usb"]}]},
            {"path": "/dev/loop0", "type": "loop", "size": 10, "rm": False,
             "hotplug": False, "tran": None, "mountpoints": [None]},
        ]}
        found = parse_lsblk(json.dumps(payload))
        self.assertEqual([d.path for d in found], ["/dev/sdb"])
        self.assertEqual(found[0].partitions, ("/dev/sdb1",))
        self.assertEqual(found[0].logical_sector_size, 4096)
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

    def test_si_default_is_compatible_at_unit_boundaries(self):
        for size, expected in (
            (0, "0 B"),
            (999, "999 B"),
            (1_000, "1.0 KB"),
            (1_000_000, "1.0 MB"),
            (1_000_000_000, "1.0 GB"),
            (1_000_000_000_000, "1.0 TB"),
            (1_000_000_000_000_000, "1000.0 TB"),
        ):
            with self.subTest(size=size):
                self.assertEqual(format_size(size), expected)
                self.assertEqual(format_size(size, SizeUnitMode.SI), expected)
                self.assertEqual(format_size(size, "si"), expected)

    def test_iec_mode_uses_binary_boundaries_and_labels(self):
        for size, expected in (
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1.0 KiB"),
            (1024**2, "1.0 MiB"),
            (1024**3, "1.0 GiB"),
            (1024**4, "1.0 TiB"),
            (1024**5, "1024.0 TiB"),
        ):
            with self.subTest(size=size):
                self.assertEqual(format_size(size, SizeUnitMode.IEC), expected)
                self.assertEqual(format_size(size, "iec"), expected)

    def test_fractional_values_and_rates_keep_the_existing_composition(self):
        self.assertEqual(format_size(1500.0, "si"), "1.5 KB")
        self.assertEqual(format_size(1536.0, "iec"), "1.5 KiB")
        self.assertEqual(f"{format_size(1536, 'iec')}/s", "1.5 KiB/s")

    def test_rounding_promotes_values_at_the_next_display_boundary(self):
        self.assertEqual(format_size(999_999, "si"), "1.0 MB")
        self.assertEqual(format_size(1_048_575, "iec"), "1.0 MiB")
        self.assertNotIn("1000.0 KB", format_size(999_999, "si"))
        self.assertNotIn("1024.0 KiB", format_size(1_048_575, "iec"))

    def test_invalid_modes_negative_and_non_finite_sizes_are_rejected(self):
        for mode in ("binary", "decimal", "", None):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                ValueError, "Unsupported size unit mode",
            ):
                format_size(1, mode)  # type: ignore[arg-type]
        for size in (-1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(size=size), self.assertRaisesRegex(
                ValueError, "finite, non-negative",
            ):
                format_size(size)

    def test_device_label_retains_the_decimal_default(self):
        item = Device(
            "/dev/sdb", 8_000_000_000, "Flash", "Acme", "usb", "SERIAL",
            "", "8:16", True, True, False, (), (),
        )
        self.assertEqual(item.label, "Acme Flash  ·  8.0 GB  ·  /dev/sdb")
        self.assertEqual(
            item.display_label(SizeUnitMode.IEC),
            "Acme Flash  ·  7.5 GiB  ·  /dev/sdb",
        )

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
        run.return_value.stderr = ""
        run.return_value.returncode = 0
        list_devices()
        command = run.call_args.args[0]
        self.assertIn("--tree", command)
        self.assertIn("LOG-SEC", command[-1])
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_device_discovery_timeout_and_output_are_bounded(self):
        def timed_out(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("lsblk", 15)

        with self.assertRaisesRegex(DeviceDiscoveryError, "timed out"):
            list_devices(runner=timed_out)

        completed = subprocess.CompletedProcess(
            ["lsblk"], 0, "x" * (MAX_DEVICE_DISCOVERY_OUTPUT + 1), "",
        )
        with self.assertRaisesRegex(DeviceDiscoveryError, "too much output"):
            list_devices(runner=lambda *_args, **_kwargs: completed)

    def test_device_discovery_failure_and_invalid_json_are_normalized(self):
        failed = subprocess.CompletedProcess(["lsblk"], 1, "", "no device access")
        with self.assertRaisesRegex(DeviceDiscoveryError, "no device access"):
            list_devices(runner=lambda *_args, **_kwargs: failed)
        invalid = subprocess.CompletedProcess(["lsblk"], 0, "not json", "")
        with self.assertRaisesRegex(DeviceDiscoveryError, "invalid data"):
            list_devices(runner=lambda *_args, **_kwargs: invalid)

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
