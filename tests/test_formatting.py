# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from isopropyl.devices import Device
from isopropyl.formatting import (
    DeviceChangedError,
    Filesystem,
    FormatCancelled,
    FormatExecutor,
    FormatPlan,
    FormatTools,
    FormatValidationError,
    FormattingError,
    MissingFormatToolError,
    PartitionTable,
    create_format_plan,
    format_command,
    parse_partitions,
    partition_command,
    partition_script,
    resolve_tools,
    validate_label,
)


def test_device(**changes):
    values = dict(
        path="/dev/sdz", size=32_000_000_000, model="Flash", vendor="Acme",
        transport="usb", serial="SERIAL", wwn="", major_minor="65:144",
        removable=True, hotplug=True, read_only=False,
        mountpoints=("/media/usb",), partitions=("/dev/sdz1",),
    )
    values.update(changes)
    return Device(**values)


TOOLS = FormatTools(
    "/usr/bin/pkexec", "/usr/bin/udisksctl", "/usr/sbin/sfdisk",
    "/usr/sbin/partprobe", "/usr/bin/udevadm", "/usr/bin/lsblk",
    "/usr/sbin/mkfs.vfat",
)


class FakeProcess:
    def __init__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.returncode = 0
        self.inputs = []
        self.terminated = False

    def communicate(self, input=None, timeout=None):
        self.inputs.append(input)
        return b"", b""

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class FormatPlanTests(unittest.TestCase):
    def test_supports_each_filesystem_and_partition_table(self):
        for filesystem in Filesystem:
            for table in PartitionTable:
                with self.subTest(filesystem=filesystem, table=table):
                    plan = create_format_plan(test_device(), filesystem, table, "USB")
                    self.assertEqual(plan.device_identity, test_device().identity)
                    self.assertEqual(plan.filesystem, filesystem)
                    self.assertEqual(plan.partition_table, table)

    def test_rejects_unsafe_devices(self):
        cases = (
            test_device(path="/dev/sdz1"),
            test_device(path="--help"),
            test_device(read_only=True),
            test_device(transport="nvme", removable=False, hotplug=False),
            test_device(size=1000),
            test_device(major_minor=""),
            test_device(partitions=("/dev/sdy1",)),
        )
        for device in cases:
            with self.subTest(device=device):
                with self.assertRaises(FormatValidationError):
                    create_format_plan(device, "fat32", "mbr")

    def test_filesystem_specific_label_limits_and_characters(self):
        self.assertEqual(validate_label("fat32", "ELEVENCHARS"), "ELEVENCHARS")
        self.assertEqual(validate_label("exfat", "portable"), "portable")
        self.assertEqual(validate_label("ntfs", "Windows media"), "Windows media")
        self.assertEqual(validate_label("ext4", "Linux media"), "Linux media")
        for filesystem, label in (
            ("fat32", "twelve-chars"), ("fat32", "BAD:LABEL"),
            ("exfat", "x" * 16), ("ntfs", "x" * 33),
            ("ext4", "0123456789abcdefg"), ("ext4", "bad/label"),
        ):
            with self.subTest(filesystem=filesystem, label=label):
                with self.assertRaises(FormatValidationError):
                    validate_label(filesystem, label)

    def test_partition_scripts_have_explicit_table_alignment_and_type(self):
        fat_mbr = create_format_plan(test_device(), "fat32", "mbr")
        ext_gpt = create_format_plan(test_device(), "ext4", "gpt")
        self.assertEqual(
            partition_script(fat_mbr),
            b"label: dos\nunit: sectors\n\nstart=2048, type=c\n",
        )
        self.assertIn(b"label: gpt", partition_script(ext_gpt))
        self.assertIn(b"0FC63DAF-8483-4772-8E79-3D69D8477DE4", partition_script(ext_gpt))

    def test_commands_are_argv_and_labels_remain_single_arguments(self):
        plan = create_format_plan(test_device(), "fat32", "mbr", "MY USB")
        self.assertEqual(partition_command(plan, TOOLS)[0:2], [TOOLS.pkexec, TOOLS.sfdisk])
        self.assertEqual(
            format_command(plan, TOOLS, "/dev/sdz1"),
            [TOOLS.pkexec, TOOLS.mkfs, "-F", "32", "-n", "MY USB", "/dev/sdz1"],
        )
        with self.assertRaises(FormatValidationError):
            format_command(plan, TOOLS, "--help")
        with self.assertRaises(FormatValidationError):
            format_command(plan, TOOLS, "/dev/sdy1")

    def test_nvme_and_mmc_partition_child_naming_is_supported(self):
        for device_path, partition_path in (
            ("/dev/nvme1n2", "/dev/nvme1n2p1"),
            ("/dev/mmcblk2", "/dev/mmcblk2p1"),
        ):
            with self.subTest(device_path=device_path):
                device = test_device(
                    path=device_path, transport="mmc" if "mmc" in device_path else "usb",
                    partitions=(partition_path,),
                )
                plan = create_format_plan(device, "ext4", "gpt")
                self.assertEqual(format_command(plan, TOOLS, partition_path)[-1], partition_path)

    def test_mkfs_flags_for_exfat_ntfs_and_ext4(self):
        for filesystem, expected in (
            ("exfat", ["-L", "USB"]),
            ("ntfs", ["-f", "-L", "USB"]),
            ("ext4", ["-F", "-L", "USB"]),
        ):
            tools = FormatTools(*TOOLS.__dict__.values())
            plan = create_format_plan(test_device(), filesystem, "gpt", "USB")
            command = format_command(plan, tools, "/dev/sdz1")
            for argument in expected:
                self.assertIn(argument, command)

    def test_missing_tools_are_reported_together(self):
        plan = create_format_plan(test_device(), "exfat", "gpt")
        with self.assertRaisesRegex(MissingFormatToolError, "sfdisk.*mkfs.exfat"):
            resolve_tools(
                plan,
                lambda name: None if name in {"sfdisk", "mkfs.exfat"} else f"/x/{name}",
            )

    @patch("isopropyl.formatting.shutil.which")
    def test_default_tool_search_does_not_use_the_session_path(self, which):
        which.side_effect = lambda name, path: f"/usr/bin/{name}"
        plan = create_format_plan(test_device(), "fat32", "mbr")
        resolve_tools(plan)
        self.assertTrue(which.call_args_list)
        self.assertTrue(all(
            call.kwargs["path"] == "/usr/sbin:/usr/bin:/sbin:/bin"
            for call in which.call_args_list
        ))

    def test_manually_forged_plan_cannot_bypass_enum_validation(self):
        device = test_device()
        forged = FormatPlan(
            device.path, device.identity, "fat32", "mbr", "USB"  # type: ignore[arg-type]
        )
        with self.assertRaises(FormatValidationError):
            resolve_tools(forged, lambda name: f"/x/{name}")

    def test_partition_discovery_only_accepts_descendants(self):
        payload = json.dumps({"blockdevices": [
            {"path": "/dev/sdy", "type": "disk", "children": [
                {"path": "/dev/sdy1", "type": "part"},
            ]},
            {"path": "/dev/sdz", "type": "disk", "children": [
                {"path": "/dev/sdz1", "type": "part"},
            ]},
        ]})
        self.assertEqual(parse_partitions(payload, "/dev/sdz"), ("/dev/sdz1",))


class FormatExecutorTests(unittest.TestCase):
    def setUp(self):
        self.device = test_device()
        self.plan = create_format_plan(self.device, "fat32", "mbr", "USB")
        self.processes = []
        self.run_calls = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            self.processes.append(process)
            return process

        def runner(argv, **kwargs):
            self.run_calls.append((argv, kwargs))
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part"},
                    ],
                }]}))
            return completed()

        self.executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            popen=popen, runner=runner, sleep=lambda _seconds: None,
        )

    def test_complete_flow_unmounts_partitions_and_uses_no_shell(self):
        stages = []
        partition = self.executor.execute(self.device, self.plan, stages.append)
        self.assertEqual(partition, "/dev/sdz1")
        self.assertEqual(
            self.run_calls[0][0],
            ["/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sdz1"],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in self.run_calls))
        self.assertTrue(all(process.kwargs["shell"] is False for process in self.processes))
        self.assertEqual(self.processes[0].inputs[0], partition_script(self.plan))
        self.assertEqual(self.processes[-2].argv[-1], "/dev/sdz1")
        self.assertEqual(stages[-1], "Complete")

    def test_preflight_missing_tool_never_unmounts_or_spawns(self):
        executor = FormatExecutor(
            device_lookup=lambda _path: self.device, which=lambda _name: None,
            popen=Mock(), runner=Mock(),
        )
        with self.assertRaises(MissingFormatToolError):
            executor.execute(self.device, self.plan)
        executor._popen.assert_not_called()
        executor._runner.assert_not_called()

    def test_changed_device_is_rejected_before_unmount(self):
        changed = test_device(serial="DIFFERENT")
        runner = Mock()
        executor = FormatExecutor(
            device_lookup=lambda _path: changed,
            which=lambda name: f"/usr/bin/{name}", runner=runner,
        )
        with self.assertRaises(DeviceChangedError):
            executor.execute(self.device, self.plan)
        runner.assert_not_called()

    def test_cancel_before_start_runs_no_commands(self):
        self.executor.cancel()
        with self.assertRaises(FormatCancelled):
            self.executor.execute(self.device, self.plan)
        self.assertEqual(self.run_calls, [])
        self.assertEqual(self.processes, [])

    def test_cancel_terminates_an_in_flight_privileged_process(self):
        holder = {}

        class SlowProcess(FakeProcess):
            def __init__(self, argv, **kwargs):
                super().__init__(argv, **kwargs)
                self.returncode = None
                self.timed_out = False

            def communicate(self, input=None, timeout=None):
                if timeout is not None and not self.timed_out:
                    self.timed_out = True
                    holder["executor"].cancel()
                    raise subprocess.TimeoutExpired(self.argv, timeout)
                return b"", b""

        processes = []

        def popen(argv, **kwargs):
            process = SlowProcess(argv, **kwargs)
            processes.append(process)
            return process

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen,
            runner=lambda _argv, **_kwargs: completed(),
        )
        holder["executor"] = executor
        with self.assertRaises(FormatCancelled):
            executor.execute(self.device, self.plan)
        self.assertEqual(len(processes), 1)
        self.assertTrue(processes[0].terminated)

    def test_unmount_failure_stops_before_partitioning(self):
        def runner(argv, **_kwargs):
            return completed(stderr="device is busy", code=1)

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", runner=runner,
            popen=lambda *_args, **_kwargs: self.fail("must not partition"),
        )
        with self.assertRaisesRegex(FormattingError, "device is busy"):
            executor.execute(self.device, self.plan)

    def test_multiple_discovered_partitions_are_not_guessed(self):
        def runner(argv, **_kwargs):
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part"},
                        {"path": "/dev/sdz2", "type": "part"},
                    ],
                }]}))
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", runner=runner,
            popen=lambda argv, **kwargs: FakeProcess(argv, **kwargs),
        )
        with self.assertRaisesRegex(FormattingError, "more than one"):
            executor.execute(self.device, self.plan)


if __name__ == "__main__":
    unittest.main()
