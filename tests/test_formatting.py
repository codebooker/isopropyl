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
    MultiFormatExecutor,
    MultiFormatPlan,
    MultiFormatTools,
    MissingFormatToolError,
    PartitionRole,
    PartitionSpec,
    PartitionTable,
    create_format_plan,
    create_multi_format_plan,
    create_uefi_ntfs_format_plan,
    format_command,
    multi_format_commands,
    multi_partition_command,
    multi_partition_script,
    parse_logical_sector_size,
    parse_partitions,
    partition_command,
    partition_script,
    resolve_multi_tools,
    resolve_tools,
    validate_label,
    validate_explicit_partition_metadata,
    validate_multi_plan,
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
        self.killed = False

    def communicate(self, input=None, timeout=None):
        self.inputs.append(input)
        return b"", b""

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


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


class MultiFormatPlanTests(unittest.TestCase):
    def test_builds_gpt_efi_and_ntfs_layout(self):
        plan = create_multi_format_plan(test_device(), "gpt", (
            PartitionSpec(
                PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ISOPROPYL", 32,
            ),
            PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "ISO_DATA"),
        ))
        self.assertEqual(plan.device_identity, test_device().identity)
        self.assertEqual(len(plan.partitions), 2)
        self.assertEqual(plan.partitions[1].size_mib, None)
        script = multi_partition_script(plan)
        self.assertEqual(
            script,
            b"label: gpt\n\n"
            b"size=32MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, "
            b'name="ISOpropyl boot"\n'
            b"type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, "
            b'name="ISOpropyl data"\n',
        )

    def test_supports_mbr_data_and_persistence_layout(self):
        plan = create_multi_format_plan(test_device(), "mbr", (
            PartitionSpec(
                PartitionRole.DATA, Filesystem.FAT32, "LIVE", 2048, True,
            ),
            PartitionSpec(
                PartitionRole.PERSISTENCE, Filesystem.EXT4, "persistence",
            ),
        ))
        self.assertEqual(
            multi_partition_script(plan),
            b"label: dos\n\n"
            b"size=2048MiB, type=c, bootable\n"
            b"type=83\n",
        )

    def test_supports_unformatted_microsoft_reserved_partition(self):
        plan = create_multi_format_plan(test_device(), "gpt", (
            PartitionSpec(
                PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ESP", 100,
            ),
            PartitionSpec(
                PartitionRole.MICROSOFT_RESERVED, None, size_mib=16,
            ),
            PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "WINDOWS"),
        ))
        tools = MultiFormatTools(
            "/usr/bin/pkexec", "/usr/bin/udisksctl", "/usr/sbin/sfdisk",
            "/usr/sbin/partprobe", "/usr/bin/udevadm", "/usr/bin/lsblk",
            ((Filesystem.FAT32, "/usr/sbin/mkfs.vfat"),
             (Filesystem.NTFS, "/usr/sbin/mkfs.ntfs")),
        )
        commands = multi_format_commands(
            plan, tools, ("/dev/sdz1", "/dev/sdz2", "/dev/sdz3"),
        )
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][-1], "/dev/sdz1")
        self.assertEqual(commands[1][-1], "/dev/sdz3")

    def test_represents_raw_uefi_ntfs_tail_partition_without_formatting_it(self):
        plan = create_uefi_ntfs_format_plan(test_device(), "gpt")
        total_sectors = test_device().size // 512
        boot_start = ((total_sectors - 33 - 2048) // 2048) * 2048
        self.assertEqual(plan.logical_sector_size, 512)
        self.assertEqual(plan.partitions[0].start_sector, 2048)
        self.assertEqual(plan.partitions[0].sector_count, boot_start - 2048)
        self.assertEqual(plan.partitions[1].start_sector, boot_start)
        script = multi_partition_script(plan)
        self.assertIn(b"unit: sectors\nsector-size: 512", script)
        self.assertIn(b"start=2048", script)
        self.assertIn(f"size={boot_start - 2048}".encode(), script)
        self.assertIn(b'type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7', script)
        self.assertIn(b'name="UEFI:NTFS", attrs=63', script)
        tools = MultiFormatTools(
            "/usr/bin/pkexec", "/usr/bin/udisksctl", "/usr/sbin/sfdisk",
            "/usr/sbin/partprobe", "/usr/bin/udevadm", "/usr/bin/lsblk",
            ((Filesystem.NTFS, "/usr/sbin/mkfs.ntfs"),),
        )
        self.assertEqual(
            multi_format_commands(plan, tools, ("/dev/sdz1", "/dev/sdz2")),
            ([
                "/usr/bin/pkexec", "/usr/sbin/mkfs.ntfs", "-f", "-L",
                "ISO_DATA", "/dev/sdz1",
            ],),
        )

    def test_rejects_malformed_uefi_ntfs_partition(self):
        for spec in (
            PartitionSpec(PartitionRole.UEFI_NTFS, Filesystem.FAT32, size_mib=1),
            PartitionSpec(PartitionRole.UEFI_NTFS, None, size_mib=2),
            PartitionSpec(PartitionRole.UEFI_NTFS, None, "BOOT", 1),
        ):
            with self.subTest(spec=spec):
                with self.assertRaisesRegex(FormatValidationError, "UEFI:NTFS"):
                    create_multi_format_plan(test_device(), "gpt", (
                        PartitionSpec(
                            PartitionRole.DATA, Filesystem.NTFS, "DATA", 100,
                        ),
                        spec,
                    ))

    def test_uefi_ntfs_geometry_is_narrow_and_device_bound(self):
        correct = create_uefi_ntfs_format_plan(test_device(), "gpt")
        assert correct.partitions[0].sector_count is not None
        assert correct.partitions[1].start_sector is not None
        with self.assertRaisesRegex(FormatValidationError, "device-sized"):
            create_multi_format_plan(test_device(), "gpt", (
                PartitionSpec(
                    PartitionRole.DATA, Filesystem.NTFS, "DATA",
                    start_sector=2048,
                    sector_count=correct.partitions[0].sector_count - 1,
                ),
                PartitionSpec(
                    PartitionRole.UEFI_NTFS, None,
                    start_sector=correct.partitions[1].start_sector,
                    sector_count=2048,
                ),
            ), logical_sector_size=512)
        with self.assertRaisesRegex(FormatValidationError, "NTFS or exFAT"):
            create_uefi_ntfs_format_plan(
                test_device(), "gpt", filesystem=Filesystem.FAT32,
            )
        with self.assertRaisesRegex(FormatValidationError, "requires MBR"):
            create_uefi_ntfs_format_plan(
                test_device(), "gpt", bios_bootable=True,
            )
        with self.assertRaisesRegex(FormatValidationError, "512-byte"):
            create_uefi_ntfs_format_plan(
                test_device(), "gpt", logical_sector_size=4096,
            )
        mbr = create_uefi_ntfs_format_plan(
            test_device(), "mbr", bios_bootable=True,
        )
        self.assertIn(b"bootable", multi_partition_script(mbr))

    def test_validates_exact_post_partition_gpt_metadata(self):
        plan = create_uefi_ntfs_format_plan(test_device(), "gpt")
        paths = ("/dev/sdz1", "/dev/sdz2")
        payload = {
            "partitiontable": {
                "label": "gpt", "device": "/dev/sdz", "unit": "sectors",
                "sectorsize": 512,
                "partitions": [
                    {
                        "node": paths[0], "start": plan.partitions[0].start_sector,
                        "size": plan.partitions[0].sector_count,
                        "type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                        "name": "ISOpropyl data",
                    },
                    {
                        "node": paths[1], "start": plan.partitions[1].start_sector,
                        "size": 2048,
                        "type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                        "name": "UEFI:NTFS", "attrs": "GUID:63",
                    },
                ],
            },
        }
        validate_explicit_partition_metadata(plan, json.dumps(payload), paths)
        mutations = (
            ("sectorsize", 4096),
            ("label", "dos"),
            ("device", "/dev/sdy"),
        )
        for field, value in mutations:
            changed = json.loads(json.dumps(payload))
            changed["partitiontable"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(FormattingError):
                    validate_explicit_partition_metadata(
                        plan, json.dumps(changed), paths,
                    )
        for index, field, value in (
            (0, "start", 4096),
            (0, "size", 1),
            (0, "node", "/dev/sdy1"),
            (0, "type", "0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
            (1, "name", "ESP"),
            (1, "attrs", "GUID:62"),
        ):
            changed = json.loads(json.dumps(payload))
            changed["partitiontable"]["partitions"][index][field] = value
            with self.subTest(partition=index, field=field):
                with self.assertRaises(FormattingError):
                    validate_explicit_partition_metadata(
                        plan, json.dumps(changed), paths,
                    )

    def test_validates_exact_post_partition_mbr_metadata(self):
        plan = create_uefi_ntfs_format_plan(
            test_device(), "mbr", bios_bootable=True,
        )
        paths = ("/dev/sdz1", "/dev/sdz2")
        payload = json.dumps({"partitiontable": {
            "label": "dos", "device": "/dev/sdz", "unit": "sectors",
            "sectorsize": 512,
            "partitions": [
                {
                    "node": paths[0], "start": plan.partitions[0].start_sector,
                    "size": plan.partitions[0].sector_count,
                    "type": "7", "bootable": True,
                },
                {
                    "node": paths[1], "start": plan.partitions[1].start_sector,
                    "size": 2048, "type": "ef",
                },
            ],
        }})
        validate_explicit_partition_metadata(plan, payload, paths)

    def test_rejects_incoherent_partition_roles(self):
        cases = (
            ("gpt", ()),
            ("gpt", (PartitionSpec(PartitionRole.DATA, None),)),
            ("gpt", (PartitionSpec(
                PartitionRole.EFI_SYSTEM, Filesystem.NTFS, "ESP",
            ),)),
            ("gpt", (PartitionSpec(
                PartitionRole.PERSISTENCE, Filesystem.FAT32, "persist",
            ),)),
            ("mbr", (PartitionSpec(
                PartitionRole.MICROSOFT_RESERVED, None, size_mib=16,
            ),)),
            ("gpt", (PartitionSpec(
                PartitionRole.DATA, Filesystem.FAT32, "DATA", bootable=True,
            ),)),
            ("gpt", (
                PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "A"),
                PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "B"),
            )),
            ("gpt", (PartitionSpec(
                PartitionRole.DATA, Filesystem.NTFS, "DATA", 0,
            ),)),
        )
        for table, specs in cases:
            with self.subTest(table=table, specs=specs):
                with self.assertRaises(FormatValidationError):
                    create_multi_format_plan(test_device(), table, specs)

    def test_rejects_duplicate_singleton_roles_and_oversized_fixed_layout(self):
        duplicate = (
            PartitionSpec(PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ESP1", 32),
            PartitionSpec(PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ESP2"),
        )
        with self.assertRaisesRegex(FormatValidationError, "more than one"):
            create_multi_format_plan(test_device(), "gpt", duplicate)
        with self.assertRaisesRegex(FormatValidationError, "do not fit"):
            create_multi_format_plan(test_device(size=20 * 1024 * 1024), "gpt", (
                PartitionSpec(PartitionRole.DATA, Filesystem.FAT32, "DATA", 19),
            ))

    def test_resolves_each_formatter_once_and_validates_partition_paths(self):
        plan = create_multi_format_plan(test_device(), "gpt", (
            PartitionSpec(PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ESP", 32),
            PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "DATA"),
        ))
        requested = []

        def finder(name):
            requested.append(name)
            return f"/usr/bin/{name}"

        tools = resolve_multi_tools(plan, finder)
        self.assertEqual(requested.count("mkfs.vfat"), 1)
        self.assertEqual(requested.count("mkfs.ntfs"), 1)
        self.assertEqual(
            multi_partition_command(plan, tools)[:2],
            ["/usr/bin/pkexec", "/usr/bin/sfdisk"],
        )
        with self.assertRaises(FormatValidationError):
            multi_format_commands(plan, tools, ("/dev/sdz1",))
        with self.assertRaises(FormatValidationError):
            multi_format_commands(plan, tools, ("/dev/sdz1", "/dev/sdy2"))

    def test_forged_multi_plan_cannot_bypass_enum_validation(self):
        device = test_device()
        forged = MultiFormatPlan(
            device.path, device.identity, PartitionTable.GPT,
            (PartitionSpec("data", Filesystem.NTFS),),  # type: ignore[arg-type]
        )
        with self.assertRaises(FormatValidationError):
            validate_multi_plan(forged)

    def test_partition_discovery_is_sorted_by_partition_number(self):
        payload = json.dumps({"blockdevices": [{
            "path": "/dev/nvme1n2", "type": "disk", "children": [
                {"path": "/dev/nvme1n2p10", "type": "part"},
                {"path": "/dev/nvme1n2p2", "type": "part"},
                {"path": "/dev/nvme1n2p1", "type": "part"},
            ],
        }]})
        self.assertEqual(
            parse_partitions(payload, "/dev/nvme1n2"),
            ("/dev/nvme1n2p1", "/dev/nvme1n2p2", "/dev/nvme1n2p10"),
        )

    def test_logical_sector_probe_requires_one_exact_whole_device(self):
        payload = json.dumps({"blockdevices": [{
            "path": "/dev/sdz", "type": "disk", "log-sec": 512,
        }]})
        self.assertEqual(parse_logical_sector_size(payload, "/dev/sdz"), 512)
        for bad in (
            {"blockdevices": []},
            {"blockdevices": [{"path": "/dev/sdy", "type": "disk", "log-sec": 512}]},
            {"blockdevices": [{"path": "/dev/sdz", "type": "part", "log-sec": 512}]},
            {"blockdevices": [{"path": "/dev/sdz", "type": "disk", "log-sec": 1000}]},
        ):
            with self.subTest(payload=bad), self.assertRaises(FormattingError):
                parse_logical_sector_size(json.dumps(bad), "/dev/sdz")


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

    def test_stuck_child_is_killed_after_bounded_timeout(self):
        class StubbornProcess(FakeProcess):
            def __init__(self, argv, **kwargs):
                super().__init__(argv, **kwargs)
                self.returncode = None

            def communicate(self, input=None, timeout=None):
                self.inputs.append(input)
                if not self.killed:
                    raise subprocess.TimeoutExpired(self.argv, timeout)
                return b"", b""

            def terminate(self):
                self.terminated = True

        processes = []

        def popen(argv, **kwargs):
            process = StubbornProcess(argv, **kwargs)
            processes.append(process)
            return process

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen,
            runner=lambda _argv, **_kwargs: completed(),
            process_timeout=0.01, stop_grace=0.01,
        )
        with self.assertRaisesRegex(FormattingError, "timed out"):
            executor.execute(self.device, self.plan)
        self.assertTrue(processes[0].terminated)
        self.assertTrue(processes[0].killed)

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


class MultiFormatExecutorTests(unittest.TestCase):
    def setUp(self):
        self.device = test_device(
            mountpoints=("/media/usb",),
            partitions=("/dev/sdz1", "/dev/sdz2"),
        )
        self.plan = create_multi_format_plan(self.device, "gpt", (
            PartitionSpec(
                PartitionRole.EFI_SYSTEM, Filesystem.FAT32, "ISOPROPYL", 32,
            ),
            PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "ISO_DATA"),
        ))
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
                        {"path": "/dev/sdz2", "type": "part"},
                        {"path": "/dev/sdz1", "type": "part"},
                    ],
                }]}))
            return completed()

        self.executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            popen=popen, runner=runner, sleep=lambda _seconds: None,
        )

    def test_complete_flow_creates_and_formats_exact_ordered_layout(self):
        stages = []
        partitions = self.executor.execute_multi(self.device, self.plan, stages.append)
        self.assertEqual(partitions, ("/dev/sdz1", "/dev/sdz2"))
        self.assertEqual(
            [call[0][3] for call in self.run_calls[:2]],
            ["/dev/sdz1", "/dev/sdz2"],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in self.run_calls))
        self.assertTrue(all(process.kwargs["shell"] is False for process in self.processes))
        self.assertEqual(self.processes[0].inputs[0], multi_partition_script(self.plan))
        mkfs_commands = [
            process.argv for process in self.processes
            if any("mkfs." in argument for argument in process.argv)
        ]
        self.assertEqual(len(mkfs_commands), 2)
        self.assertIn("/usr/bin/mkfs.vfat", mkfs_commands[0])
        self.assertEqual(mkfs_commands[0][-1], "/dev/sdz1")
        self.assertIn("/usr/bin/mkfs.ntfs", mkfs_commands[1])
        self.assertEqual(mkfs_commands[1][-1], "/dev/sdz2")
        self.assertEqual(stages[-1], "Complete")

    def test_missing_tool_preflight_touches_nothing(self):
        runner = Mock()
        popen = Mock()
        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: None if name == "mkfs.ntfs" else f"/usr/bin/{name}",
            runner=runner, popen=popen,
        )
        with self.assertRaisesRegex(MissingFormatToolError, "mkfs.ntfs"):
            executor.execute_multi(self.device, self.plan)
        runner.assert_not_called()
        popen.assert_not_called()

    def test_changed_device_is_rejected_before_unmount(self):
        changed = test_device(serial="OTHER")
        runner = Mock()
        executor = MultiFormatExecutor(
            device_lookup=lambda _path: changed,
            which=lambda name: f"/usr/bin/{name}", runner=runner,
        )
        with self.assertRaises(DeviceChangedError):
            executor.execute_multi(self.device, self.plan)
        runner.assert_not_called()

    def test_wrong_partition_count_fails_without_formatting(self):
        processes = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part"},
                        {"path": "/dev/sdz2", "type": "part"},
                        {"path": "/dev/sdz3", "type": "part"},
                    ],
                }]}))
            return completed()

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen, sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(FormattingError, "more children"):
            executor.execute_multi(self.device, self.plan)
        self.assertFalse(any(
            any("mkfs." in argument for argument in process.argv)
            for process in processes
        ))

    def test_cancel_before_start_runs_no_commands(self):
        self.executor.cancel()
        with self.assertRaises(FormatCancelled):
            self.executor.execute_multi(self.device, self.plan)
        self.assertEqual(self.run_calls, [])
        self.assertEqual(self.processes, [])

    def test_unformatted_partition_is_created_but_not_formatted(self):
        device = test_device(partitions=())
        plan = create_multi_format_plan(device, "gpt", (
            PartitionSpec(
                PartitionRole.MICROSOFT_RESERVED, None, size_mib=16,
            ),
            PartitionSpec(PartitionRole.DATA, Filesystem.NTFS, "WINDOWS"),
        ))
        processes = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part"},
                        {"path": "/dev/sdz2", "type": "part"},
                    ],
                }]}))
            return completed()

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen, sleep=lambda _seconds: None,
        )
        self.assertEqual(
            executor.execute_multi(device, plan), ("/dev/sdz1", "/dev/sdz2"),
        )
        mkfs_commands = [
            process.argv for process in processes
            if any("mkfs." in argument for argument in process.argv)
        ]
        self.assertEqual(len(mkfs_commands), 1)
        self.assertEqual(mkfs_commands[0][-1], "/dev/sdz2")

    def test_explicit_layout_is_verified_before_filesystem_creation(self):
        plan = create_uefi_ntfs_format_plan(self.device, "gpt")
        processes = []

        def metadata(*, wrong_size=False):
            return json.dumps({"partitiontable": {
                "label": "gpt", "device": "/dev/sdz", "unit": "sectors",
                "sectorsize": 512,
                "partitions": [
                    {
                        "node": "/dev/sdz1", "start": plan.partitions[0].start_sector,
                        "size": (
                            1 if wrong_size else plan.partitions[0].sector_count
                        ),
                        "type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                        "name": "ISOpropyl data",
                    },
                    {
                        "node": "/dev/sdz2", "start": plan.partitions[1].start_sector,
                        "size": 2048,
                        "type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                        "name": "UEFI:NTFS", "attrs": "GUID:63",
                    },
                ],
            }})

        def run_case(*, wrong_size=False):
            processes.clear()

            def popen(argv, **kwargs):
                process = FakeProcess(argv, **kwargs)
                processes.append(process)
                return process

            def runner(argv, **_kwargs):
                if "--nodeps" in argv:
                    return completed(json.dumps({"blockdevices": [{
                        "path": "/dev/sdz", "type": "disk", "log-sec": 512,
                    }]}))
                if "lsblk" in argv[0]:
                    return completed(json.dumps({"blockdevices": [{
                        "path": "/dev/sdz", "type": "disk", "children": [
                            {"path": "/dev/sdz1", "type": "part"},
                            {"path": "/dev/sdz2", "type": "part"},
                        ],
                    }]}))
                if argv[:3] == [
                    "/usr/bin/pkexec", "/usr/bin/sfdisk", "--json",
                ]:
                    return completed(metadata(wrong_size=wrong_size))
                return completed()

            executor = MultiFormatExecutor(
                device_lookup=lambda _path: self.device,
                which=lambda name: f"/usr/bin/{name}",
                runner=runner, popen=popen, sleep=lambda _seconds: None,
            )
            return executor.execute_multi(self.device, plan)

        self.assertEqual(run_case(), ("/dev/sdz1", "/dev/sdz2"))
        self.assertEqual(len([
            process for process in processes
            if any("mkfs." in argument for argument in process.argv)
        ]), 1)
        with self.assertRaisesRegex(FormattingError, "geometry"):
            run_case(wrong_size=True)
        self.assertFalse(any(
            any("mkfs." in argument for argument in process.argv)
            for process in processes
        ))

    def test_wrong_logical_sector_size_stops_before_unmount_or_partitioning(self):
        plan = create_uefi_ntfs_format_plan(self.device, "gpt")
        run_calls = []
        popen = Mock()

        def runner(argv, **kwargs):
            run_calls.append((argv, kwargs))
            if "--nodeps" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "log-sec": 4096,
                }]}))
            return completed()

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", runner=runner, popen=popen,
        )
        with self.assertRaisesRegex(DeviceChangedError, "4096-byte"):
            executor.execute_multi(self.device, plan)
        self.assertEqual(len(run_calls), 1)
        self.assertIn("--nodeps", run_calls[0][0])
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
