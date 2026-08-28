# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import json
import os
import stat
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
    parse_partition_identities,
    parse_partitions,
    partition_command,
    partition_script,
    resolve_multi_tools,
    resolve_tools,
    restore_allocation_unit_sizes,
    restore_filesystem_geometry_supported,
    restore_filesystem_size_supported,
    validate_label,
    validate_explicit_partition_metadata,
    validate_multi_plan,
    validate_single_partition_metadata,
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


SUPPORTED_MKUDFFS_HELP = (
    b"mkudffs from udftools 2.3\n"
    b"Usage:\n"
    b"\tmkudffs [options] device [blocks-count]\n"
    b"\t--label=, -l       UDF label\n"
    b"\t--blocksize=, -b   Size of blocks in bytes (default: detect)\n"
)


class MkudffsHelpProcess:
    def __init__(
        self,
        argv,
        *,
        output=SUPPORTED_MKUDFFS_HELP,
        returncode=1,
        running=False,
        **kwargs,
    ):
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = io.BytesIO(output)
        self.returncode = None if running else returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode


def supported_mkudffs_popen(argv, **kwargs):
    return MkudffsHelpProcess(argv, **kwargs)


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def partition_lstat(path: str):
    number = int(path.rsplit("z", 1)[-1])
    return Mock(st_mode=stat.S_IFBLK, st_rdev=os.makedev(65, 144 + number))


def single_metadata_payload(
    plan: FormatPlan,
    *,
    sector_size: int = 512,
    partition: str = "/dev/sdz1",
    start: int = 2048,
    size: int | None = None,
    partition_type: str | None = None,
) -> str:
    total_sectors = plan.device_identity[1] // sector_size
    trailing_sectors = (
        1 + (128 * 128 + sector_size - 1) // sector_size
        if plan.partition_table is PartitionTable.GPT else 0
    )
    expected_size = total_sectors - start - trailing_sectors
    script_type = partition_script(plan).decode("ascii").split("type=", 1)[1].strip()
    table = {
        "label": "gpt" if plan.partition_table is PartitionTable.GPT else "dos",
        "device": plan.device_path,
        "unit": "sectors",
        "sectorsize": sector_size,
        "partitions": [{
            "node": partition,
            "start": start,
            "size": expected_size if size is None else size,
            "type": script_type if partition_type is None else partition_type,
        }],
    }
    if plan.partition_table is PartitionTable.GPT:
        table["lastlba"] = total_sectors - trailing_sectors - 1
    return json.dumps({"partitiontable": table})


class FormatPlanTests(unittest.TestCase):
    def test_supports_each_filesystem_and_partition_table(self):
        for filesystem in Filesystem:
            for table in PartitionTable:
                with self.subTest(filesystem=filesystem, table=table):
                    device = test_device(
                        size=128 * 1024 * 1024
                        if filesystem in {Filesystem.FAT12, Filesystem.FAT16}
                        else test_device().size,
                    )
                    plan = create_format_plan(device, filesystem, table, "USB")
                    self.assertEqual(plan.device_identity, device.identity)
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
        self.assertEqual(validate_label("fat12", "ELEVENCHARS"), "ELEVENCHARS")
        self.assertEqual(validate_label("fat16", "ELEVENCHARS"), "ELEVENCHARS")
        self.assertEqual(validate_label("fat32", "ELEVENCHARS"), "ELEVENCHARS")
        self.assertEqual(validate_label("exfat", "portable"), "portable")
        self.assertEqual(validate_label("ntfs", "Windows media"), "Windows media")
        self.assertEqual(validate_label("udf", "Portable media"), "Portable media")
        self.assertEqual(validate_label("udf", "x" * 30), "x" * 30)
        self.assertEqual(validate_label("udf", "é" * 15), "é" * 15)
        self.assertEqual(validate_label("ext2", "Linux media"), "Linux media")
        self.assertEqual(validate_label("ext3", "Linux media"), "Linux media")
        self.assertEqual(validate_label("ext4", "Linux media"), "Linux media")
        for filesystem, label in (
            ("fat12", "twelve-chars"), ("fat16", "BAD:LABEL"),
            ("fat32", "twelve-chars"), ("fat32", "BAD:LABEL"),
            ("exfat", "x" * 16), ("ntfs", "x" * 33),
            ("udf", "x" * 31), ("udf", "é" * 16), ("udf", "BAD:LABEL"),
            ("ext2", "0123456789abcdefg"), ("ext2", "bad/label"),
            ("ext3", "0123456789abcdefg"), ("ext3", "bad/label"),
            ("ext4", "0123456789abcdefg"), ("ext4", "bad/label"),
        ):
            with self.subTest(filesystem=filesystem, label=label):
                with self.assertRaises(FormatValidationError):
                    validate_label(filesystem, label)

        with self.assertRaisesRegex(FormatValidationError, "invalid Unicode"):
            validate_label("udf", "\ud800")

    def test_fat_labels_require_safe_ascii_and_reject_no_name_semantics(self):
        for filesystem in ("fat12", "fat16", "fat32"):
            with self.subTest(filesystem=filesystem):
                self.assertEqual(validate_label(filesystem, "ABCDEFGHIJK"), "ABCDEFGHIJK")
                with self.assertRaisesRegex(FormatValidationError, "11 ASCII"):
                    validate_label(filesystem, "ABCDEFGHIJKL")
                with self.assertRaisesRegex(FormatValidationError, "only ASCII"):
                    validate_label(filesystem, "é" * 5)
                for sentinel in ("NO NAME", "no name", "No Name"):
                    with self.assertRaisesRegex(FormatValidationError, "means no label"):
                        validate_label(filesystem, sentinel)

    def test_udf_labels_reject_supplementary_unicode_at_preflight(self):
        self.assertEqual(validate_label("udf", "Résumé"), "Résumé")
        with self.assertRaisesRegex(FormatValidationError, "Basic Multilingual Plane"):
            validate_label("udf", "USB😀")

    def test_fat_and_udf_size_bounds_fail_closed(self):
        for filesystem, size, message in (
            ("fat12", 256 * 1024 * 1024 + 1, "256 MiB"),
            ("fat16", 128 * 1024 * 1024 - 1, "128 MiB"),
            ("fat16", 4 * 1024**3 + 1, "4 GiB"),
            ("fat32", 2 * 1024**4 + 1, "2 TiB"),
            ("udf", 2 * 1024**4 + 1, "2 TiB"),
        ):
            with self.subTest(filesystem=filesystem, size=size):
                with self.assertRaisesRegex(FormatValidationError, message):
                    create_format_plan(
                        test_device(size=size), filesystem, "gpt", "USB",
                    )

        self.assertEqual(
            create_format_plan(
                test_device(size=256 * 1024 * 1024), "fat12", "mbr",
            ).filesystem,
            Filesystem.FAT12,
        )
        self.assertEqual(
            create_format_plan(
                test_device(size=4 * 1024**3), "fat16", "mbr",
            ).filesystem,
            Filesystem.FAT16,
        )
        self.assertEqual(
            create_format_plan(
                test_device(size=2 * 1024**4), "udf", "gpt",
            ).filesystem,
            Filesystem.UDF,
        )
        self.assertEqual(
            create_format_plan(
                test_device(size=2 * 1024**4), "fat32", "gpt",
            ).filesystem,
            Filesystem.FAT32,
        )

    def test_restore_size_support_helper_shares_exact_plan_boundaries(self):
        cases = (
            ("fat12", 256 * 1024**2, True),
            ("fat12", 256 * 1024**2 + 1, False),
            ("fat16", 128 * 1024**2, True),
            ("fat16", 128 * 1024**2 - 1, False),
            ("fat16", 4 * 1024**3, True),
            ("fat16", 4 * 1024**3 + 1, False),
            ("fat32", 2 * 1024**4, True),
            ("fat32", 2 * 1024**4 + 1, False),
            ("udf", 2 * 1024**4, True),
            ("udf", 2 * 1024**4 + 1, False),
            ("fat32", test_device().size, True),
        )
        for filesystem, size, expected in cases:
            with self.subTest(filesystem=filesystem, size=size):
                self.assertIs(
                    restore_filesystem_size_supported(filesystem, size), expected,
                )
        for filesystem, size in (("bogus", 1), ("fat12", 0), ([], 128 * 1024**2)):
            with self.subTest(filesystem=filesystem, size=size):
                self.assertFalse(restore_filesystem_size_supported(filesystem, size))

    def test_allocation_unit_validation_preserves_formatter_defaults(self):
        default_plan = create_format_plan(test_device(), "ext4", "gpt", "USB")
        self.assertIsNone(default_plan.allocation_unit_size)

        for filesystem, size, allocation_unit in (
            ("fat12", 256 * 1024**2, 65536),
            ("fat16", 128 * 1024**2, 4096),
            ("fat32", test_device().size, 32768),
            ("exfat", test_device().size, 32 * 1024**2),
            ("ntfs", test_device().size, 2 * 1024**2),
            ("ext2", test_device().size, 1024),
            ("ext3", test_device().size, 2048),
            ("ext4", test_device().size, 4096),
        ):
            with self.subTest(filesystem=filesystem):
                plan = create_format_plan(
                    test_device(size=size), filesystem, "gpt", "USB",
                    allocation_unit,
                )
                self.assertEqual(plan.allocation_unit_size, allocation_unit)

        for filesystem, allocation_unit in (
            ("udf", 2048),
            ("fat32", True),
            ("fat32", 0),
            ("fat32", 1000),
            ("fat32", 131072),
            ("exfat", 64 * 1024**2),
            ("ntfs", 4 * 1024**2),
            ("ext4", 8192),
        ):
            with self.subTest(filesystem=filesystem, unit=allocation_unit):
                with self.assertRaises(FormatValidationError):
                    create_format_plan(
                        test_device(), filesystem, "gpt", "USB",
                        allocation_unit,
                    )

    def test_allocation_unit_helper_binds_exact_partition_capacity_and_sector(self):
        mib = 1024**2
        gib = 1024**3
        self.assertEqual(
            restore_allocation_unit_sizes("fat12", 256 * mib, 512),
            (65536,),
        )
        self.assertEqual(
            restore_allocation_unit_sizes("fat16", 128 * mib, 512),
            (2048, 4096, 8192, 16384),
        )
        self.assertEqual(
            restore_allocation_unit_sizes("fat16", 4 * gib, 512),
            (65536,),
        )
        for sector_size in (512, 4096):
            with self.subTest(filesystem="fat32", sector_size=sector_size):
                self.assertEqual(
                    restore_allocation_unit_sizes(
                        "fat32", 2 * 1024**4, sector_size,
                    ),
                    (8192, 16384, 32768, 65536),
                )
                self.assertEqual(
                    restore_allocation_unit_sizes(
                        "fat32", 2 * 1024**4 + sector_size, sector_size,
                    ),
                    (),
                )
        self.assertEqual(
            restore_allocation_unit_sizes("ext4", test_device().size, 4096),
            (4096,),
        )
        self.assertNotIn(
            4096,
            restore_allocation_unit_sizes("ntfs", 32 * 1024**4, 512, "gpt"),
        )
        self.assertIn(
            8192,
            restore_allocation_unit_sizes("ntfs", 32 * 1024**4, 512, "gpt"),
        )
        self.assertEqual(restore_allocation_unit_sizes("udf", 16 * mib, 512), ())
        for args in (
            ("bogus", 16 * mib, 512),
            ("fat32", 16 * mib, 1000),
            ("fat32", 0, 512),
            ([], 16 * mib, 512),
        ):
            with self.subTest(args=args):
                self.assertEqual(restore_allocation_unit_sizes(*args), ())

    def test_automatic_restore_geometry_rejects_known_formatter_dead_ends(self):
        mib = 1024**2
        tib = 1024**4
        pib = 1024**5
        self.assertTrue(
            restore_filesystem_geometry_supported("fat32", 64 * mib, 512)
        )
        self.assertFalse(
            restore_filesystem_geometry_supported("fat32", 64 * mib, 4096)
        )
        self.assertFalse(
            restore_filesystem_geometry_supported("fat12", 128 * mib, 1024)
        )
        self.assertFalse(
            restore_filesystem_geometry_supported("ext3", 20 * tib, 512, "gpt")
        )
        self.assertTrue(
            restore_filesystem_geometry_supported("ext4", 20 * tib, 512, "gpt")
        )
        self.assertFalse(
            restore_filesystem_geometry_supported("ext4", 8 * 1024**3, 8192)
        )
        self.assertTrue(
            restore_filesystem_geometry_supported("ext4", 8 * 1024**3, 0)
        )
        mbr_limit = (0xFFFFFFFF + 2048) * 512
        self.assertTrue(
            restore_filesystem_geometry_supported(
                "ext4", mbr_limit, 512, "mbr",
            )
        )
        self.assertFalse(
            restore_filesystem_geometry_supported(
                "ext4", mbr_limit + 512, 512, "mbr",
            )
        )
        self.assertTrue(
            restore_filesystem_geometry_supported(
                "ext4", mbr_limit + 512, 512, "gpt",
            )
        )
        for filesystem, size, explicit in (
            ("exfat", 600 * tib, 256 * 1024),
            ("ntfs", 5 * pib, 2 * mib),
            ("ext4", 40 * pib, 2048),
        ):
            with self.subTest(filesystem=filesystem, size=size):
                self.assertFalse(
                    restore_filesystem_geometry_supported(
                        filesystem, size, 512, "gpt",
                    )
                )
                self.assertIn(
                    explicit,
                    restore_allocation_unit_sizes(
                        filesystem, size, 512, "gpt",
                    ),
                )
        for filesystem in ("ext2", "ext3"):
            with self.subTest(filesystem=filesystem):
                self.assertEqual(
                    restore_allocation_unit_sizes(
                        filesystem, 10 * tib, 512, "gpt",
                    ),
                    (4096,),
                )
                self.assertEqual(
                    restore_allocation_unit_sizes(
                        filesystem, 20 * tib, 512, "gpt",
                    ),
                    (),
                )

    def test_partition_scripts_have_explicit_table_alignment_and_type(self):
        fat_mbr = create_format_plan(test_device(), "fat32", "mbr")
        self.assertEqual(
            partition_script(fat_mbr),
            b"label: dos\nunit: sectors\n\nstart=2048, type=c\n",
        )
        for filesystem in ("ext2", "ext3", "ext4"):
            with self.subTest(filesystem=filesystem):
                ext_mbr = create_format_plan(test_device(), filesystem, "mbr")
                ext_gpt = create_format_plan(test_device(), filesystem, "gpt")
                self.assertIn(b"type=83", partition_script(ext_mbr))
                self.assertIn(b"label: gpt", partition_script(ext_gpt))
                self.assertIn(
                    b"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                    partition_script(ext_gpt),
                )
        for filesystem, expected_type in (("fat12", b"type=1"), ("fat16", b"type=e")):
            with self.subTest(filesystem=filesystem):
                plan = create_format_plan(
                    test_device(size=128 * 1024 * 1024), filesystem, "mbr",
                )
                self.assertIn(expected_type, partition_script(plan))
        udf_mbr = create_format_plan(test_device(), "udf", "mbr")
        udf_gpt = create_format_plan(test_device(), "udf", "gpt")
        self.assertIn(b"type=7", partition_script(udf_mbr))
        self.assertIn(
            b"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
            partition_script(udf_gpt),
        )

    def test_single_partition_metadata_binds_exact_full_capacity_geometry(self):
        cases = (
            create_format_plan(test_device(), "udf", "mbr", "USB"),
            create_format_plan(test_device(), "udf", "gpt", "USB"),
        )
        for plan in cases:
            with self.subTest(table=plan.partition_table):
                payload = single_metadata_payload(plan)
                self.assertEqual(
                    validate_single_partition_metadata(
                        plan, payload, "/dev/sdz1", 512,
                    ),
                    512,
                )

    def test_single_partition_metadata_rejects_each_geometry_or_identity_change(self):
        plan = create_format_plan(test_device(), "udf", "gpt", "USB")
        cases = (
            (dict(partition="/dev/sdy1"), "safe partition path"),
            (dict(partition="/dev/sdz2"), "path, start, size, or type"),
            (dict(start=4096), "path, start, size, or type"),
            (dict(size=1), "path, start, size, or type"),
            (dict(partition_type="DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF"),
             "path, start, size, or type"),
        )
        for changes, message in cases:
            with self.subTest(changes=changes):
                payload_changes = dict(changes)
                partition = payload_changes.pop("partition", "/dev/sdz1")
                payload = single_metadata_payload(plan, **payload_changes)
                with self.assertRaisesRegex((FormatValidationError, FormattingError), message):
                    validate_single_partition_metadata(plan, payload, partition, 512)

        with self.assertRaisesRegex(DeviceChangedError, "logical sector size"):
            validate_single_partition_metadata(
                plan, single_metadata_payload(plan, sector_size=4096),
                "/dev/sdz1", 512,
            )

    def test_commands_are_argv_and_labels_remain_single_arguments(self):
        plan = create_format_plan(test_device(), "fat32", "mbr", "MY USB")
        self.assertEqual(partition_command(plan, TOOLS)[0:2], [TOOLS.pkexec, TOOLS.sfdisk])
        self.assertEqual(partition_command(plan, TOOLS)[2], "--lock=nonblock")
        self.assertEqual(
            format_command(plan, TOOLS, "/dev/sdz1"),
            [TOOLS.pkexec, TOOLS.mkfs, "-F", "32", "-n", "MY USB", "/dev/sdz1"],
        )
        with self.assertRaises(FormatValidationError):
            format_command(plan, TOOLS, "--help")
        with self.assertRaises(FormatValidationError):
            format_command(plan, TOOLS, "/dev/sdy1")

    def test_fat12_fat16_and_udf_commands_are_exact(self):
        for filesystem, bits in (("fat12", "12"), ("fat16", "16")):
            with self.subTest(filesystem=filesystem):
                plan = create_format_plan(
                    test_device(size=128 * 1024 * 1024),
                    filesystem, "mbr", "MY USB",
                )
                self.assertEqual(
                    format_command(plan, TOOLS, "/dev/sdz1"),
                    [
                        TOOLS.pkexec, TOOLS.mkfs, "-F", bits, "-n", "MY USB",
                        "/dev/sdz1",
                    ],
                )
        udf_tools = FormatTools(
            TOOLS.pkexec, TOOLS.udisksctl, TOOLS.sfdisk, TOOLS.partprobe,
            TOOLS.udevadm, TOOLS.lsblk, "/usr/sbin/mkudffs",
        )
        udf = create_format_plan(test_device(), "udf", "gpt", "MY USB")
        self.assertEqual(
            format_command(udf, udf_tools, "/dev/sdz1"),
            [
                TOOLS.pkexec, "/usr/sbin/mkudffs", "--utf8",
                "--media-type=hd", "--udfrev=0x0201", "--label=MY USB",
                "/dev/sdz1",
            ],
        )
        empty = create_format_plan(test_device(), "udf", "gpt")
        self.assertIn(
            "--label=", format_command(empty, udf_tools, "/dev/sdz1"),
        )

    def test_explicit_allocation_unit_commands_are_exact_and_geometry_bound(self):
        cases = (
            (
                "fat16", 128 * 1024**2, 4096, "/usr/sbin/mkfs.vfat",
                ["-F", "16", "-s", "8", "-n", "USB"],
            ),
            (
                "exfat", test_device().size, 65536, "/usr/sbin/mkfs.exfat",
                ["-c", "65536", "-L", "USB"],
            ),
            (
                "ntfs", test_device().size, 65536, "/usr/sbin/mkfs.ntfs",
                ["-f", "-c", "65536", "-L", "USB"],
            ),
            (
                "ext4", test_device().size, 2048, "/usr/sbin/mkfs.ext4",
                ["-F", "-b", "2048", "-L", "USB"],
            ),
        )
        for filesystem, size, unit, mkfs, expected_options in cases:
            with self.subTest(filesystem=filesystem):
                plan = create_format_plan(
                    test_device(size=size), filesystem, "mbr", "USB", unit,
                )
                tools = FormatTools(
                    TOOLS.pkexec, TOOLS.udisksctl, TOOLS.sfdisk,
                    TOOLS.partprobe, TOOLS.udevadm, TOOLS.lsblk, mkfs,
                )
                self.assertEqual(
                    format_command(plan, tools, "/dev/sdz1", 512),
                    [TOOLS.pkexec, mkfs, *expected_options, "/dev/sdz1"],
                )
                with self.assertRaisesRegex(
                    FormatValidationError, "bound logical sector",
                ):
                    format_command(plan, tools, "/dev/sdz1")

        incompatible = create_format_plan(
            test_device(size=128 * 1024**2), "fat16", "mbr", "USB", 32768,
        )
        with self.assertRaisesRegex(FormatValidationError, "incompatible"):
            format_command(incompatible, TOOLS, "/dev/sdz1", 512)

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

    def test_mkfs_flags_and_trusted_tools_for_each_non_fat_filesystem(self):
        for filesystem, tool, expected in (
            ("exfat", "/usr/sbin/mkfs.exfat", ["-L", "USB"]),
            ("ntfs", "/usr/sbin/mkfs.ntfs", ["-f", "-L", "USB"]),
            ("ext2", "/usr/sbin/mkfs.ext2", ["-F", "-L", "USB"]),
            ("ext3", "/usr/sbin/mkfs.ext3", ["-F", "-L", "USB"]),
            ("ext4", "/usr/sbin/mkfs.ext4", ["-F", "-L", "USB"]),
        ):
            tools = FormatTools(
                TOOLS.pkexec, TOOLS.udisksctl, TOOLS.sfdisk, TOOLS.partprobe,
                TOOLS.udevadm, TOOLS.lsblk, tool,
            )
            plan = create_format_plan(test_device(), filesystem, "gpt", "USB")
            command = format_command(plan, tools, "/dev/sdz1")
            self.assertEqual(command[1], tool)
            for argument in expected:
                self.assertIn(argument, command)

    def test_ext2_and_ext3_resolve_their_exact_mkfs_tools(self):
        for filesystem in ("ext2", "ext3"):
            with self.subTest(filesystem=filesystem):
                requested = []

                def finder(name):
                    requested.append(name)
                    return f"/usr/bin/{name}"

                plan = create_format_plan(test_device(), filesystem, "mbr", "LINUX")
                tools = resolve_tools(plan, finder)
                self.assertEqual(tools.mkfs, f"/usr/bin/mkfs.{filesystem}")
                self.assertIn(f"mkfs.{filesystem}", requested)
                self.assertNotIn("mkfs.ext4", requested)

    def test_new_restore_formats_resolve_exact_trusted_formatters(self):
        for filesystem, size, expected in (
            ("fat12", 128 * 1024 * 1024, "mkfs.vfat"),
            ("fat16", 128 * 1024 * 1024, "mkfs.vfat"),
            ("udf", test_device().size, "mkudffs"),
        ):
            with self.subTest(filesystem=filesystem):
                requested = []

                def finder(name):
                    requested.append(name)
                    return f"/usr/sbin/{name}"

                plan = create_format_plan(
                    test_device(size=size), filesystem, "gpt", "USB",
                )
                self.assertEqual(resolve_tools(plan, finder).mkfs, f"/usr/sbin/{expected}")
                self.assertIn(expected, requested)

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
                {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
            ]},
        ]})
        self.assertEqual(parse_partitions(payload, "/dev/sdz"), ("/dev/sdz1",))

    def test_partition_identity_parser_requires_direct_kernel_children(self):
        payload = json.dumps({"blockdevices": [{
            "path": "/dev/sdz", "type": "disk", "children": [
                {"path": "/dev/sdz2", "type": "part", "pkname": "sdz", "maj:min": "65:146"},
                {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
            ],
        }]})
        self.assertEqual(
            parse_partition_identities(payload, "/dev/sdz"),
            (("/dev/sdz1", "65:145"), ("/dev/sdz2", "65:146")),
        )
        with self.assertRaisesRegex(FormattingError, "unsafe partition identity"):
            parse_partition_identities(
                payload.replace('"pkname": "sdz"', '"pkname": "sdy"'),
                "/dev/sdz",
            )


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

    def test_restore_only_filesystems_are_rejected_from_multi_layouts(self):
        for filesystem in (Filesystem.FAT12, Filesystem.FAT16, Filesystem.UDF):
            with self.subTest(filesystem=filesystem):
                with self.assertRaisesRegex(
                    FormatValidationError, "single-partition restore",
                ):
                    create_multi_format_plan(test_device(), "gpt", (
                        PartitionSpec(PartitionRole.DATA, filesystem, "DATA"),
                    ))

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
        self.assertEqual(multi_partition_command(plan, tools)[2], "--lock=nonblock")
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
            if "--json" in argv and any(
                argument.endswith("/sfdisk") for argument in argv
            ):
                return completed(single_metadata_payload(self.plan))
            if "lsblk" in argv[0] and "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                    ],
                }]}))
            return completed()

        self.executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            popen=popen, runner=runner, lstat_func=partition_lstat,
            sleep=lambda _seconds: None,
        )

    def test_complete_flow_unmounts_partitions_and_uses_no_shell(self):
        stages = []
        partition = self.executor.execute(self.device, self.plan, stages.append)
        self.assertEqual(partition, "/dev/sdz1")
        self.assertEqual(
            next(
                argv for argv, _kwargs in self.run_calls
                if argv[0].endswith("/udisksctl")
            ),
            ["/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sdz1"],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in self.run_calls))
        self.assertTrue(all(call[1]["timeout"] > 0 for call in self.run_calls))
        hierarchy_queries = [
            argv for argv, _kwargs in self.run_calls
            if argv[0].endswith("/lsblk")
            and any(value in argv for value in (
                "PATH,TYPE", "PATH,TYPE,PKNAME,MAJ:MIN",
            ))
        ]
        self.assertTrue(hierarchy_queries)
        self.assertTrue(all("--tree" in argv for argv in hierarchy_queries))
        self.assertTrue(all(process.kwargs["shell"] is False for process in self.processes))
        self.assertEqual(self.processes[0].inputs[0], partition_script(self.plan))
        self.assertEqual(self.processes[-2].argv[-1], "/dev/sdz1")
        self.assertEqual(
            self.processes[-2].argv[:9],
            [
                "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive", "--nonblock",
                "--conflict-exit-code", "75", "--no-fork", "/dev/sdz",
                "/usr/bin/mkfs.vfat",
            ],
        )
        self.assertEqual(stages[-1], "Complete")

    def test_ext2_and_ext3_mkfs_are_whole_device_locked(self):
        for filesystem in ("ext2", "ext3"):
            with self.subTest(filesystem=filesystem):
                before = len(self.processes)
                plan = create_format_plan(
                    self.device, filesystem, "gpt", "LINUX",
                )
                self.plan = plan
                self.executor.execute(self.device, plan)
                spawned = self.processes[before:]
                mkfs = next(
                    process.argv for process in spawned
                    if any(
                        argument.endswith(f"/mkfs.{filesystem}")
                        for argument in process.argv
                    )
                )
                self.assertEqual(mkfs[1], "/usr/bin/flock")
                self.assertEqual(mkfs[7], self.device.path)
                self.assertEqual(mkfs[8], f"/usr/bin/mkfs.{filesystem}")
                self.assertEqual(mkfs[-1], "/dev/sdz1")

    def test_new_restore_formats_bind_sector_geometry_and_lock_mkfs(self):
        for filesystem, size, formatter in (
            ("fat12", 128 * 1024 * 1024, "mkfs.vfat"),
            ("fat16", 128 * 1024 * 1024, "mkfs.vfat"),
            ("udf", self.device.size, "mkudffs"),
        ):
            with self.subTest(filesystem=filesystem):
                device = test_device(size=size)
                plan = create_format_plan(device, filesystem, "gpt", "USB")
                processes = []
                geometry_probes = []

                def popen(argv, **kwargs):
                    process = FakeProcess(argv, **kwargs)
                    processes.append(process)
                    return process

                def runner(argv, **kwargs):
                    if "--json" in argv and any(
                        argument.endswith("/sfdisk") for argument in argv
                    ):
                        return completed(single_metadata_payload(plan))
                    if "lsblk" in argv[0] and "PATH,TYPE,LOG-SEC" in argv:
                        geometry_probes.append(argv)
                        return completed(json.dumps({"blockdevices": [{
                            "path": device.path, "type": "disk", "log-sec": 512,
                        }]}))
                    if "lsblk" in argv[0]:
                        return completed(json.dumps({"blockdevices": [{
                            "path": device.path, "type": "disk", "children": [{
                                "path": "/dev/sdz1", "type": "part",
                                "pkname": device.path, "maj:min": "65:145",
                            }],
                        }]}))
                    return completed()

                executor = FormatExecutor(
                    device_lookup=lambda _path: device,
                    which=lambda name: f"/usr/bin/{name}",
                    popen=popen, preflight_popen=supported_mkudffs_popen,
                    runner=runner, lstat_func=partition_lstat,
                    sleep=lambda _seconds: None,
                )
                self.assertEqual(executor.execute(device, plan), "/dev/sdz1")
                self.assertEqual(len(geometry_probes), 4)
                mkfs = next(
                    process.argv for process in processes
                    if any(argument.endswith(f"/{formatter}") for argument in process.argv)
                )
                self.assertEqual(mkfs[:8], [
                    "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive", "--nonblock",
                    "--conflict-exit-code", "75", "--no-fork", device.path,
                ])
                self.assertEqual(mkfs[8], f"/usr/bin/{formatter}")

    def test_explicit_allocation_units_revalidate_geometry_and_reach_mkfs(self):
        for filesystem, size, unit, formatter, expected_tail in (
            (
                "fat16", 128 * 1024**2, 4096, "mkfs.vfat",
                ["-F", "16", "-s", "8", "-n", "USB", "/dev/sdz1"],
            ),
            (
                "fat32", self.device.size, 32768, "mkfs.vfat",
                ["-F", "32", "-s", "64", "-n", "USB", "/dev/sdz1"],
            ),
            (
                "exfat", self.device.size, 65536, "mkfs.exfat",
                ["-c", "65536", "-L", "USB", "/dev/sdz1"],
            ),
            (
                "ntfs", self.device.size, 65536, "mkfs.ntfs",
                ["-f", "-c", "65536", "-L", "USB", "/dev/sdz1"],
            ),
            (
                "ext4", self.device.size, 2048, "mkfs.ext4",
                ["-F", "-b", "2048", "-L", "USB", "/dev/sdz1"],
            ),
        ):
            with self.subTest(filesystem=filesystem):
                device = test_device(size=size)
                plan = create_format_plan(
                    device, filesystem, "mbr", "USB", unit,
                )
                processes = []
                geometry_probes = []

                def popen(argv, **kwargs):
                    process = FakeProcess(argv, **kwargs)
                    processes.append(process)
                    return process

                def runner(argv, **_kwargs):
                    if "--json" in argv and any(
                        argument.endswith("/sfdisk") for argument in argv
                    ):
                        return completed(single_metadata_payload(plan))
                    if "lsblk" in argv[0] and "PATH,TYPE,LOG-SEC" in argv:
                        geometry_probes.append(argv)
                        return completed(json.dumps({"blockdevices": [{
                            "path": device.path, "type": "disk", "log-sec": 512,
                        }]}))
                    if "lsblk" in argv[0]:
                        return completed(json.dumps({"blockdevices": [{
                            "path": device.path, "type": "disk", "children": [{
                                "path": "/dev/sdz1", "type": "part",
                                "pkname": device.path, "maj:min": "65:145",
                            }],
                        }]}))
                    return completed()

                executor = FormatExecutor(
                    device_lookup=lambda _path: device,
                    which=lambda name: f"/usr/bin/{name}",
                    popen=popen, runner=runner, lstat_func=partition_lstat,
                    sleep=lambda _seconds: None,
                )
                self.assertEqual(executor.execute(device, plan), "/dev/sdz1")
                self.assertEqual(len(geometry_probes), 4)
                mkfs = next(
                    process.argv for process in processes
                    if any(argument.endswith(f"/{formatter}") for argument in process.argv)
                )
                self.assertEqual(mkfs[8], f"/usr/bin/{formatter}")
                self.assertEqual(mkfs[9:], expected_tail)

    def test_incompatible_allocation_unit_stops_before_unmount_or_spawn(self):
        device = test_device(size=128 * 1024**2)
        plan = create_format_plan(
            device, "fat16", "mbr", "USB", 32768,
        )
        calls = []
        popen = Mock()

        def runner(argv, **_kwargs):
            calls.append(argv)
            return completed(json.dumps({"blockdevices": [{
                "path": device.path, "type": "disk", "log-sec": 512,
            }]}))

        executor = FormatExecutor(
            device_lookup=lambda _path: device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen,
        )
        with self.assertRaisesRegex(FormatValidationError, "incompatible"):
            executor.execute(device, plan)
        self.assertEqual(len(calls), 1)
        self.assertIn("PATH,TYPE,LOG-SEC", calls[0])
        popen.assert_not_called()

    def test_incompatible_automatic_geometry_stops_before_unmount_or_spawn(self):
        for filesystem, size, sector_size in (
            ("fat32", 64 * 1024**2, 4096),
            ("ext2", 20 * 1024**4, 512),
            ("ext3", 20 * 1024**4, 512),
        ):
            with self.subTest(filesystem=filesystem):
                device = test_device(size=size)
                table = "gpt" if filesystem in {"ext2", "ext3"} else "mbr"
                plan = create_format_plan(device, filesystem, table, "USB")
                calls = []
                popen = Mock()

                def runner(argv, **_kwargs):
                    calls.append(argv)
                    return completed(json.dumps({"blockdevices": [{
                        "path": device.path,
                        "type": "disk",
                        "log-sec": sector_size,
                    }]}))

                executor = FormatExecutor(
                    device_lookup=lambda _path: device,
                    which=lambda name: f"/usr/bin/{name}",
                    runner=runner,
                    popen=popen,
                )
                with self.assertRaisesRegex(
                    FormatValidationError, "formatter defaults are incompatible",
                ):
                    executor.execute(device, plan)

                self.assertEqual(len(calls), 1)
                self.assertIn("PATH,TYPE,LOG-SEC", calls[0])
                popen.assert_not_called()

    def test_restore_geometry_failure_occurs_before_unmount_or_spawn(self):
        for filesystem, size, sector_size, error_type, message in (
            (
                "fat12", 128 * 1024 * 1024, 8192,
                FormatValidationError, "512- or 4096-byte",
            ),
            (
                "udf", self.device.size, 8192,
                FormatValidationError, "512 through 4096",
            ),
            (
                "fat32", self.device.size, 8192,
                FormatValidationError, "512 through 4096",
            ),
            (
                "exfat", self.device.size, 8192,
                FormatValidationError, "512 through 4096",
            ),
            (
                "ntfs", self.device.size, 8192,
                FormatValidationError, "512 through 4096",
            ),
            (
                "ext4", self.device.size, 8192,
                FormatValidationError, "512 through 4096",
            ),
            (
                "ext4", 3 * 1024**4, 512,
                FormatValidationError, "MBR cannot represent",
            ),
            (
                "udf", self.device.size, 1000,
                FormattingError, "invalid logical sector size",
            ),
        ):
            with self.subTest(filesystem=filesystem):
                device = test_device(size=size)
                plan = create_format_plan(device, filesystem, "mbr", "USB")
                calls = []

                def runner(argv, **_kwargs):
                    calls.append(argv)
                    return completed(json.dumps({"blockdevices": [{
                        "path": device.path, "type": "disk", "log-sec": sector_size,
                    }]}))

                popen = Mock()
                executor = FormatExecutor(
                    device_lookup=lambda _path: device,
                    which=lambda name: f"/usr/bin/{name}",
                    runner=runner, popen=popen,
                    preflight_popen=supported_mkudffs_popen,
                )
                with self.assertRaisesRegex(error_type, message):
                    executor.execute(device, plan)
                self.assertEqual(len(calls), 1)
                self.assertIn("PATH,TYPE,LOG-SEC", calls[0])
                popen.assert_not_called()

    def test_auto_restore_accepts_supported_logical_sector_boundaries(self):
        for filesystem, size in (
            ("fat12", 128 * 1024**2),
            ("fat16", 128 * 1024**2),
            ("fat32", self.device.size),
            ("exfat", self.device.size),
            ("ntfs", self.device.size),
            ("ext2", self.device.size),
            ("ext3", self.device.size),
            ("ext4", self.device.size),
            ("udf", self.device.size),
        ):
            device = test_device(size=size)
            plan = create_format_plan(device, filesystem, "gpt", "USB")
            tools = resolve_tools(plan, lambda name: f"/usr/bin/{name}")
            for sector_size in (512, 4096):
                with self.subTest(filesystem=filesystem, sector_size=sector_size):
                    executor = FormatExecutor(
                        runner=lambda _argv, **_kwargs: completed(json.dumps({
                            "blockdevices": [{
                                "path": device.path, "type": "disk",
                                "log-sec": sector_size,
                            }],
                        })),
                    )
                    self.assertEqual(
                        executor._assert_restore_filesystem_geometry(plan, tools),
                        sector_size,
                    )

    def test_changed_restore_geometry_is_rejected_before_partitioning(self):
        device = test_device(size=128 * 1024 * 1024)
        plan = create_format_plan(device, "fat16", "gpt", "USB")
        sectors = iter((512, 4096))
        popen = Mock()

        def runner(argv, **_kwargs):
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": device.path, "type": "disk", "log-sec": next(sectors),
                }]}))
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: device,
            which=lambda name: f"/usr/bin/{name}", runner=runner, popen=popen,
        )
        with self.assertRaisesRegex(DeviceChangedError, "logical sector size changed"):
            executor.execute(device, plan)
        popen.assert_not_called()

    def test_preflight_missing_tool_never_unmounts_or_spawns(self):
        executor = FormatExecutor(
            device_lookup=lambda _path: self.device, which=lambda _name: None,
            popen=Mock(), runner=Mock(),
        )
        with self.assertRaises(MissingFormatToolError):
            executor.execute(self.device, self.plan)
        executor._popen.assert_not_called()
        executor._runner.assert_not_called()

    def test_missing_flock_preflight_never_unmounts_or_spawns(self):
        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: None if name == "flock" else f"/usr/bin/{name}",
            popen=Mock(), runner=Mock(),
        )
        with self.assertRaisesRegex(MissingFormatToolError, "flock"):
            executor.execute(self.device, self.plan)
        executor._popen.assert_not_called()
        executor._runner.assert_not_called()

    def test_udf_rejects_old_or_malformed_mkudffs_before_device_access(self):
        plan = create_format_plan(self.device, "udf", "gpt", "USB")
        cases = (
            (
                b"mkudffs from udftools 1.0\n--label=, -l\n",
                "1.1 or newer",
            ),
            (
                b"mkudffs from udftools current\n--label=, -l\n",
                "Could not verify",
            ),
            (
                b"mkudffs from udftools 2.3\nUsage:\n",
                "--label support",
            ),
        )
        for output, message in cases:
            with self.subTest(output=output):
                identity_lookup = Mock()
                runner = Mock()
                destructive_popen = Mock()
                preflight_calls = []

                def preflight_popen(argv, **kwargs):
                    preflight_calls.append((argv, kwargs))
                    return MkudffsHelpProcess(argv, output=output, **kwargs)

                executor = FormatExecutor(
                    device_lookup=identity_lookup,
                    which=lambda name: f"/usr/bin/{name}",
                    popen=destructive_popen,
                    preflight_popen=preflight_popen,
                    runner=runner,
                )
                with self.assertRaisesRegex(MissingFormatToolError, message):
                    executor.execute(self.device, plan)
                self.assertEqual(len(preflight_calls), 1)
                identity_lookup.assert_not_called()
                runner.assert_not_called()
                destructive_popen.assert_not_called()

    def test_udf_mkudffs_preflight_accepts_minimum_and_current_exact_argv_first(self):
        plan = create_format_plan(self.device, "udf", "gpt", "USB")
        for version in (b"1.1", b"2.3"):
            with self.subTest(version=version):
                events = []
                calls = []
                output = (
                    b"mkudffs from udftools " + version
                    + b"\nUsage:\n--label=, -l\n"
                )

                def preflight_popen(argv, **kwargs):
                    events.append("mkudffs preflight")
                    calls.append((argv, kwargs))
                    return MkudffsHelpProcess(argv, output=output, **kwargs)

                def lookup(_path):
                    events.append("identity lookup")
                    return None

                executor = FormatExecutor(
                    device_lookup=lookup,
                    which=lambda name: f"/usr/bin/{name}",
                    popen=Mock(), runner=Mock(),
                    preflight_popen=preflight_popen,
                )
                with self.assertRaisesRegex(DeviceChangedError, "no longer connected"):
                    executor.execute(self.device, plan)
                self.assertEqual(events, ["mkudffs preflight", "identity lookup"])
                self.assertEqual(calls[0][0], ["/usr/bin/mkudffs", "--help"])
                self.assertEqual(calls[0][1], {
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.STDOUT,
                    "shell": False,
                })
                executor._runner.assert_not_called()
                executor._popen.assert_not_called()

    def test_udf_mkudffs_preflight_rejects_untrusted_formatter_path(self):
        plan = create_format_plan(self.device, "udf", "gpt", "USB")
        identity_lookup = Mock()
        preflight_popen = Mock()
        executor = FormatExecutor(
            device_lookup=identity_lookup,
            which=lambda name: (
                "/tmp/mkudffs" if name == "mkudffs" else f"/usr/bin/{name}"
            ),
            popen=Mock(), runner=Mock(), preflight_popen=preflight_popen,
        )
        with self.assertRaisesRegex(MissingFormatToolError, "untrusted mkudffs"):
            executor.execute(self.device, plan)
        preflight_popen.assert_not_called()
        identity_lookup.assert_not_called()
        executor._runner.assert_not_called()
        executor._popen.assert_not_called()

    def test_udf_mkudffs_preflight_timeout_is_bounded_before_device_access(self):
        plan = create_format_plan(self.device, "udf", "gpt", "USB")
        process = MkudffsHelpProcess(
            ["/usr/bin/mkudffs", "--help"], running=True,
        )
        identity_lookup = Mock()
        runner = Mock()
        destructive_popen = Mock()
        executor = FormatExecutor(
            device_lookup=identity_lookup,
            which=lambda name: f"/usr/bin/{name}",
            popen=destructive_popen,
            preflight_popen=lambda _argv, **_kwargs: process,
            runner=runner,
            mkudffs_preflight_timeout=0.01,
        )
        with self.assertRaisesRegex(FormattingError, "inspection timed out"):
            executor.execute(self.device, plan)
        self.assertTrue(process.terminated)
        identity_lookup.assert_not_called()
        runner.assert_not_called()
        destructive_popen.assert_not_called()

    def test_udf_mkudffs_preflight_caps_output_before_device_access(self):
        plan = create_format_plan(self.device, "udf", "gpt", "USB")
        identity_lookup = Mock()
        runner = Mock()
        destructive_popen = Mock()
        executor = FormatExecutor(
            device_lookup=identity_lookup,
            which=lambda name: f"/usr/bin/{name}",
            popen=destructive_popen,
            preflight_popen=lambda argv, **kwargs: MkudffsHelpProcess(
                argv, output=SUPPORTED_MKUDFFS_HELP + b"x" * (64 * 1024), **kwargs,
            ),
            runner=runner,
        )
        with self.assertRaisesRegex(FormattingError, "too much output"):
            executor.execute(self.device, plan)
        identity_lookup.assert_not_called()
        runner.assert_not_called()
        destructive_popen.assert_not_called()

    def test_lock_conflict_exit_is_reported_specifically(self):
        class ConflictProcess(FakeProcess):
            def communicate(self, input=None, timeout=None):
                self.inputs.append(input)
                self.returncode = 75
                return b"", b"generic failure"

        executor = FormatExecutor(
            popen=lambda argv, **kwargs: ConflictProcess(argv, **kwargs),
        )
        with self.assertRaisesRegex(FormattingError, "Another lock-aware"):
            executor._run_process([
                "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive",
                "--nonblock", "--conflict-exit-code", "75", "--no-fork",
                "/dev/sdz", "/usr/sbin/mkfs.vfat", "/dev/sdz1",
            ])

    def test_unwrapped_exit_75_is_not_misreported_as_a_lock_conflict(self):
        class TemporaryFailureProcess(FakeProcess):
            def communicate(self, input=None, timeout=None):
                self.inputs.append(input)
                self.returncode = 75
                return b"", b"partprobe temporary failure"

        executor = FormatExecutor(
            popen=lambda argv, **kwargs: TemporaryFailureProcess(argv, **kwargs),
        )
        with self.assertRaisesRegex(
            FormattingError, "partprobe temporary failure",
        ) as raised:
            executor._run_process([
                "/usr/bin/pkexec", "/usr/sbin/partprobe", "/dev/sdz",
            ])
        self.assertNotIn("lock-aware", str(raised.exception))

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

        def runner(argv, **_kwargs):
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen,
            runner=runner,
        )
        holder["executor"] = executor
        with self.assertRaises(FormatCancelled):
            executor.execute(self.device, self.plan)
        self.assertEqual(len(processes), 1)
        self.assertTrue(processes[0].terminated)

    def test_cancelled_child_exit_is_classified_as_cancellation(self):
        holder = {}

        class PromptlyTerminatedProcess(FakeProcess):
            def __init__(self, argv, **kwargs):
                super().__init__(argv, **kwargs)
                self.returncode = None

            def communicate(self, input=None, timeout=None):
                self.inputs.append(input)
                holder["executor"].cancel()
                return b"", b""

        executor = FormatExecutor(
            popen=lambda argv, **kwargs: PromptlyTerminatedProcess(argv, **kwargs),
        )
        holder["executor"] = executor
        with self.assertRaisesRegex(FormatCancelled, "cancelled"):
            executor._run_process([
                "/usr/bin/pkexec", "/usr/sbin/mkfs.vfat", "/dev/sdz1",
            ])

    def test_bounded_probe_normalizes_timeout_and_cancel(self):
        observed_kwargs = []

        def timeout_runner(argv, **kwargs):
            observed_kwargs.append(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        executor = FormatExecutor(runner=timeout_runner)
        with self.assertRaisesRegex(FormattingError, "Device inspection timed out"):
            executor._run_probe(
                ["/usr/bin/lsblk"], purpose="Device inspection", timeout=0.5,
            )
        self.assertEqual(observed_kwargs[0]["timeout"], 0.5)
        self.assertFalse(observed_kwargs[0]["shell"])

        holder = {}

        def cancelling_runner(_argv, **_kwargs):
            holder["executor"].cancel()
            return completed()

        cancelled = FormatExecutor(runner=cancelling_runner)
        holder["executor"] = cancelled
        with self.assertRaisesRegex(FormatCancelled, "cancelled"):
            cancelled._run_probe(["/usr/bin/lsblk"], purpose="Device inspection")

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

        def runner(argv, **_kwargs):
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen,
            runner=runner,
            process_timeout=0.01, stop_grace=0.01,
        )
        with self.assertRaisesRegex(FormattingError, "timed out"):
            executor.execute(self.device, self.plan)
        self.assertTrue(processes[0].terminated)
        self.assertTrue(processes[0].killed)

    def test_unmount_failure_stops_before_partitioning(self):
        def runner(argv, **_kwargs):
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            return completed(stderr="device is busy", code=1)

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", runner=runner,
            popen=lambda *_args, **_kwargs: self.fail("must not partition"),
        )
        with (
            patch(
                "isopropyl.formatting.conflict_diagnostic_suffix",
                return_value=(
                    " Processes currently using the target: Files (PID 42)."
                ),
            ) as diagnose,
            self.assertRaisesRegex(FormattingError, "Files.*PID 42"),
        ):
            executor.execute(self.device, self.plan)
        diagnose.assert_called_once_with("/dev/sdz1")

    def test_unformatted_partition_response_allows_safe_recovery_format(self):
        processes = []
        unmount_seen = False

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            nonlocal unmount_seen
            if argv[0].endswith("/udisksctl"):
                unmount_seen = True
                return completed(
                    stderr=(
                        "Object /org/freedesktop/UDisks2/block_devices/sdz1 "
                        "is not a mountable filesystem."
                    ),
                    code=1,
                )
            if "--json" in argv and any(
                argument.endswith("/sfdisk") for argument in argv
            ):
                return completed(single_metadata_payload(self.plan))
            if "lsblk" in argv[0] and "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "children": [{
                        "path": "/dev/sdz1", "type": "part",
                        "pkname": self.device.path, "maj:min": "65:145",
                    }],
                }]}))
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: (
                test_device(mountpoints=()) if unmount_seen else self.device
            ),
            which=lambda name: f"/usr/bin/{name}",
            popen=popen,
            runner=runner,
            lstat_func=partition_lstat,
            sleep=lambda _seconds: None,
        )

        self.assertEqual(executor.execute(self.device, self.plan), "/dev/sdz1")
        self.assertTrue(any(
            any(argument.endswith("/mkfs.vfat") for argument in process.argv)
            for process in processes
        ))

    def test_normalized_unmount_response_requires_empty_mountpoint_witness(self):
        partitioner = Mock()

        def runner(argv, **_kwargs):
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            if argv[0].endswith("/udisksctl"):
                return completed(
                    stderr=(
                        "Object /org/freedesktop/UDisks2/block_devices/sdz1 "
                        "is not a mountable filesystem."
                    ),
                    code=1,
                )
            return completed()

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner,
            popen=partitioner,
        )

        with self.assertRaisesRegex(FormattingError, "still reports mounted"):
            executor.execute(self.device, self.plan)
        partitioner.assert_not_called()

    def test_unmount_timeout_is_bounded_before_partitioning(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        popen = Mock()
        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", runner=runner, popen=popen,
        )
        with (
            patch(
                "isopropyl.formatting.conflict_diagnostic_suffix",
                return_value=" A recent snapshot found Files (PID 42).",
            ) as diagnose,
            self.assertRaisesRegex(FormattingError, "timed out.*PID 42"),
        ):
            executor.execute(self.device, self.plan)
        diagnose.assert_called_once_with("/dev/sdz1")
        self.assertEqual(calls[0][1]["timeout"], 15)
        self.assertEqual(calls[1][1]["timeout"], 30)
        popen.assert_not_called()

    def test_single_partition_node_replacement_stops_before_mkfs(self):
        processes = []
        lstat_calls = 0

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            if "--json" in argv and any(
                argument.endswith("/sfdisk") for argument in argv
            ):
                return completed(single_metadata_payload(self.plan))
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            return completed(json.dumps({"blockdevices": [{
                "path": self.device.path, "type": "disk", "children": [{
                    "path": "/dev/sdz1", "type": "part",
                    "pkname": self.device.path, "maj:min": "65:145",
                }],
            }]}))

        def changing_lstat(path):
            nonlocal lstat_calls
            lstat_calls += 1
            info = partition_lstat(path)
            if lstat_calls == 2:
                info.st_rdev = os.makedev(65, 199)
            return info

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen, runner=runner,
            lstat_func=changing_lstat, sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(DeviceChangedError, "node identity changed"):
            executor.execute(self.device, self.plan)
        self.assertFalse(any(
            any(argument.endswith("/mkfs.vfat") for argument in process.argv)
            for process in processes
        ))

    def test_single_partition_geometry_replacement_stops_before_mkfs(self):
        processes = []
        geometry_calls = 0

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            nonlocal geometry_calls
            if "--json" in argv and any(
                argument.endswith("/sfdisk") for argument in argv
            ):
                geometry_calls += 1
                return completed(single_metadata_payload(
                    self.plan, size=None if geometry_calls == 1 else 1,
                ))
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            return completed(json.dumps({"blockdevices": [{
                "path": self.device.path, "type": "disk", "children": [{
                    "path": "/dev/sdz1", "type": "part",
                    "pkname": self.device.path, "maj:min": "65:145",
                }],
            }]}))

        executor = FormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}", popen=popen, runner=runner,
            lstat_func=partition_lstat, sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(FormattingError, "path, start, size, or type"):
            executor.execute(self.device, self.plan)
        self.assertEqual(geometry_calls, 2)
        self.assertFalse(any(
            any(argument.endswith("/mkfs.vfat") for argument in process.argv)
            for process in processes
        ))

    def test_multiple_discovered_partitions_are_not_guessed(self):
        def runner(argv, **_kwargs):
            if "PATH,TYPE,LOG-SEC" in argv:
                return completed(json.dumps({"blockdevices": [{
                    "path": self.device.path, "type": "disk", "log-sec": 512,
                }]}))
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                        {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
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
                        {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                    ],
                }]}))
            return completed()

        self.executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            popen=popen, runner=runner, lstat_func=partition_lstat,
            sleep=lambda _seconds: None,
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
        hierarchy_queries = [
            argv for argv, _kwargs in self.run_calls
            if argv[0].endswith("/lsblk")
            and any(value in argv for value in (
                "PATH,TYPE", "PATH,TYPE,PKNAME,MAJ:MIN",
            ))
        ]
        self.assertTrue(hierarchy_queries)
        self.assertTrue(all("--tree" in argv for argv in hierarchy_queries))
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
        self.assertTrue(all(command[1] == "/usr/bin/flock" for command in mkfs_commands))
        self.assertTrue(all(command[7] == "/dev/sdz" for command in mkfs_commands))
        self.assertEqual(stages[-1], "Complete")

    def test_missing_tool_preflight_touches_nothing(self):
        runner = Mock()
        popen = Mock()
        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: None if name == "mkfs.ntfs" else f"/usr/bin/{name}",
            runner=runner, popen=popen, lstat_func=partition_lstat,
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
            lstat_func=partition_lstat,
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
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                        {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
                        {"path": "/dev/sdz3", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:147"},
                    ],
                }]}))
            return completed()

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen, lstat_func=partition_lstat,
            sleep=lambda _seconds: None,
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
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                        {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
                    ],
                }]}))
            return completed()

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen, lstat_func=partition_lstat,
            sleep=lambda _seconds: None,
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

    def test_partition_node_replacement_stops_before_mkfs(self):
        processes = []
        lstat_calls = 0

        def popen(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **_kwargs):
            if "lsblk" in argv[0]:
                return completed(json.dumps({"blockdevices": [{
                    "path": "/dev/sdz", "type": "disk", "children": [
                        {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                        {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
                    ],
                }]}))
            return completed()

        def changing_lstat(path):
            nonlocal lstat_calls
            lstat_calls += 1
            info = partition_lstat(path)
            if lstat_calls == 3:
                info.st_rdev = os.makedev(65, 200)
            return info

        executor = MultiFormatExecutor(
            device_lookup=lambda _path: self.device,
            which=lambda name: f"/usr/bin/{name}",
            runner=runner, popen=popen, lstat_func=changing_lstat,
            sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(DeviceChangedError, "identity changed"):
            executor.execute_multi(self.device, self.plan)
        self.assertFalse(any(
            any("mkfs." in argument for argument in process.argv)
            for process in processes
        ))

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
                            {"path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:145"},
                            {"path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz", "maj:min": "65:146"},
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
                runner=runner, popen=popen, lstat_func=partition_lstat,
                sleep=lambda _seconds: None,
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
            lstat_func=partition_lstat,
        )
        with self.assertRaisesRegex(DeviceChangedError, "4096-byte"):
            executor.execute_multi(self.device, plan)
        self.assertEqual(len(run_calls), 1)
        self.assertIn("--nodeps", run_calls[0][0])
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
