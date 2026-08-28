# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import unittest
from dataclasses import replace

from isopropyl.devices import Device
from isopropyl.formatting import (
    Filesystem,
    FormatValidationError,
    PartitionRole,
    PartitionSpec,
    PartitionTable,
    create_multi_format_plan,
    multi_partition_script,
)
from isopropyl.wim import WimEdition, WimSelection
from isopropyl.windows_to_go import (
    EXECUTION_BLOCKERS,
    GIB,
    WindowsToGoUnavailable,
    build_windows_to_go_preview,
    validate_windows_to_go_preview,
)


def target(size: int = 64 * GIB) -> Device:
    return Device(
        path="/dev/sdz",
        size=size,
        model="Portable SSD",
        vendor="Acme",
        transport="usb",
        serial="WTG-SERIAL",
        wwn="",
        major_minor="65:144",
        removable=False,
        hotplug=True,
        read_only=False,
        mountpoints=(),
        partitions=(),
        logical_sector_size=512,
    )


def selection(
    *,
    architecture: str = "amd64",
    major: int = 10,
    minor: int = 0,
    build: int = 26100,
    expanded: int = 20 * GIB,
) -> WimSelection:
    edition = WimEdition(
        index=6,
        name="Windows 11 Pro",
        description="Windows 11 Pro",
        edition_id="Professional",
        architecture=architecture,
        major_version=major,
        minor_version=minor,
        build=build,
        service_pack_build=1,
        expanded_bytes=expanded,
    )
    return WimSelection("sources/install.wim", 5 * GIB, (edition,), 6)


class WindowsToGoPreviewTests(unittest.TestCase):
    def test_builds_exact_rufus_gpt_uefi_geometry_but_cannot_execute(self):
        plan = build_windows_to_go_preview(selection(), target(), 512)
        self.assertFalse(plan.executable)
        self.assertEqual(plan.blockers, EXECUTION_BLOCKERS)
        self.assertEqual(plan.layout.logical_sector_size, 512)
        self.assertEqual(
            [part.role for part in plan.layout.partitions],
            [
                PartitionRole.EFI_SYSTEM,
                PartitionRole.MICROSOFT_RESERVED,
                PartitionRole.WINDOWS_OS,
            ],
        )
        esp, msr, windows = plan.layout.partitions
        self.assertEqual((esp.start_sector, esp.sector_count), (2048, 532480))
        self.assertEqual((msr.start_sector, msr.sector_count), (534528, 262144))
        self.assertEqual((windows.start_sector, windows.sector_count), (796672, 133419008))
        self.assertEqual(esp.filesystem, Filesystem.FAT32)
        self.assertEqual(msr.filesystem, None)
        self.assertEqual(windows.filesystem, Filesystem.NTFS)
        self.assertEqual(windows.label, "Windows")
        script = multi_partition_script(plan.layout).decode("ascii")
        self.assertIn('name="ISOpropyl boot"', script)
        self.assertIn('name="Microsoft reserved"', script)
        self.assertIn('name="Windows"', script)
        self.assertIn("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", script)

    def test_rejects_unsupported_image_target_sector_and_capacity(self):
        invalid = (
            (selection(architecture="arm64"), target(), 512, "x64"),
            (selection(major=6, minor=1), target(), 512, "Windows 8"),
            (selection(expanded=0), target(), 512, "expanded"),
            (selection(), target(31 * GIB), 512, "32 GiB"),
            (
                selection(), replace(target(), logical_sector_size=0), 4096,
                "512-byte",
            ),
            (
                selection(), replace(target(), logical_sector_size=4096), 512,
                "logical sector size",
            ),
            (selection(expanded=58 * GIB), target(), 512, "8 GiB"),
            (
                selection(build=14393), replace(target(), removable=True), 512,
                "Pre-build-15000",
            ),
        )
        for selected, device, sector, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(
                WindowsToGoUnavailable, message,
            ):
                build_windows_to_go_preview(selected, device, sector)

    def test_forged_preview_bindings_fail_validation(self):
        plan = build_windows_to_go_preview(selection(), target(), 512)
        for forged in (
            replace(plan, windows_capacity=plan.windows_capacity + 512),
            replace(plan, expanded_bytes=plan.expanded_bytes + 1),
            replace(plan, blockers=plan.blockers[:-1]),
            replace(plan, device=target(size=65 * GIB)),
        ):
            with self.subTest(forged=forged), self.assertRaises(
                WindowsToGoUnavailable,
            ):
                validate_windows_to_go_preview(forged)

    def test_windows_os_role_is_unambiguous_in_generic_layouts(self):
        with self.assertRaisesRegex(FormatValidationError, "more than one windows-os"):
            create_multi_format_plan(
                target(),
                PartitionTable.GPT,
                (
                    PartitionSpec(
                        PartitionRole.WINDOWS_OS, Filesystem.NTFS, "Windows A",
                        size_mib=1024,
                    ),
                    PartitionSpec(
                        PartitionRole.WINDOWS_OS, Filesystem.NTFS, "Windows B",
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
