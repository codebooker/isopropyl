# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Fail-closed planning primitives for a future Windows To Go workflow.

This module deliberately creates preview plans only. It does not partition a
drive or apply a WIM. Physical execution remains gated on native BCD creation,
offline SAN-policy verification, and an authenticated privileged WIM-apply
transaction.
"""

import math
from dataclasses import dataclass

from .devices import Device
from .formatting import (
    Filesystem,
    MultiFormatPlan,
    PartitionRole,
    PartitionSpec,
    PartitionTable,
    create_multi_format_plan,
    validate_device,
    validate_multi_plan,
)
from .wim import WimSelection, validate_wim_selection

MIB = 1024 * 1024
GIB = 1024 * MIB
RUFUS_ESP_BYTES = 260 * MIB
RUFUS_MSR_BYTES = 128 * MIB
MINIMUM_TARGET_BYTES = 32 * GIB
MINIMUM_FREE_BYTES = 8 * GIB
SUPPORTED_LOGICAL_SECTOR_SIZE = 512
_GPT_ENTRY_ARRAY_BYTES = 128 * 128

# These are feature gates, not advisory warnings. An executor must eliminate
# every one before a preview can become an executable plan.
EXECUTION_BLOCKERS = (
    "authenticated-privileged-wim-apply",
    "native-bcd-authoring-and-readback",
    "offline-san-policy-write-and-readback",
    "qemu-ovmf-and-physical-media-certification",
)


class WindowsToGoError(RuntimeError):
    pass


class WindowsToGoUnavailable(WindowsToGoError):
    pass


@dataclass(frozen=True)
class WindowsToGoPreviewPlan:
    """Immutable, explicitly non-executable Windows To Go intent."""

    device: Device
    selection: WimSelection
    layout: MultiFormatPlan
    expanded_bytes: int
    windows_capacity: int
    blockers: tuple[str, ...] = EXECUTION_BLOCKERS

    @property
    def executable(self) -> bool:
        return False


def _version_is_windows_8_or_later(selection: WimSelection) -> bool:
    edition = selection.edition
    return (edition.major_version, edition.minor_version) >= (6, 2)


def _layout(device: Device, logical_sector_size: int) -> MultiFormatPlan:
    if logical_sector_size != SUPPORTED_LOGICAL_SECTOR_SIZE:
        raise WindowsToGoUnavailable(
            "The first Windows To Go profile is certified only for 512-byte logical sectors"
        )
    alignment = MIB // logical_sector_size
    total_sectors = device.size // logical_sector_size
    gpt_tail = math.ceil(_GPT_ENTRY_ARRAY_BYTES / logical_sector_size) + 1
    aligned_end = ((total_sectors - gpt_tail) // alignment) * alignment
    esp_count = RUFUS_ESP_BYTES // logical_sector_size
    msr_count = RUFUS_MSR_BYTES // logical_sector_size
    esp_start = alignment
    msr_start = esp_start + esp_count
    windows_start = msr_start + msr_count
    windows_count = aligned_end - windows_start
    if windows_count <= 0:
        raise WindowsToGoUnavailable("The target is too small for the Windows To Go layout")
    return create_multi_format_plan(
        device,
        PartitionTable.GPT,
        (
            PartitionSpec(
                PartitionRole.EFI_SYSTEM,
                Filesystem.FAT32,
                start_sector=esp_start,
                sector_count=esp_count,
            ),
            PartitionSpec(
                PartitionRole.MICROSOFT_RESERVED,
                None,
                start_sector=msr_start,
                sector_count=msr_count,
            ),
            PartitionSpec(
                PartitionRole.WINDOWS_OS,
                Filesystem.NTFS,
                "Windows",
                start_sector=windows_start,
                sector_count=windows_count,
            ),
        ),
        logical_sector_size=logical_sector_size,
    )


def build_windows_to_go_preview(
    selection: WimSelection,
    device: Device,
    logical_sector_size: int,
) -> WindowsToGoPreviewPlan:
    """Build Rufus-compatible GPT geometry without authorizing any write."""

    validate_wim_selection(selection)
    validate_device(device)
    if device.logical_sector_size not in (0, logical_sector_size):
        raise WindowsToGoUnavailable(
            "The requested layout disagrees with the target logical sector size"
        )
    edition = selection.edition
    if edition.architecture != "amd64":
        raise WindowsToGoUnavailable(
            "The initial Windows To Go profile supports x64 images only"
        )
    if not _version_is_windows_8_or_later(selection):
        raise WindowsToGoUnavailable("Windows To Go requires Windows 8 or later")
    if device.removable and edition.build < 15_000:
        raise WindowsToGoUnavailable(
            "Pre-build-15000 Windows is not supported on removable-media targets"
        )
    if edition.expanded_bytes <= 0:
        raise WindowsToGoUnavailable(
            "The selected WIM does not report an expanded image size"
        )
    if device.size < MINIMUM_TARGET_BYTES:
        raise WindowsToGoUnavailable("Windows To Go requires a target of at least 32 GiB")
    layout = _layout(device, logical_sector_size)
    windows = layout.partitions[2]
    assert windows.sector_count is not None
    windows_capacity = windows.sector_count * logical_sector_size
    if windows_capacity < edition.expanded_bytes + MINIMUM_FREE_BYTES:
        raise WindowsToGoUnavailable(
            "The Windows partition cannot hold the expanded image with 8 GiB free space"
        )
    plan = WindowsToGoPreviewPlan(
        device,
        selection,
        layout,
        edition.expanded_bytes,
        windows_capacity,
    )
    validate_windows_to_go_preview(plan)
    return plan


def validate_windows_to_go_preview(plan: WindowsToGoPreviewPlan) -> None:
    if not isinstance(plan, WindowsToGoPreviewPlan):
        raise WindowsToGoUnavailable("A WindowsToGoPreviewPlan is required")
    validate_device(plan.device)
    validate_wim_selection(plan.selection)
    validate_multi_plan(plan.layout)
    if plan.device.logical_sector_size not in (
        0, plan.layout.logical_sector_size,
    ):
        raise WindowsToGoUnavailable(
            "The preview disagrees with the target logical sector size"
        )
    if plan.layout != _layout(plan.device, plan.layout.logical_sector_size or 0):
        raise WindowsToGoUnavailable("The Windows To Go layout was modified")
    edition = plan.selection.edition
    windows = plan.layout.partitions[2]
    assert windows.sector_count is not None
    expected_capacity = windows.sector_count * SUPPORTED_LOGICAL_SECTOR_SIZE
    if (
        edition.architecture != "amd64"
        or not _version_is_windows_8_or_later(plan.selection)
        or (plan.device.removable and edition.build < 15_000)
        or edition.expanded_bytes <= 0
        or plan.device.size < MINIMUM_TARGET_BYTES
        or plan.expanded_bytes != edition.expanded_bytes
        or plan.windows_capacity != expected_capacity
        or expected_capacity < edition.expanded_bytes + MINIMUM_FREE_BYTES
        or plan.blockers != EXECUTION_BLOCKERS
        or plan.executable
    ):
        raise WindowsToGoUnavailable("The Windows To Go preview binding is invalid")
