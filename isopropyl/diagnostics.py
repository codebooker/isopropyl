from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Privacy-conscious diagnostic bundle generation."""

import enum
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .devices import Device
from .dbx import SOURCE_COMMIT, SOURCE_RELEASE, SOURCE_RELEASE_DATE, DbxState
from .images import ImageInspection

TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_TOOL_OUTPUT = 4096
MAX_EMBEDDED_UEFI_FAT_SUMMARIES = 32


def _device_record(device: Device, include_identifiers: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": device.path,
        "size": device.size,
        "model": device.model,
        "vendor": device.vendor,
        "transport": device.transport,
        "removable": device.removable,
        "hotplug": device.hotplug,
        "read_only": device.read_only,
        "major_minor": device.major_minor,
        "partition_count": len(device.partitions),
        "mounted": bool(device.mountpoints),
    }
    if include_identifiers:
        record.update({
            "serial": device.serial,
            "wwn": device.wwn,
            "mountpoints": list(device.mountpoints),
            "partitions": list(device.partitions),
        })
    return record


def _image_record(inspection: ImageInspection | None) -> dict[str, Any] | None:
    if inspection is None:
        return None
    # Volume labels, member paths, and member-scoped issue text can contain
    # private project/customer names. Counts retain the useful diagnostic facts
    # without exporting that catalog. El Torito identifiers and selection bytes
    # are likewise image-controlled, so export only a structural summary.
    record = asdict(inspection)
    record.pop("volume_label", None)
    record["volume_label_present"] = bool(inspection.volume_label)
    record.pop("members", None)
    record["member_count"] = len(inspection.members)
    record.pop("bootloader_issues", None)
    record["bootloader_issue_count"] = len(inspection.bootloader_issues)
    record.pop("uefi_payloads", None)
    record["uefi_payload_count"] = len(inspection.uefi_payloads)
    dbx_counts = {state.value: 0 for state in DbxState}
    dbx_unavailable = 0
    for payload in inspection.uefi_payloads:
        if payload.dbx is None:
            dbx_unavailable += 1
        else:
            dbx_counts[payload.dbx.state.value] += 1
    record["dbx_advisor"] = {
        "snapshot_release": SOURCE_RELEASE,
        "snapshot_commit": SOURCE_COMMIT,
        "snapshot_date": SOURCE_RELEASE_DATE,
        "counts": dbx_counts,
        "unavailable": dbx_unavailable,
        "analysis_complete": inspection.uefi_analysis_complete,
    }
    record.pop("uefi_analysis_issues", None)
    record["uefi_analysis_issue_count"] = len(inspection.uefi_analysis_issues)
    record.pop("embedded_uefi_fats", None)
    record.pop("embedded_uefi_fat", None)
    record.pop("embedded_uefi_issues", None)
    record["embedded_uefi_issue_count"] = len(inspection.embedded_uefi_issues)
    record["embedded_uefi_fat_count"] = len(inspection.embedded_uefi_fats)
    embedded_summaries = [
        {
            "catalog_index": embedded.boot_entry.catalog_index,
            "fat_type": embedded.fat_type.value,
            "entry_count": len(embedded.entries),
            "file_count": sum(not entry.is_directory for entry in embedded.entries),
            "content_bytes": embedded.content_bytes,
            "mbr_wrapped": embedded.partition_start_lba is not None,
        }
        for embedded in inspection.embedded_uefi_fats[
            :MAX_EMBEDDED_UEFI_FAT_SUMMARIES
        ]
    ]
    record["embedded_uefi_fats"] = embedded_summaries
    record["embedded_uefi_fat_summaries_complete"] = (
        len(embedded_summaries) == len(inspection.embedded_uefi_fats)
    )
    if len(embedded_summaries) == 1:
        # Schema-1 compatibility for consumers which predate plural EFI images.
        record["embedded_uefi_fat"] = embedded_summaries[0]
    if inspection.eltorito is not None:
        record["eltorito"] = {
            "source_size": inspection.eltorito.source_size,
            "catalog_lba": inspection.eltorito.catalog_lba,
            "catalog_offset": inspection.eltorito.catalog_offset,
            "catalog_size": inspection.eltorito.catalog_size,
            "descriptors_scanned": inspection.eltorito.descriptors_scanned,
            "logical_volume_size": inspection.eltorito.logical_volume_size,
            "validation_platform": inspection.eltorito.validation.platform.value,
            "entry_count": len(inspection.eltorito.entries),
            "bootable_platforms": [
                platform.value for platform in inspection.eltorito.bootable_platforms
            ],
        }
    return _json_safe(record)


def _json_safe(value: Any) -> Any:
    """Return a bounded diagnostic value made only of JSON-native types."""
    if isinstance(value, enum.Enum):
        return _json_safe(value.value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"Unsupported diagnostic value: {type(value).__name__}")


def probe_tool_versions(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, dict[str, Any]]:
    probes = {
        "7z": ("--help",),
        "xorriso": ("-version",),
        "wimlib-imagex": ("--version",),
        "qemu-img": ("--version",),
        "parted": ("--version",),
        "mkfs.fat": ("--help",),
        "mkfs.ntfs": ("--version",),
        "mkfs.exfat": ("--version",),
        "f3probe": ("--version",),
        "badblocks": ("-V",),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, arguments in probes.items():
        executable = shutil.which(name, path=TRUSTED_PATH)
        if not executable:
            result[name] = {"available": False}
            continue
        try:
            completed = runner(
                [executable, *arguments], capture_output=True, text=True,
                timeout=5, shell=False,
            )
            combined = ((completed.stdout or "") + (completed.stderr or ""))[:MAX_TOOL_OUTPUT]
            first_line = next((line.strip() for line in combined.splitlines() if line.strip()), "")
            result[name] = {
                "available": True,
                "path": executable,
                "version": first_line,
                "probe_exit_status": completed.returncode,
            }
        except (OSError, subprocess.SubprocessError) as error:
            result[name] = {
                "available": True,
                "path": executable,
                "probe_error": str(error)[:512],
            }
    return result


def build_diagnostics(
    devices: Sequence[Device],
    inspection: ImageInspection | None,
    *,
    include_identifiers: bool = False,
    log_text: str | None = None,
    tool_probe: Callable[[], dict[str, dict[str, Any]]] = probe_tool_versions,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": 1,
        "isopropyl_version": __version__,
        "privacy": {
            "identifiers_included": include_identifiers,
            "log_included": include_identifiers and log_text is not None,
        },
        "system": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "devices": [_device_record(device, include_identifiers) for device in devices],
        "selected_image_inspection": _image_record(inspection),
        "tools": tool_probe(),
    }
    if include_identifiers and log_text is not None:
        report["activity_log"] = log_text
    return report


def write_diagnostics(path: Path, report: dict[str, Any]) -> None:
    """Atomically publish a user-owned JSON report."""
    destination = path.expanduser().resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".partial", dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
