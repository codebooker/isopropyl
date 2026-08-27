from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Privacy-conscious diagnostic bundle generation."""

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
from .images import ImageInspection

TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_TOOL_OUTPUT = 4096


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
    # Member paths can contain private project/customer names; counts retain
    # the useful diagnostic fact without exporting that catalog.
    record = asdict(inspection)
    record.pop("members", None)
    record["member_count"] = len(inspection.members)
    return record


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
