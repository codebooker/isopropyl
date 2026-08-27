from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import math
import os
import subprocess
from dataclasses import dataclass
from collections.abc import Callable
from enum import Enum


DEVICE_DISCOVERY_TIMEOUT_SECONDS = 15
MAX_DEVICE_DISCOVERY_OUTPUT = 2 * 1024 * 1024


class DeviceDiscoveryError(RuntimeError):
    pass


class SizeUnitMode(str, Enum):
    """Unit families available for human-readable byte counts."""

    SI = "si"
    IEC = "iec"


@dataclass(frozen=True)
class Device:
    path: str
    size: int
    model: str
    vendor: str
    transport: str
    serial: str
    wwn: str
    major_minor: str
    removable: bool
    hotplug: bool
    read_only: bool
    mountpoints: tuple[str, ...]
    partitions: tuple[str, ...]
    # Discovery-time hint for filtering non-destructive UI choices. Every
    # formatter re-probes and binds this value before it touches the drive.
    logical_sector_size: int = 0

    @property
    def label(self) -> str:
        return self.display_label()

    def display_label(
        self, mode: SizeUnitMode | str = SizeUnitMode.SI,
    ) -> str:
        """Return the device-picker label in the requested unit family."""

        name = " ".join(x for x in (self.vendor, self.model) if x).strip() or "USB drive"
        return f"{name}  ·  {format_size(self.size, mode)}  ·  {self.path}"

    @property
    def identity(self) -> tuple[str, int, str, str, str, str]:
        """Fields that should remain stable while a selected drive is connected."""
        return (self.path, self.size, self.serial, self.wwn, self.model, self.major_minor)

    @property
    def stable_id(self) -> str | None:
        """A reconnect-stable identifier suitable for a safety denylist."""
        if self.wwn:
            return f"wwn:{self.wwn.casefold()}"
        if self.serial:
            return f"serial:{self.transport.casefold()}:{self.serial.casefold()}"
        return None


def format_size(
    size: int | float,
    mode: SizeUnitMode | str = SizeUnitMode.SI,
) -> str:
    """Format non-negative bytes using decimal SI or binary IEC units.

    SI remains the default to preserve ISOpropyl's existing display strings.
    Rate callers can continue appending ``/s`` to the returned value.
    """

    try:
        selected = SizeUnitMode(mode)
    except (TypeError, ValueError) as error:
        choices = ", ".join(item.value for item in SizeUnitMode)
        raise ValueError(f"Unsupported size unit mode {mode!r}; choose {choices}") from error
    value = float(size)
    if not math.isfinite(value) or value < 0:
        raise ValueError("Size must be a finite, non-negative number")
    divisor, units = (
        (1000, ("B", "KB", "MB", "GB", "TB"))
        if selected is SizeUnitMode.SI
        else (1024, ("B", "KiB", "MiB", "GiB", "TiB"))
    )
    index = 0
    while value >= divisor and index < len(units) - 1:
        value /= divisor
        index += 1
    # Do not display boundary-impossible strings such as 1000.0 KB or
    # 1024.0 KiB merely because the value crossed the boundary when rounded.
    if (
        index > 0
        and index < len(units) - 1
        and float(f"{value:.1f}") >= divisor
    ):
        value /= divisor
        index += 1
    unit = units[index]
    return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"


def _mounts(node: dict) -> list[str]:
    values = node.get("mountpoints") or []
    if node.get("mountpoint"):
        values.append(node["mountpoint"])
    found = [str(v) for v in values if v]
    for child in node.get("children") or []:
        found.extend(_mounts(child))
    return found


def parse_lsblk(payload: str, include_usb_hdds: bool = False) -> list[Device]:
    data = json.loads(payload)
    devices: list[Device] = []
    for node in data.get("blockdevices", []):
        if node.get("type") != "disk":
            continue
        mounts = _mounts(node)
        # The root backing disk is forbidden even if a USB-installed OS reports
        # it as hot-pluggable/removable.
        if "/" in mounts:
            continue
        removable = bool(node.get("rm"))
        hotplug = bool(node.get("hotplug"))
        transport = str(node.get("tran") or "")
        if transport not in {"usb", "mmc"}:
            continue
        if not removable and not (include_usb_hdds and hotplug and transport == "usb"):
            continue
        children = node.get("children") or []
        partitions = tuple(
            str(child.get("path")) for child in children
            if child.get("type") == "part" and child.get("path")
        )
        devices.append(Device(
            path=str(node["path"]), size=int(node.get("size") or 0),
            model=str(node.get("model") or "").strip(),
            vendor=str(node.get("vendor") or "").strip(), transport=transport,
            serial=str(node.get("serial") or "").strip(),
            wwn=str(node.get("wwn") or "").strip(),
            major_minor=str(node.get("maj:min") or "").strip(),
            removable=removable, hotplug=hotplug, read_only=bool(node.get("ro")),
            mountpoints=tuple(mounts), partitions=partitions,
            logical_sector_size=int(node.get("log-sec") or 0),
        ))
    return devices


def list_devices(
    include_usb_hdds: bool = False,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> list[Device]:
    fields = (
        "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,"
        "MOUNTPOINTS,RO,LOG-SEC"
    )
    execute = runner or subprocess.run
    try:
        result = execute(
            ["lsblk", "--tree", "--bytes", "--json", "--output", fields],
            check=False, capture_output=True, text=True,
            timeout=DEVICE_DISCOVERY_TIMEOUT_SECONDS, shell=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DeviceDiscoveryError("Drive discovery timed out") from error
    except OSError as error:
        raise DeviceDiscoveryError("Could not start drive discovery") from error
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > (
        MAX_DEVICE_DISCOVERY_OUTPUT
    ):
        raise DeviceDiscoveryError("Drive discovery produced too much output")
    if result.returncode:
        detail = stderr.strip()[-2048:]
        raise DeviceDiscoveryError(detail or "Drive discovery failed")
    try:
        devices = parse_lsblk(stdout, include_usb_hdds)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise DeviceDiscoveryError("Drive discovery returned invalid data") from error
    return sorted(
        devices,
        key=lambda device: (device.size, device.vendor.casefold(), device.model.casefold(), device.path),
    )


def image_is_on_device(image_path: str, device: Device) -> bool:
    """Return whether an image file is backed by the prospective target disk."""
    try:
        source_id = os.stat(image_path).st_dev
    except OSError:
        return False
    for block_path in (device.path, *device.partitions):
        try:
            if os.stat(block_path).st_rdev == source_id:
                return True
        except OSError:
            continue
    return False


def path_is_on_device(path: str, device: Device) -> bool:
    """Check an existing path (or a prospective file's parent) against a drive."""
    candidate = path
    while not os.path.exists(candidate):
        parent = os.path.dirname(candidate)
        if parent == candidate:
            return False
        candidate = parent
    try:
        source_id = os.stat(candidate).st_dev
    except OSError:
        return False
    for block_path in (device.path, *device.partitions):
        try:
            if os.stat(block_path).st_rdev == source_id:
                return True
        except OSError:
            continue
    return False
