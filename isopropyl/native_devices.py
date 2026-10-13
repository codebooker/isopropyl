"""Read-only native discovery. Never interpolate device paths into scripts."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass

from .devices import MAX_DEVICE_DISCOVERY_OUTPUT, Device, DeviceDiscoveryError

DISKUTIL = "/usr/sbin/diskutil"
MAC_DISK = re.compile(r"disk[0-9]+")
WIN_DISK = re.compile(r"\\\\\.\\PhysicalDrive([0-9]+)")
WIN_VOLUME = re.compile(r"\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\")

# A fixed script, run without profiles; no image or target input enters it.
WINDOWS_DISCOVERY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$media = @{}
Get-CimInstance Win32_DiskDrive | ForEach-Object { $media[[int]$_.Index] = $_ }
$partitions = @(Get-Partition -ErrorAction Stop)
$result = @(Get-Disk | Where-Object { $_.BusType -in @('USB','SD') -and -not $_.IsBoot -and -not $_.IsSystem -and -not $_.IsOffline } | ForEach-Object {
  $d = $_
  $parts = @($partitions | Where-Object { $_.DiskNumber -eq $d.Number })
  [pscustomobject]@{
    Number = [int]$d.Number; Size = [long]$d.Size
    Model = [string]$d.FriendlyName; Serial = [string]$d.SerialNumber
    UniqueId = [string]$d.UniqueId; BusType = [string]$d.BusType
    IsBoot = [bool]$d.IsBoot; IsSystem = [bool]$d.IsSystem
    IsOffline = [bool]$d.IsOffline; IsReadOnly = [bool]$d.IsReadOnly
    LogicalSectorSize = [int]$d.LogicalSectorSize
    Removable = ($media[[int]$d.Number].MediaType -eq 'Removable Media')
    PhysicalId = [string]$media[[int]$d.Number].PNPDeviceID
    AccessPaths = @($parts | ForEach-Object { $_.AccessPaths } | Where-Object { $_ })
  }
})
ConvertTo-Json -InputObject $result -Depth 5 -Compress
"""


@dataclass(frozen=True)
class NativeDevice:
    device: Device
    # Volumes without drive letters must be locked too.
    volumes: tuple[str, ...] = ()
    # IOKit path / Storage UniqueId used in addition to common Device identity.
    hardware_id: str = ""
    # macOS hides filesystem topology while an exclusive whole-disk handle is
    # held. Keep the IOMedia lifetime identity available independently.
    physical_hardware_id: str = ""

    @property
    def identity(self) -> tuple:
        return (*self.device.identity, self.device.logical_sector_size, self.hardware_id)

    @property
    def physical_identity(self) -> tuple:
        return (*self.device.identity, self.device.logical_sector_size,
                self.physical_hardware_id or self.hardware_id)


def command(argv: list[str], *, runner=None) -> bytes:
    # Console tools otherwise create a visible window when launched by pythonw.
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
    try:
        result = (runner or subprocess.run)(
            argv, check=False, capture_output=True, timeout=30, shell=False, **options,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeviceDiscoveryError(f"Native disk command could not complete: {error}") from error
    output = result.stdout or b""
    detail = result.stderr or b""
    if isinstance(output, str):
        output = output.encode("utf-8")
    if isinstance(detail, str):
        detail = detail.encode("utf-8")
    if len(output) + len(detail) > MAX_DEVICE_DISCOVERY_OUTPUT:
        raise DeviceDiscoveryError("Native disk command produced too much output")
    if result.returncode:
        raise DeviceDiscoveryError(detail.decode("utf-8", "replace")[-2048:] or "Native disk command failed")
    return output


def mac_info(name: str, *, runner=None) -> dict:
    try:
        info = plistlib.loads(command([DISKUTIL, "info", "-plist", name], runner=runner))
        if not isinstance(info, dict):
            raise TypeError("Expected a disk information dictionary")
        return info
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise DeviceDiscoveryError("diskutil returned invalid disk information") from error


def mac_registry_id(name: str) -> int:
    """Bind the IOMedia object's lifetime, so reconnecting at one port changes identity."""
    import ctypes as c
    library = c.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    library.IOBSDNameMatching.argtypes = [c.c_uint, c.c_uint, c.c_char_p]
    library.IOBSDNameMatching.restype = c.c_void_p
    library.IOServiceGetMatchingService.argtypes = [c.c_uint, c.c_void_p]
    library.IOServiceGetMatchingService.restype = c.c_uint
    library.IORegistryEntryGetRegistryEntryID.argtypes = [c.c_uint, c.POINTER(c.c_uint64)]
    library.IORegistryEntryGetRegistryEntryID.restype = c.c_int
    library.IOObjectRelease.argtypes = [c.c_uint]
    library.IOObjectRelease.restype = c.c_int
    matching = library.IOBSDNameMatching(0, 0, name.encode("ascii"))
    if not matching:
        raise DeviceDiscoveryError("Could not match the native disk object")
    service = library.IOServiceGetMatchingService(0, matching)
    if not service:
        raise DeviceDiscoveryError("The native disk object disappeared")
    try:
        identity = c.c_uint64()
        if library.IORegistryEntryGetRegistryEntryID(service, c.byref(identity)) or not identity.value:
            raise DeviceDiscoveryError("Could not bind the native disk object's identity")
        return identity.value
    finally:
        library.IOObjectRelease(service)


def mac_system_disks(info: dict) -> set[str]:
    """Resolve an APFS startup volume to every physical store (including Fusion)."""
    names = [info.get("ParentWholeDisk", ""), info.get("DeviceIdentifier", "")]
    names.extend(item.get("APFSPhysicalStore", "") for item in info.get("APFSPhysicalStores", []))
    return {match.group() for name in names if (match := re.match(r"disk[0-9]+", name))}


def mac_apfs_mapping(parts: list[dict], listing: dict, *, runner=None):
    """Map each APFS store to its one container and all synthesized volumes.

    Multi-store containers are excluded: erasing one drive would invalidate
    data on another. Missing or ambiguous mappings also fail closed.
    """
    children, containers, identities = [], [], []
    for part in parts:
        if "APFS" not in str(part.get("Content", "")):
            continue
        store = part["DeviceIdentifier"]
        matches = [container for container in listing["Containers"] if any(
            item.get("DeviceIdentifier") == store for item in container.get("PhysicalStores", [])
        )]
        if len(matches) != 1 or len(matches[0].get("PhysicalStores", [])) != 1:
            return None
        container = matches[0]
        name = container["ContainerReference"]
        uuid = container.get("APFSContainerUUID")
        if not MAC_DISK.fullmatch(name) or not isinstance(uuid, str) or not uuid:
            raise ValueError("Invalid APFS container identity")
        containers.append(f"/dev/{name}")
        identities.append(f"{store}:{name}:{uuid}")
        for volume in container["Volumes"]:
            volume_name = volume["DeviceIdentifier"]
            volume_uuid = volume.get("APFSVolumeUUID")
            if (not re.fullmatch(re.escape(name) + r"s[0-9]+", volume_name)
                    or not isinstance(volume_uuid, str) or not volume_uuid):
                raise ValueError("Invalid APFS volume identity")
            info = mac_info(volume_name, runner=runner)
            if info.get("DeviceIdentifier") != volume_name or info.get("ParentWholeDisk") != name:
                raise ValueError("APFS volume mapping changed during discovery")
            children.append(info)
            identities.append(f"{volume_name}:{volume_uuid}")
    return children, tuple(sorted(set(containers))), tuple(sorted(identities))


def parse_mac_device(info: dict, children: list[dict], forbidden: set[str], include_fixed: bool) -> NativeDevice | None:
    name = info.get("DeviceIdentifier", "")
    # Missing safety metadata excludes the disk. Disk images and synthesized
    # APFS containers cannot satisfy this physical whole-disk predicate.
    if (not isinstance(name, str) or not MAC_DISK.fullmatch(name)
            or name in forbidden or info.get("WholeDisk") is not True
            or info.get("Internal") is not False or info.get("VirtualOrPhysical") != "Physical"
            or str(info.get("BusProtocol", "")).lower() not in {"usb", "secure digital"}):
        return None
    removable = info.get("RemovableMedia") is True
    if not removable and not (include_fixed and str(info.get("BusProtocol")).lower() == "usb"):
        return None
    mounts = tuple(item["MountPoint"] for item in [info, *children] if item.get("MountPoint"))
    if any(mount in {"/", "/System/Volumes/Data"} for mount in mounts):
        return None
    size = info.get("TotalSize", 0)
    sector = info.get("DeviceBlockSize", 0)
    if type(size) is not int or size <= 0 or type(sector) is not int or sector <= 0:
        raise DeviceDiscoveryError("Invalid native disk geometry")
    device = Device(
        path=f"/dev/{name}", size=size, model=str(info.get("MediaName") or "USB drive"),
        vendor="", transport="usb" if info.get("BusProtocol") == "USB" else "mmc",
        serial=str(info.get("SerialNumber") or ""), wwn="", major_minor=name,
        removable=removable, hotplug=True, read_only=info.get("WritableMedia") is not True,
        mountpoints=mounts, partitions=tuple(
            f"/dev/{item['DeviceIdentifier']}" for item in children if item.get("DeviceIdentifier")
        ), logical_sector_size=sector,
    )
    return NativeDevice(device, hardware_id=f"{info.get('DeviceTreePath') or ''}:{info.get('RegistryEntryID') or ''}")


def parse_windows(payload: bytes | str, include_fixed: bool = False) -> list[NativeDevice]:
    rows = json.loads(payload)
    if not isinstance(rows, list):
        raise TypeError("Expected a disk array")
    found = []
    for row in rows:
        if (row.get("IsBoot") is not False or row.get("IsSystem") is not False
                or row.get("IsOffline") is not False or row.get("BusType") not in {'USB','SD'}):
            continue
        if row.get('BusType') == 'SD' and row.get('Removable') is not True:
            continue
        if row.get("Removable") is not True and not include_fixed:
            continue
        number, size, sector = row.get("Number"), row.get("Size"), row.get("LogicalSectorSize")
        if (type(number) is not int or number < 0 or type(size) is not int or size <= 0
                or type(sector) is not int or sector <= 0):
            raise ValueError("Invalid disk identity or geometry")
        paths = row.get("AccessPaths", [])
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            raise ValueError("Invalid disk access paths")
        volumes = tuple(sorted({path for path in paths if WIN_VOLUME.fullmatch(path)}))
        mounts = tuple(path for path in paths if not WIN_VOLUME.fullmatch(path))
        # Every mounted partition must have a volume GUID, not only a letter.
        if mounts and not volumes:
            raise ValueError("Mounted disk lacks volume identities")
        found.append(NativeDevice(Device(
            path=rf"\\.\PhysicalDrive{number}", size=size, model=str(row.get("Model") or "USB drive"),
            vendor="", transport='sd' if row.get('BusType') == 'SD' else 'usb', serial=str(row.get("Serial") or "").strip(),
            wwn="", major_minor=str(number), removable=row.get("Removable") is True,
            hotplug=True, read_only=row.get("IsReadOnly") is not False,
            mountpoints=mounts, partitions=volumes, logical_sector_size=sector,
        ), volumes, str(row.get("UniqueId") or ""), str(row.get('PhysicalId') or '')))
    return found


def discover(include_fixed: bool = False, *, host: str | None = None, runner=None) -> list[NativeDevice]:
    host = host or sys.platform
    try:
        if host == "darwin":
            forbidden = mac_system_disks(mac_info("/", runner=runner))
            forbidden |= mac_system_disks(mac_info("/System/Volumes/Data", runner=runner))
            listing = plistlib.loads(command([DISKUTIL, "list", "-plist", "external", "physical"], runner=runner))
            found = []
            apfs = None
            for disk in listing.get("AllDisksAndPartitions", []):
                name = disk["DeviceIdentifier"]
                if not MAC_DISK.fullmatch(name):
                    raise ValueError("Invalid whole disk name")
                info = mac_info(name, runner=runner)
                parts = disk.get("Partitions", [])
                children = [mac_info(part["DeviceIdentifier"], runner=runner) for part in parts]
                containers, apfs_identity = (), ()
                if any("APFS" in str(part.get("Content", "")) for part in parts):
                    if apfs is None:
                        apfs = plistlib.loads(command([DISKUTIL, "apfs", "list", "-plist"], runner=runner))
                    mapped = mac_apfs_mapping(parts, apfs, runner=runner)
                    if mapped is None:
                        continue
                    volumes, containers, apfs_identity = mapped
                    children.extend(volumes)
                candidate = parse_mac_device(info, children, forbidden, include_fixed)
                if candidate:
                    from dataclasses import replace
                    physical_id = f"{candidate.hardware_id}:{mac_registry_id(name)}"
                    candidate = replace(candidate, volumes=containers,
                        hardware_id=f"{physical_id}:{apfs_identity!r}", physical_hardware_id=physical_id)
                    found.append(candidate)
        elif host == "win32":
            root = os.environ.get("SystemRoot", r"C:\Windows")
            executable = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
            found = parse_windows(command([
                executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_DISCOVERY,
            ], runner=runner), include_fixed)
        else:
            raise DeviceDiscoveryError(f"No native disk backend for {host}")
        paths = [item.device.path for item in found]
        if len(paths) != len(set(paths)):
            raise ValueError("Duplicate whole disk identities")
        return sorted(found, key=lambda item: (item.device.size, item.device.path))
    except (ValueError, TypeError, KeyError, AttributeError, plistlib.InvalidFileException) as error:
        raise DeviceDiscoveryError("Native drive discovery returned invalid data") from error
