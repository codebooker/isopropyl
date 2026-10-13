"""Prepare Windows installer media in an isolated, file-backed virtual disk.

No physical device identity enters the PowerShell preparation commands. Only
NativeWriter receives the separately confirmed USB target after preparation.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import tempfile
from pathlib import Path

from .mac_windows_iso import (
    FAT_LIMIT,
    WindowsSourceMetadata,
    collect_files,
    installer_profile,
    run_tool,
    verify_loader,
)
from .native_writer import (
    BLOCK,
    NativeWriteError,
    NativeWriter,
    build_plan,
    file_identity,
    path_file_identity,
)
from .wim import WimEdition, _validate_staged_parts
from .windows import add_autounattend_to_staging, generate_autounattend

PS_HEADER = """param([string]$ImagePath, [string]$SourcePath, [int]$SizeMiB)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
"""
MOUNT_ISO = (
    PS_HEADER
    + """
if ([IO.Path]::GetExtension($ImagePath) -ne '.iso') { throw 'Expected private ISO snapshot' }
$image = Mount-DiskImage -ImagePath $ImagePath -StorageType ISO -Access ReadOnly -PassThru
if (-not $image.Attached -or [string]$image.StorageType -notin @('1','ISO')) { throw 'ISO attachment failed' }
$volumes = @($image | Get-Volume)
if ($volumes.Count -ne 1 -or -not $volumes[0].DriveLetter -or [string]$volumes[0].DriveType -notin @('CD-ROM','CDROM','5')) { throw 'Expected one optical installer volume' }
@{Root=([string]$volumes[0].DriveLetter + ':\\')} | ConvertTo-Json -Compress
"""
)
DETACH = (
    PS_HEADER
    + """
$image = Get-DiskImage -ImagePath $ImagePath -ErrorAction SilentlyContinue
if ($image -and $image.Attached) { Dismount-DiskImage -ImagePath $ImagePath | Out-Null }
"""
)
MOUNT_VHD = (
    PS_HEADER
    + """
if ([IO.Path]::GetExtension($ImagePath) -ne '.vhd' -or -not [IO.File]::Exists($ImagePath)) { throw 'Expected private VHD file' }
$image = Mount-DiskImage -ImagePath $ImagePath -StorageType VHD -Access ReadWrite -PassThru
if (-not $image.Attached -or [string]$image.StorageType -notin @('2','VHD')) { throw 'VHD attachment failed' }
$disks = @($image | Get-Disk)
if ($disks.Count -ne 1) { throw 'Expected one file-backed disk' }
$disk = $disks[0]
if ([string]$disk.BusType -notin @('FileBackedVirtual','File Backed Virtual','Virtual','15','14') -or $disk.IsBoot -ne $false -or $disk.IsSystem -ne $false -or $disk.Size -ne ([long]$SizeMiB * 1MB)) { throw 'Virtual disk safety check failed' }
if ([string]$disk.PartitionStyle -notin @('RAW','0')) { throw 'Private virtual disk is not blank' }
$initialized = Initialize-Disk -InputObject $disk -PartitionStyle MBR -PassThru
$partition = New-Partition -InputObject $initialized -UseMaximumSize -IsActive -MbrType FAT32 -Offset 1MB
$volume = Format-Volume -Partition $partition -FileSystem FAT32 -NewFileSystemLabel ISOPROPYL -Confirm:$false
Add-PartitionAccessPath -InputObject $partition -AssignDriveLetter | Out-Null
$volume = Get-Volume -Partition $partition
if ($volume.FileSystem -ne 'FAT32' -or -not $volume.DriveLetter) { throw 'Virtual FAT32 formatting failed' }
@{Root=([string]$volume.DriveLetter + ':\\')} | ConvertTo-Json -Compress
"""
)
WIM_INFO = (
    PS_HEADER
    + """
$images = @(Get-WindowsImage -ImagePath $ImagePath | ForEach-Object {
  $item = Get-WindowsImage -ImagePath $ImagePath -Index $_.ImageIndex
  $version = [version]$item.Version
  @{Index=[int]$item.ImageIndex; Name=[string]$item.ImageName; Description=[string]$item.ImageDescription;
    Edition=[string]$item.EditionId; Architecture=[string]$item.Architecture;
    Major=[int]$version.Major; Minor=[int]$version.Minor; Build=[int]$version.Build;
    Revision=[int]$item.SPBuild; ExpandedBytes=[long]$item.ImageSize}
})
ConvertTo-Json -InputObject $images -Depth 4 -Compress
"""
)


def invoke_ps(script, image, writer, *, size_mib=0, timeout=1800):
    with tempfile.TemporaryDirectory(prefix="isopropyl-command-") as directory:
        path = Path(directory) / "prepare.ps1"
        path.write_text(script, encoding="utf-8-sig")
        system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        return run_tool(
            [
                str(system / "System32/WindowsPowerShell/v1.0/powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(path),
                "-ImagePath",
                str(image),
                "-SizeMiB",
                str(size_mib),
            ],
            writer,
            timeout=timeout,
        )


def root_from_result(payload):
    root = json.loads(payload).get("Root", "")
    import re

    if not isinstance(root, str) or not re.fullmatch(r"[A-Z]:\\", root, re.IGNORECASE):
        raise NativeWriteError("Virtual image did not provide one drive root")
    return Path(root)


def detach(image):
    # Cancellation must not prevent cleanup of our own virtual attachment.
    invoke_ps(DETACH, image, NativeWriter(host="win32"), timeout=60)


def inspect_wim(image, writer):
    from .wim import validate_wim_editions

    rows = json.loads(invoke_ps(WIM_INFO, image, writer, timeout=180))
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise NativeWriteError("Invalid Windows image metadata")
    architectures = {
        "9": "amd64",
        "amd64": "amd64",
        "x64": "amd64",
        "12": "arm64",
        "arm64": "arm64",
        "0": "x86",
        "x86": "x86",
    }
    editions = tuple(
        WimEdition(
            int(row["Index"]),
            str(row["Name"]),
            str(row["Description"]),
            str(row["Edition"]),
            architectures.get(str(row["Architecture"]).lower(), ""),
            int(row["Major"]),
            int(row["Minor"]),
            int(row["Build"]),
            int(row["Revision"]),
            int(row["ExpandedBytes"]),
        )
        for row in rows
    )
    validate_wim_editions(editions)
    return tuple(sorted(editions, key=lambda item: item.index))


def inspect_windows_source(source, writer, selected_member=None):
    from .native_extract import extract_iso,snapshot_file
    from .mac_windows_iso import wim_tool
    from .wim import parse_wim_info_xml
    from .windows_bootex import BootExProvenanceError,profile_for_official_iso
    path=Path(source).absolute();before=path_file_identity(path)
    with tempfile.TemporaryDirectory(prefix='isopropyl-inspect-') as directory:
        workspace=Path(directory);snapshot=workspace/'input.iso'
        digest=snapshot_file(path,before,snapshot,writer)
        extract_iso(snapshot,workspace/'files',writer)
        tree=workspace/'files';files=collect_files(tree);index,(loader,machine),install=installer_profile(files,selected_member)
        from .mac_windows_iso import installer_candidates
        candidates,source_count=installer_candidates(files)
        verify_loader(tree/index[loader],machine);member=tree/index[install]
        editions=parse_wim_info_xml(run_tool([wim_tool(),'info',str(member),'--xml'],writer))
        size=member.stat().st_size
    architecture='amd64' if machine==0x8664 else 'arm64'
    try:profile_for_official_iso(before[2],digest,architecture=architecture);supported=True
    except BootExProvenanceError:supported=False
    return WindowsSourceMetadata(before,architecture,index[install].as_posix(),size,editions,digest,supported,candidates,source_count)


def copy_snapshot(source, identity, destination, writer, progress):
    digest = hashlib.sha256()
    done = 0
    with source.open("rb") as original, destination.open("xb") as staged:
        if file_identity(os.fstat(original.fileno())) != identity:
            raise NativeWriteError("The ISO changed after confirmation")
        while done < identity[2]:
            writer.check_cancelled()
            data = original.read(min(BLOCK, identity[2] - done))
            if not data:
                raise NativeWriteError("The ISO ended unexpectedly")
            staged.write(data)
            digest.update(data)
            done += len(data)
            progress("Staging Windows ISO", done, identity[2])
        if (
            original.read(1)
            or file_identity(os.fstat(original.fileno())) != identity
            or path_file_identity(source) != identity
        ):
            raise NativeWriteError("The ISO changed during staging")
    return digest.hexdigest()


def tree_hashes(root, writer, *, ignore_system_entries=False):
    result = {}
    for relative, size in collect_files(
        root, ignore_system_entries=ignore_system_entries
    ):
        writer.check_cancelled()
        digest = hashlib.sha256()
        with (root / relative).open("rb") as source:
            while data := source.read(BLOCK):
                writer.check_cancelled()
                digest.update(data)
        result[relative.as_posix().casefold()] = (size, digest.hexdigest())
    return result


def strip_fixed_vhd(source, destination, writer, progress):
    # Fixed VHD is raw disk bytes followed by one checksummed 512-byte footer.
    with source.open("rb") as disk:
        disk.seek(-512, os.SEEK_END)
        footer = disk.read(512)
        if (
            len(footer) != 512
            or footer[:8] != b"conectix"
            or struct.unpack_from(">I", footer, 60)[0] != 2
        ):
            raise NativeWriteError("The private image is not a fixed VHD")
        expected = struct.unpack_from(">I", footer, 64)[0]
        check = bytearray(footer)
        check[64:68] = bytes(4)
        size = struct.unpack_from(">Q", footer, 48)[0]
        if (
            ((~sum(check)) & 0xFFFFFFFF) != expected
            or source.stat().st_size != size + 512
            or size % 512
        ):
            raise NativeWriteError("The private VHD size or checksum is invalid")
        disk.seek(0)
        done = 0
        with destination.open("xb") as output:
            while done < size:
                writer.check_cancelled()
                data = disk.read(min(BLOCK, size - done))
                if not data:
                    raise NativeWriteError(
                        "The private virtual image ended unexpectedly"
                    )
                output.write(data)
                done += len(data)
                progress("Preparing verified USB image", done, size)
    return destination


def prepare_windows_image(plan, workspace, writer, progress=lambda *args: None):
    from .native_media import NativeMediaOptions,build_media_plan,prepare_media_image
    native=build_media_plan(plan.source,plan.target,NativeMediaOptions(mode='iso',customization=plan.customization,bootex=plan.bootex),
        include_fixed=plan.include_fixed,expected_sha256=plan.expected_sha256)
    if native.source_identity!=plan.source_identity:raise NativeWriteError('The ISO changed after confirmation')
    return prepare_media_image(native,workspace,writer,progress)


def run_windows_iso(plan, confirmation, writer, *, progress=lambda *args: None):
    if confirmation != plan.confirmation:
        raise NativeWriteError("The exact erase confirmation was not supplied")
    with tempfile.TemporaryDirectory(prefix="isopropyl-windows-") as directory:
        image = prepare_windows_image(plan, Path(directory), writer, progress)
        raw = build_plan(image, plan.target, include_fixed=plan.include_fixed)
        return writer.run(raw, confirmation, progress=progress)
