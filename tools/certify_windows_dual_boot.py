#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Opt-in, device-free Windows BIOS+UEFI certification under QEMU.

The input is a user-owned Windows installer ISO.  This development tool runs
ISOpropyl's strict Windows BOTH planner, private ISO staging, anonymous FAT32
composition, and final re-attestation.  It then boots the exact final bytes
under networkless SeaBIOS and non-Secure-Boot OVMF virtual machines.  TCG is
the portable default; an explicit KVM run is supported when /dev/kvm is
available so a genuine Windows PE boot need not be bounded by emulation speed.

No block-device path is accepted or opened.  QEMU receives the final image
only as an inherited read-only duplicate of ISOpropyl's anonymous O_TMPFILE;
all guest writes go to QEMU's disposable snapshot overlay.  Ephemeral QMP VGA
screendumps are validated and OCR inspected for Windows Setup UI evidence,
hashed for the JSON receipt, and deleted.  Microsoft image bytes and screen
captures are never published by this tool.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

# Direct execution puts tools/ rather than the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.images import ImageMember, inspect_image
from isopropyl.iso import (
    ArchiveEntry,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    WriteMode,
    build_write_plan,
)
from isopropyl.iso_staging import IsoStagingExecutor, build_iso_staging_plan
from isopropyl.windows_iso_fat32 import (
    PreparedWindowsIsoFat32,
    build_windows_iso_fat32_plan,
    prepare_windows_iso_fat32,
)
from tools import certify_freedos_boot as _hardened_qemu


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT = 360
MIN_TIMEOUT = 30
MAX_TIMEOUT = 900
DEFAULT_CAPTURE_INTERVAL = 4
MIN_CAPTURE_INTERVAL = 1
MAX_CAPTURE_INTERVAL = 30
DEFAULT_MEMORY_MIB = 2048
MIN_MEMORY_MIB = 1024
MAX_MEMORY_MIB = 8192
IMAGE_HEADROOM = 512 * 1024 * 1024
MIB = 1024 * 1024
MAX_QMP_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_OCR_BYTES = 64 * 1024
MAX_SCREENSHOT_BYTES = 64 * 1024 * 1024
MAX_SCREEN_DIMENSION = 4096
QMP_COMMAND_TIMEOUT = 15.0
OCR_TIMEOUT = 30.0
DEFAULT_EXECUTABLE_PATH = _hardened_qemu.DEFAULT_EXECUTABLE_PATH
DEFAULT_OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
DEFAULT_OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
WINDOWS_TITLE_MARKERS = (
    "WINDOWS SETUP",
    "WINDOWS 10 SETUP",
    "WINDOWS 11 SETUP",
)
WINDOWS_DETAIL_GROUPS = (
    ("INSTALL NOW",),
    ("LANGUAGE TO INSTALL",),
    ("KEYBOARD OR INPUT METHOD",),
    ("REPAIR YOUR COMPUTER",),
)

BootCertificationError = _hardened_qemu.BootCertificationError
FileIdentity = _hardened_qemu.FileIdentity
QemuIdentity = _hardened_qemu.QemuIdentity
resolve_qemu = _hardened_qemu.resolve_qemu
verify_qemu_unchanged = _hardened_qemu.verify_qemu_unchanged
query_qemu_version = _hardened_qemu.query_qemu_version


@dataclass
class BoundRegularFile:
    path: Path
    fd: int
    identity: FileIdentity
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "BoundRegularFile":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class FrameEvidence:
    firmware: str
    screenshot_sha256: str
    width: int
    height: int
    rgb_unique_sample_count: int
    markers: tuple[str, ...]
    capture_attempts: int
    elapsed_seconds: float


@dataclass(frozen=True)
class PipelineEvidence:
    source_iso_size: int
    source_iso_sha256: str
    volume_label: str
    catalog_members: int
    staging_catalog_sha256: str
    staging_manifest_sha256: str
    composite_plan_sha256: str
    private_plan_sha256: str
    pbr_plan_sha256: str
    final_image_sha256: str
    final_fat_manifest_sha256: str
    image_size: int
    files_verified: int
    directories_verified: int
    bytes_verified: int


def _identity(status: os.stat_result) -> FileIdentity:
    return _hardened_qemu._identity(status)


def _sha256_fd(fd: int, size: int, *, description: str) -> str:
    return _hardened_qemu._sha256_fd(fd, size, description=description)


def _path_identity(path: Path, *, description: str) -> FileIdentity:
    return _hardened_qemu._path_identity(path, description=description)


def _descriptor_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"


def _bind_regular_file(
    path: Path,
    *,
    description: str,
    executable_name: str | None = None,
) -> BoundRegularFile:
    candidate = Path(os.path.abspath(os.fspath(path)))
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        status = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise BootCertificationError(f"Could not bind {description}: {error}") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_size <= 0
        or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or status.st_mode & stat.S_IWOTH
    ):
        os.close(descriptor)
        raise BootCertificationError(
            f"{description} must be a non-set-ID, non-world-writable regular file"
        )
    if executable_name is not None and (
        resolved.name != executable_name or not os.access(resolved, os.X_OK)
    ):
        os.close(descriptor)
        raise BootCertificationError(
            f"{description} must be an executable named {executable_name}"
        )
    identity = _identity(status)
    try:
        digest = _sha256_fd(descriptor, identity.size, description=description)
        if (
            _identity(os.fstat(descriptor)) != identity
            or _path_identity(resolved, description=description) != identity
        ):
            raise BootCertificationError(f"{description} changed while it was bound")
        return BoundRegularFile(resolved, descriptor, identity, digest)
    except BaseException:
        os.close(descriptor)
        raise


def verify_bound_regular_file(bound: BoundRegularFile, *, description: str) -> None:
    if (
        _identity(os.fstat(bound.fd)) != bound.identity
        or _path_identity(bound.path, description=description) != bound.identity
        or _sha256_fd(bound.fd, bound.identity.size, description=description)
        != bound.sha256
        or _identity(os.fstat(bound.fd)) != bound.identity
        or _path_identity(bound.path, description=description) != bound.identity
    ):
        raise BootCertificationError(f"{description} changed during certification")


def resolve_tesseract(path: Path | None = None) -> BoundRegularFile:
    if path is None:
        found = shutil.which("tesseract", path=DEFAULT_EXECUTABLE_PATH)
        if found is None:
            raise BootCertificationError("tesseract is required for VGA evidence")
        path = Path(found)
    elif not path.is_absolute():
        raise BootCertificationError("The Tesseract executable path must be absolute")
    return _bind_regular_file(
        path, description="Tesseract executable", executable_name="tesseract",
    )


def _archive_entries(members: Sequence[ImageMember]) -> tuple[ArchiveEntry, ...]:
    kinds = {
        "file": EntryKind.FILE,
        "directory": EntryKind.DIRECTORY,
        "symlink": EntryKind.SYMLINK,
        "hardlink": EntryKind.HARDLINK,
    }
    return tuple(
        ArchiveEntry(
            member.path,
            member.size,
            kinds.get(member.kind, EntryKind.FILE),
            member.link_target or None,
            member.modified_ns,
        )
        for member in members
    )


def _recommended_image_size(minimum_target: int, staged_bytes: int) -> int:
    if type(minimum_target) is not int or minimum_target <= 0:
        raise BootCertificationError("The Windows target-size bound is invalid")
    if type(staged_bytes) is not int or staged_bytes <= 0:
        raise BootCertificationError("The staged Windows byte count is invalid")
    minimum = max(minimum_target, staged_bytes + IMAGE_HEADROOM)
    return ((minimum + MIB - 1) // MIB) * MIB


def _progress(stage: str, path: str, done: int, total: int) -> None:
    detail = f" ({path})" if path else ""
    rendered = f"{stage}{detail}: {done}/{total}"
    print(rendered[-1024:], file=sys.stderr, flush=True)


def prepare_certification_pipeline(
    iso: BoundRegularFile,
    workspace: Path,
    *,
    image_size: int | None = None,
) -> tuple[PreparedWindowsIsoFat32, PipelineEvidence]:
    """Run the real strict Windows staging and anonymous composition pipeline."""

    expected_iso_identity = (
        iso.identity.device,
        iso.identity.inode,
        iso.identity.size,
        iso.identity.mtime_ns,
        iso.identity.ctime_ns,
    )
    inspection = inspect_image(
        iso.path,
        expected_identity=expected_iso_identity,
    )
    verify_bound_regular_file(iso, description="source Windows ISO")
    if (
        inspection.size != iso.identity.size
        or inspection.kind != "Optical ISO"
        or inspection.is_iso9660 is not True
        or inspection.contents_scanned is not True
        or inspection.has_windows_installer is not True
        or inspection.bootloader != "Windows Boot Manager"
        or inspection.bootloader_identity_ambiguous
        or inspection.architectures != ("x64",)
        or not {"BIOS", "UEFI"}.issubset(inspection.boot_modes)
        or inspection.uefi_analysis_complete is not True
    ):
        raise BootCertificationError(
            "The source is outside the strict x64 Windows BIOS+UEFI installer profile"
        )
    entries = _archive_entries(inspection.members)
    write_plan = build_write_plan(
        inspection,
        entries,
        requested_mode=WriteMode.EXTRACTED_ISO,
        requested_filesystem=FileSystem.FAT32,
        firmware_target=FirmwareTarget.BOTH,
    )
    staging_plan = build_iso_staging_plan(
        iso.path,
        workspace / "staged-media",
        entries,
        write_plan,
    )
    if staging_plan.image_identity != expected_iso_identity:
        raise BootCertificationError(
            "The ISO staging plan belongs to a different source image"
        )
    verify_bound_regular_file(iso, description="source Windows ISO")
    staging_result = IsoStagingExecutor().execute(staging_plan)
    verify_bound_regular_file(iso, description="source Windows ISO")
    manifest = staging_result.tree_manifest
    if manifest is None:
        raise BootCertificationError(
            "The Windows staging result has no authenticated tree manifest"
        )
    final_size = (
        _recommended_image_size(write_plan.minimum_target_bytes, manifest.total_bytes)
        if image_size is None else image_size
    )
    image_workspace = workspace / "anonymous-image-workspace"
    image_workspace.mkdir(mode=0o700)
    composite = build_windows_iso_fat32_plan(
        staging_plan,
        staging_result,
        image_workspace,
        image_size=final_size,
    )
    prepared = prepare_windows_iso_fat32(composite, progress=_progress)
    try:
        result = prepared.result
        evidence = PipelineEvidence(
            iso.identity.size,
            iso.sha256,
            inspection.volume_label,
            len(entries),
            staging_result.catalog_digest,
            manifest.manifest_sha256,
            result.plan_sha256,
            result.private_plan_sha256,
            result.pbr_plan_sha256,
            result.final_image_sha256,
            result.final_fat_manifest_sha256,
            result.image_size,
            result.files_verified,
            result.directories_verified,
            result.bytes_verified,
        )
        return prepared, evidence
    except BaseException:
        prepared.close()
        raise


def _duplicate_prepared_descriptor(prepared: PreparedWindowsIsoFat32) -> int:
    method = getattr(prepared, "_duplicate_attested_readonly_descriptor", None)
    if not callable(method):
        raise BootCertificationError(
            "The Windows image owner does not expose its safe read-only descriptor boundary"
        )
    try:
        descriptor, reported_size = method()
        status = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as error:
        raise BootCertificationError(
            f"Could not duplicate the anonymous Windows image: {error}"
        ) from error
    if (
        type(descriptor) is not int
        or descriptor < 0
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 0
        or reported_size != prepared.result.image_size
        or status.st_size != prepared.result.image_size
        or flags & os.O_ACCMODE != os.O_RDONLY
        or flags & os.O_APPEND
    ):
        os.close(descriptor)
        raise BootCertificationError("The anonymous Windows image duplicate is unsafe")
    return descriptor


def _copy_ovmf_vars(source: BoundRegularFile) -> int:
    if not hasattr(os, "memfd_create"):
        raise BootCertificationError("OVMF certification requires Linux memfd support")
    descriptor = -1
    readonly = -1
    try:
        descriptor = os.memfd_create("isopropyl-ovmf-vars", os.MFD_CLOEXEC)
        offset = 0
        while offset < source.identity.size:
            block = os.pread(source.fd, min(MIB, source.identity.size - offset), offset)
            if not block:
                raise BootCertificationError("The OVMF variable template was truncated")
            consumed = 0
            while consumed < len(block):
                written = os.pwrite(descriptor, block[consumed:], offset + consumed)
                if written <= 0:
                    raise BootCertificationError("Could not copy the OVMF variable template")
                consumed += written
            offset += len(block)
        if os.fstat(descriptor).st_size != source.identity.size:
            raise BootCertificationError("The anonymous OVMF variable store is incomplete")
        if _sha256_fd(descriptor, source.identity.size, description="OVMF variable copy") != source.sha256:
            raise BootCertificationError("The anonymous OVMF variable store changed while copied")
        readonly = os.open(
            _descriptor_path(descriptor), os.O_RDONLY | os.O_CLOEXEC,
        )
        result = readonly
        readonly = -1
        return result
    except BaseException:
        raise
    finally:
        if readonly >= 0:
            os.close(readonly)
        if descriptor >= 0:
            os.close(descriptor)


def build_qemu_command(
    firmware: str,
    qemu_fd: int,
    source_fd: int,
    *,
    acceleration: str = "tcg",
    memory_mib: int = DEFAULT_MEMORY_MIB,
    ovmf_code_fd: int | None = None,
    ovmf_vars_fd: int | None = None,
) -> tuple[str, ...]:
    """Build one fixed networkless snapshot command with no host device path."""

    if firmware not in {"seabios", "ovmf"}:
        raise ValueError("firmware must be 'seabios' or 'ovmf'")
    if acceleration not in {"tcg", "kvm"}:
        raise ValueError("acceleration must be 'tcg' or 'kvm'")
    if type(memory_mib) is not int or not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB:
        raise ValueError(
            f"memory_mib must be from {MIN_MEMORY_MIB} to {MAX_MEMORY_MIB}"
        )
    machine_type = "pc" if firmware == "seabios" else "q35"
    machine = f"{machine_type},accel={acceleration}"
    command = [
        _descriptor_path(qemu_fd),
        "-no-user-config",
        "-sandbox", "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
        "-machine", machine,
        "-cpu", "host" if acceleration == "kvm" else "max",
        "-m", f"{memory_mib}M",
        "-snapshot",
        "-boot", "order=c,strict=on",
        "-add-fd", f"fd={source_fd},set=1,opaque=windows-prepared",
        "-drive",
        "file=/dev/fdset/1,if=ide,index=0,media=disk,format=raw,snapshot=on",
        "-nic", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-display", "none",
        "-qmp", "stdio",
        "-no-reboot",
        "-no-shutdown",
    ]
    if firmware == "ovmf":
        if type(ovmf_code_fd) is not int or type(ovmf_vars_fd) is not int:
            raise ValueError("OVMF firmware descriptors are required")
        command.extend((
            "-add-fd", f"fd={ovmf_code_fd},set=2,opaque=ovmf-code",
            "-add-fd", f"fd={ovmf_vars_fd},set=3,opaque=ovmf-vars",
            "-drive", "if=pflash,unit=0,format=raw,readonly=on,file=/dev/fdset/2",
            "-drive", "if=pflash,unit=1,format=raw,file=/dev/fdset/3,snapshot=on",
        ))
    return tuple(command)


class QmpClient:
    """Minimal bounded newline-delimited QMP client for screendump only."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        limit: int = MAX_QMP_BYTES,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._limit = limit
        self._received = 0
        self._buffer = bytearray()
        self._next_id = 1
        os.set_blocking(reader.fileno(), False)

    def _message(self, deadline: float) -> dict[str, object]:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline]).strip()
                del self._buffer[:newline + 1]
                if not raw:
                    continue
                try:
                    value = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise BootCertificationError("QEMU returned invalid QMP JSON") from error
                if not isinstance(value, dict):
                    raise BootCertificationError("QEMU returned a non-object QMP message")
                return value
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BootCertificationError("QMP response timed out")
            selector = selectors.DefaultSelector()
            try:
                selector.register(self._reader, selectors.EVENT_READ)
                if not selector.select(remaining):
                    raise BootCertificationError("QMP response timed out")
            finally:
                selector.close()
            try:
                block = os.read(self._reader.fileno(), 65_536)
            except BlockingIOError:
                continue
            if not block:
                raise BootCertificationError("QEMU closed QMP unexpectedly")
            self._received += len(block)
            if self._received > self._limit:
                raise BootCertificationError("QEMU produced too much QMP output")
            self._buffer.extend(block)

    def greeting(self) -> None:
        message = self._message(time.monotonic() + QMP_COMMAND_TIMEOUT)
        if "QMP" not in message:
            raise BootCertificationError("QEMU did not provide a QMP greeting")
        self.execute("qmp_capabilities")

    def execute(self, name: str, arguments: dict[str, object] | None = None) -> object:
        command_id = self._next_id
        self._next_id += 1
        payload: dict[str, object] = {"execute": name, "id": command_id}
        if arguments is not None:
            payload["arguments"] = arguments
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\r\n"
        try:
            self._writer.write(encoded)
            self._writer.flush()
        except (OSError, ValueError) as error:
            raise BootCertificationError("Could not send a QMP command") from error
        deadline = time.monotonic() + QMP_COMMAND_TIMEOUT
        while True:
            message = self._message(deadline)
            if message.get("id") != command_id:
                continue
            if "error" in message:
                detail = str(message["error"])[-1024:]
                raise BootCertificationError(f"QMP {name} failed: {detail}")
            if "return" not in message:
                raise BootCertificationError("QMP returned an invalid command response")
            return message["return"]


def _read_ppm(path: Path) -> tuple[bytes, int, int, int]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or not 1 <= status.st_size <= MAX_SCREENSHOT_BYTES:
            raise BootCertificationError("QEMU produced an invalid VGA screendump file")
        data = bytearray()
        offset = 0
        while offset < status.st_size:
            block = os.pread(descriptor, min(MIB, status.st_size - offset), offset)
            if not block:
                raise BootCertificationError("The VGA screendump was truncated")
            data.extend(block)
            offset += len(block)
        if _identity(os.fstat(descriptor)) != _identity(status):
            raise BootCertificationError("The VGA screendump changed while it was read")
    except OSError as error:
        raise BootCertificationError(f"Could not read the VGA screendump: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    match = re.match(rb"P6[ \t\r\n]+(\d+)[ \t\r\n]+(\d+)[ \t\r\n]+255([ \t\r\n])", bytes(data))
    if match is None:
        raise BootCertificationError("QEMU produced an unsupported PPM screendump")
    width, height = int(match.group(1)), int(match.group(2))
    pixels = bytes(data)[match.end():]
    if (
        not 1 <= width <= MAX_SCREEN_DIMENSION
        or not 1 <= height <= MAX_SCREEN_DIMENSION
        or len(pixels) != width * height * 3
    ):
        raise BootCertificationError("QEMU produced invalid PPM dimensions")
    sample_step = max(3, (len(pixels) // 100_000 // 3) * 3)
    colors = {
        pixels[index:index + 3]
        for index in range(0, len(pixels) - 2, sample_step)
    }
    return bytes(data), width, height, len(colors)


def _bounded_subprocess_output(
    command: tuple[str, ...],
    *,
    pass_fds: tuple[int, ...],
    timeout: float,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            env={
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH,
            },
        )
        if process.stdout is None:
            raise BootCertificationError("OCR output pipe was not created")
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BootCertificationError("Tesseract OCR timed out")
            if process.poll() is not None and not selector.get_map():
                break
            for key, _mask in selector.select(min(remaining, 0.1)):
                try:
                    block = os.read(key.fd, 65_536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(block)
                    if len(output) > MAX_OCR_BYTES:
                        raise BootCertificationError("Tesseract produced too much output")
        if process.returncode != 0:
            raise BootCertificationError("Tesseract could not inspect the VGA screendump")
        return bytes(output)
    except OSError as error:
        raise BootCertificationError(f"Could not run Tesseract: {error}") from error
    finally:
        selector.close()
        if process is not None:
            _hardened_qemu._stop_and_reap(process)
            if process.stdout is not None:
                process.stdout.close()


def _ocr_frame(tesseract: BoundRegularFile, screenshot: Path) -> tuple[str, ...]:
    verify_bound_regular_file(tesseract, description="Tesseract executable")
    # Setup's title and its controls occupy separate visual regions.  PSM 6 is
    # reliable for the control block, while PSM 11 is substantially better at
    # the isolated title on OVMF's 1280x800 framebuffer.  Evidence is still
    # admitted only by the same exact title + independent-detail rule below;
    # the second pass improves observation rather than weakening acceptance.
    readings = []
    for page_segmentation_mode in ("6", "11"):
        readings.append(_bounded_subprocess_output(
            (
                _descriptor_path(tesseract.fd),
                str(screenshot),
                "stdout",
                "--psm", page_segmentation_mode,
            ),
            pass_fds=(tesseract.fd,),
            timeout=OCR_TIMEOUT,
        ))
    verify_bound_regular_file(tesseract, description="Tesseract executable")
    text = " ".join(
        b" ".join(readings).decode("utf-8", "replace").upper().split()
    )
    found = tuple(
        marker
        for marker in (
            *WINDOWS_TITLE_MARKERS,
            *(group[0] for group in WINDOWS_DETAIL_GROUPS),
        )
        if marker in text
    )
    return found


def _windows_setup_reached(markers: Sequence[str]) -> bool:
    observed = set(markers)
    return bool(observed.intersection(WINDOWS_TITLE_MARKERS)) and any(
        all(marker in observed for marker in group)
        for group in WINDOWS_DETAIL_GROUPS
    )


def capture_windows_setup(
    firmware: str,
    qemu: QemuIdentity,
    source_fd: int,
    tesseract: BoundRegularFile,
    screenshot_directory: Path,
    *,
    acceleration: str = "tcg",
    timeout: int = DEFAULT_TIMEOUT,
    interval: int = DEFAULT_CAPTURE_INTERVAL,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    ovmf_code_fd: int | None = None,
    ovmf_vars_fd: int | None = None,
) -> FrameEvidence:
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be from {MIN_TIMEOUT} to {MAX_TIMEOUT}")
    if type(interval) is not int or not MIN_CAPTURE_INTERVAL <= interval <= MAX_CAPTURE_INTERVAL:
        raise ValueError(
            f"interval must be from {MIN_CAPTURE_INTERVAL} to {MAX_CAPTURE_INTERVAL}"
        )
    verify_qemu_unchanged(qemu)
    command = build_qemu_command(
        firmware,
        qemu.fd,
        source_fd,
        acceleration=acceleration,
        memory_mib=memory_mib,
        ovmf_code_fd=ovmf_code_fd,
        ovmf_vars_fd=ovmf_vars_fd,
    )
    inherited = [qemu.fd, source_fd]
    if firmware == "ovmf":
        assert ovmf_code_fd is not None and ovmf_vars_fd is not None
        inherited.extend((ovmf_code_fd, ovmf_vars_fd))
    process: subprocess.Popen[bytes] | None = None
    diagnostic = bytearray()
    started = time.monotonic()
    attempts = 0
    last_markers: tuple[str, ...] = ()
    last_frame: tuple[str, int, int, int] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=tuple(inherited),
            start_new_session=True,
            env={
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH, "TZ": "UTC",
            },
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise BootCertificationError("QEMU control pipes were not created")
        qmp = QmpClient(process.stdout, process.stdin)
        qmp.greeting()
        deadline = started + timeout
        next_capture = time.monotonic()
        while time.monotonic() < deadline and process.poll() is None:
            now = time.monotonic()
            if now < next_capture:
                time.sleep(min(next_capture - now, 0.25))
                continue
            attempts += 1
            screenshot = screenshot_directory / f"{firmware}-{attempts}.ppm"
            if os.path.lexists(screenshot):
                raise BootCertificationError("The private screendump path already exists")
            try:
                qmp.execute("screendump", {"filename": str(screenshot)})
                ppm, width, height, unique = _read_ppm(screenshot)
                markers = _ocr_frame(tesseract, screenshot)
                last_markers = markers
                last_frame = (hashlib.sha256(ppm).hexdigest(), width, height, unique)
                if _windows_setup_reached(markers):
                    digest, width, height, unique = last_frame
                    return FrameEvidence(
                        firmware,
                        digest,
                        width,
                        height,
                        unique,
                        markers,
                        attempts,
                        round(time.monotonic() - started, 3),
                    )
            finally:
                try:
                    screenshot.unlink(missing_ok=True)
                except OSError as error:
                    raise BootCertificationError(
                        f"Could not delete the ephemeral VGA screendump: {error}"
                    ) from error
            next_capture = time.monotonic() + interval
        try:
            os.set_blocking(process.stderr.fileno(), False)
            while len(diagnostic) < MAX_DIAGNOSTIC_BYTES:
                block = os.read(
                    process.stderr.fileno(), MAX_DIAGNOSTIC_BYTES - len(diagnostic),
                )
                if not block:
                    break
                diagnostic.extend(block)
        except BlockingIOError:
            pass
        reason = "QEMU exited" if process.poll() is not None else "QEMU timed out"
        details = bytes(diagnostic).decode("utf-8", "replace").strip()[-2048:]
        suffix = f"; diagnostic: {details}" if details else ""
        raise BootCertificationError(
            f"{firmware} {reason} before exact Windows Setup UI evidence; "
            f"last markers={list(last_markers)!r}; frame={last_frame!r}{suffix}"
        )
    except OSError as error:
        raise BootCertificationError(f"Could not run {firmware} QEMU: {error}") from error
    finally:
        if process is not None:
            _hardened_qemu._stop_and_reap(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        verify_qemu_unchanged(qemu)


def _frame_json(frame: FrameEvidence) -> dict[str, object]:
    return {
        "firmware": frame.firmware,
        "markers": list(frame.markers),
        "screenshot_sha256": frame.screenshot_sha256,
        "width": frame.width,
        "height": frame.height,
        "rgb_unique_sample_count": frame.rgb_unique_sample_count,
        "capture_attempts": frame.capture_attempts,
        "elapsed_seconds": frame.elapsed_seconds,
        "screenshot_retained": False,
    }


def certify_windows_dual_boot(
    iso_path: Path,
    *,
    qemu_path: Path | None = None,
    tesseract_path: Path | None = None,
    ovmf_code_path: Path = DEFAULT_OVMF_CODE,
    ovmf_vars_path: Path = DEFAULT_OVMF_VARS,
    workspace_parent: Path | None = None,
    acceleration: str = "tcg",
    timeout: int = DEFAULT_TIMEOUT,
    interval: int = DEFAULT_CAPTURE_INTERVAL,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    image_size: int | None = None,
) -> dict[str, object]:
    if os.geteuid() == 0:
        raise BootCertificationError("Windows certification refuses to run as root")
    if acceleration not in {"tcg", "kvm"}:
        raise BootCertificationError("The QEMU accelerator is invalid")
    if acceleration == "kvm" and not os.access(
        "/dev/kvm", os.R_OK | os.W_OK,
    ):
        raise BootCertificationError(
            "KVM acceleration requires read/write access to /dev/kvm"
        )
    parent = (
        Path(os.path.abspath(os.fspath(workspace_parent)))
        if workspace_parent is not None else Path(iso_path).resolve().parent
    )
    with (
        resolve_qemu(qemu_path) as qemu,
        resolve_tesseract(tesseract_path) as tesseract,
        _bind_regular_file(iso_path, description="source Windows ISO") as iso,
        _bind_regular_file(ovmf_code_path, description="OVMF code") as ovmf_code,
        _bind_regular_file(ovmf_vars_path, description="OVMF variable template") as ovmf_vars,
        tempfile.TemporaryDirectory(prefix=".isopropyl-windows-cert-", dir=parent) as temporary,
    ):
        qemu_version = query_qemu_version(qemu)
        workspace = Path(temporary)
        prepared, pipeline = prepare_certification_pipeline(
            iso, workspace, image_size=image_size,
        )
        with prepared:
            source_fd = _duplicate_prepared_descriptor(prepared)
            try:
                before = _sha256_fd(
                    source_fd,
                    pipeline.image_size,
                    description="anonymous prepared Windows image",
                )
                if before != pipeline.final_image_sha256:
                    raise BootCertificationError(
                        "The anonymous Windows image differs from its final attestation"
                    )
                verify_bound_regular_file(iso, description="source Windows ISO")
                seabios = capture_windows_setup(
                    "seabios", qemu, source_fd, tesseract, workspace,
                    acceleration=acceleration,
                    timeout=timeout, interval=interval, memory_mib=memory_mib,
                )
                ovmf_vars_fd = _copy_ovmf_vars(ovmf_vars)
                try:
                    ovmf = capture_windows_setup(
                        "ovmf", qemu, source_fd, tesseract, workspace,
                        acceleration=acceleration,
                        timeout=timeout, interval=interval, memory_mib=memory_mib,
                        ovmf_code_fd=ovmf_code.fd,
                        ovmf_vars_fd=ovmf_vars_fd,
                    )
                finally:
                    os.close(ovmf_vars_fd)
                after = _sha256_fd(
                    source_fd,
                    pipeline.image_size,
                    description="anonymous prepared Windows image",
                )
                if after != before:
                    raise BootCertificationError(
                        "The anonymous Windows image changed during QEMU certification"
                    )
            finally:
                os.close(source_fd)
        verify_bound_regular_file(iso, description="source Windows ISO")
        verify_bound_regular_file(ovmf_code, description="OVMF code")
        verify_bound_regular_file(ovmf_vars, description="OVMF variable template")
        verify_qemu_unchanged(qemu)
        verify_bound_regular_file(tesseract, description="Tesseract executable")
        return {
            "schema_version": SCHEMA_VERSION,
            "certified": True,
            "profile": "windows-x64-fat32-mbr-active-bios-uefi",
            "source": {
                "kind": "user-owned-windows-iso",
                "filename": iso.path.name,
                "size": pipeline.source_iso_size,
                "sha256": pipeline.source_iso_sha256,
                "volume_label": pipeline.volume_label,
                "catalog_members": pipeline.catalog_members,
                "microsoft_bytes_redistributed": False,
            },
            "pipeline": {
                "staging_catalog_sha256": pipeline.staging_catalog_sha256,
                "staging_manifest_sha256": pipeline.staging_manifest_sha256,
                "composite_plan_sha256": pipeline.composite_plan_sha256,
                "private_plan_sha256": pipeline.private_plan_sha256,
                "pbr_plan_sha256": pipeline.pbr_plan_sha256,
                "final_image_sha256": pipeline.final_image_sha256,
                "final_fat_manifest_sha256": pipeline.final_fat_manifest_sha256,
                "image_size": pipeline.image_size,
                "files_verified": pipeline.files_verified,
                "directories_verified": pipeline.directories_verified,
                "bytes_verified": pipeline.bytes_verified,
                "anonymous_image": True,
                "named_image_published": False,
            },
            "firmware_results": [_frame_json(seabios), _frame_json(ovmf)],
            "isolation": {
                "acceleration": acceleration,
                "snapshot": True,
                "source_read_only_descriptor": True,
                "source_anonymous_otmpfile": True,
                "network": "none",
                "attached_host_block_devices": [],
                "unprivileged_process": True,
                "qemu_executable_set_id": False,
                "qemu_seccomp": True,
                "qemu_seccomp_policy": "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
                "secure_boot": False,
            },
            "qemu": {
                "executable": str(qemu.path),
                "sha256": qemu.sha256,
                "version": qemu_version,
            },
            "tesseract": {
                "executable": str(tesseract.path),
                "sha256": tesseract.sha256,
            },
            "ovmf": {
                "code_sha256": ovmf_code.sha256,
                "vars_template_sha256": ovmf_vars.sha256,
                "secure_boot": False,
            },
        }


def _bounded_integer(value: str, minimum: int, maximum: int, label: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from error
    if not minimum <= result <= maximum:
        raise argparse.ArgumentTypeError(f"{label} must be from {minimum} to {maximum}")
    return result


def _timeout(value: str) -> int:
    return _bounded_integer(value, MIN_TIMEOUT, MAX_TIMEOUT, "timeout")


def _interval(value: str) -> int:
    return _bounded_integer(
        value, MIN_CAPTURE_INTERVAL, MAX_CAPTURE_INTERVAL, "capture interval",
    )


def _memory(value: str) -> int:
    return _bounded_integer(value, MIN_MEMORY_MIB, MAX_MEMORY_MIB, "memory")


def _image_size(value: str) -> int:
    return _bounded_integer(value, 64 * MIB, 16 * 1024**4, "image size")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path, help="user-owned x64 Windows installer ISO")
    parser.add_argument(
        "--run",
        action="store_true",
        help="explicitly opt in to private staging and two networkless TCG boots",
    )
    parser.add_argument("--qemu", type=Path, help="absolute qemu-system-x86_64 path")
    parser.add_argument("--tesseract", type=Path, help="absolute tesseract path")
    parser.add_argument("--ovmf-code", type=Path, default=DEFAULT_OVMF_CODE)
    parser.add_argument("--ovmf-vars", type=Path, default=DEFAULT_OVMF_VARS)
    parser.add_argument(
        "--workspace-parent",
        type=Path,
        help="filesystem for private staging and anonymous image (default: ISO directory)",
    )
    parser.add_argument(
        "--accel",
        choices=("tcg", "kvm"),
        default="tcg",
        help="QEMU accelerator (default: tcg; use kvm explicitly when available)",
    )
    parser.add_argument("--timeout", type=_timeout, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--capture-interval", type=_interval, default=DEFAULT_CAPTURE_INTERVAL,
    )
    parser.add_argument("--memory-mib", type=_memory, default=DEFAULT_MEMORY_MIB)
    parser.add_argument(
        "--image-size", type=_image_size,
        help="advanced exact anonymous disk size in bytes; default adds bounded headroom",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.error(
            "certification is opt-in; pass --run to stage the ISO and start QEMU"
        )
    try:
        observation = certify_windows_dual_boot(
            args.iso,
            qemu_path=args.qemu,
            tesseract_path=args.tesseract,
            ovmf_code_path=args.ovmf_code,
            ovmf_vars_path=args.ovmf_vars,
            workspace_parent=args.workspace_parent,
            acceleration=args.accel,
            timeout=args.timeout,
            interval=args.capture_interval,
            memory_mib=args.memory_mib,
            image_size=args.image_size,
        )
    except (BootCertificationError, OSError, ValueError) as error:
        print(f"certification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
