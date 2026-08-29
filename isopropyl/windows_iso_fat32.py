from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Witnessed Windows staging tree -> anonymous dual-firmware FAT32 image.

This backend-only composition never creates a named image, mount, loop device,
or block-device handle.  It binds a narrowly admitted Windows x64 write plan to
one complete staged-tree manifest, constructs the image anonymously, installs
the pinned project-authored BIOS loader, and independently re-attests both the
FAT tree and the complete image before returning a byte-stream owner.
"""

import hashlib
import hmac
import json
import os
import re
import fcntl
import stat
import array
import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from .fat_image import FatImageError, RegularFat32Image, inspect_regular_fat32_image
from .iso import (
    BootStrategy,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    RequirementSource,
    Transformation,
    WIM_SPLIT_PART_SIZE,
    WriteMode,
    WritePlan,
)
from .iso_staging import (
    IsoStagingPlan,
    IsoStagingResult,
    IsoStagingSafetyError,
    validate_published_windows_staging,
)
from .private_fat32 import (
    COPY_BLOCK_BYTES,
    AnonymousFat32Image,
    PrivateFat32BuildProfile,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32Plan,
    PrivateFat32State,
    build_windows_private_fat32_plan,
    validate_private_fat32_plan,
)
from .staging_tree import (
    StagingTreeManifest,
)
from .windows_bios_pbr import (
    Fat32BootmgrPbrPlan,
    WindowsBootmgrBiosProfile,
    WindowsBiosPbrError,
    attest_fat32_bootmgr_pbr,
    classify_windows_bootmgr_bios,
    plan_fat32_bootmgr_pbr,
)


_PLAN_PROFILE = "io.github.codebooker.isopropyl/windows-iso-fat32-plan/v1"
_PLAN_WITNESS = object()
_OWNER_WITNESS = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TRANSITIONAL_BLOCKER = (
    "BIOS construction is not enabled; choose UEFI-only or use DD mode."
)
_REQUIRED_PATHS = (
    "bootmgr",
    "boot/bcd",
    "efi/boot/bootx64.efi",
)


class WindowsIsoFat32Error(RuntimeError):
    """A Windows dual-firmware anonymous image could not be proven safe."""


class WindowsIsoFat32Cancelled(WindowsIsoFat32Error):
    """Windows image preparation was cancelled and its image was discarded."""


@dataclass(frozen=True)
class _CompositeReceipt:
    token: object
    plan: object
    iso_plan: object
    staging_result: object
    private_plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class WindowsIsoFat32Plan:
    """One exact final Windows tree and its unconsumable pre-patch image plan."""

    iso_plan: IsoStagingPlan = field(repr=False, compare=False)
    staging_result: IsoStagingResult = field(repr=False, compare=False)
    private_plan: PrivateFat32Plan = field(repr=False)
    source_manifest_sha256: str
    bootmgr_sha256: str
    bcd_sha256: str
    bootx64_sha256: str
    plan_sha256: str
    _receipt: _CompositeReceipt | None = field(
        init=False, default=None, repr=False, compare=False,
    )


@dataclass(frozen=True)
class WindowsIsoFat32Result:
    """Before/after proof for one BIOS-patched dual-firmware image."""

    plan_sha256: str
    private_plan_sha256: str
    pbr_plan_sha256: str
    disk_signature: int
    volume_id: int
    image_size: int
    unpatched_image_sha256: str
    final_image_sha256: str
    source_manifest_sha256: str
    final_fat_manifest_sha256: str
    files_verified: int
    directories_verified: int
    bytes_verified: int


CancelCheck = Callable[[], None]
Progress = Callable[[str, str, int, int], None]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _write_plan_signature(plan: WritePlan) -> tuple[object, ...]:
    layout = plan.layout
    return (
        plan.mode,
        plan.firmware_target,
        layout,
        plan.requirements,
        plan.transformations,
        plan.warnings,
        plan.minimum_content_bytes,
        plan.minimum_target_bytes,
        plan.content_constraints_checked,
        plan.blockers,
    )


def _validate_write_plan(plan: WritePlan, manifest: StagingTreeManifest, image_size: int) -> None:
    if type(plan) is not WritePlan:
        raise WindowsIsoFat32Error("An exact Windows WritePlan is required")
    layout = plan.layout
    if (
        plan.mode is not WriteMode.EXTRACTED_ISO
        or plan.firmware_target is not FirmwareTarget.BOTH
        or layout is None
        or layout.partition_table is not PartitionTable.MBR
        or layout.main_filesystem is not FileSystem.FAT32
        or layout.partition_count != 1
        or layout.boot_partition_filesystem is not None
        or not layout.bios_bootable
        or not layout.uefi_bootable
        or layout.boot_strategy is not BootStrategy.WINDOWS_BOOTMGR_FAT32
        or not layout.main_partition_active
        or not plan.content_constraints_checked
        or plan.blockers not in {(), (_TRANSITIONAL_BLOCKER,)}
        or plan.transformations not in {
            (), (Transformation.SPLIT_WINDOWS_WIM,),
        }
        or type(plan.minimum_content_bytes) is not int
        or plan.minimum_content_bytes <= 0
        or type(plan.minimum_target_bytes) is not int
        or plan.minimum_target_bytes <= 0
        or type(image_size) is not int
        or image_size < plan.minimum_target_bytes
        or (
            plan.transformations != (Transformation.SPLIT_WINDOWS_WIM,)
            and manifest.total_bytes < plan.minimum_content_bytes
        )
    ):
        raise WindowsIsoFat32Error(
            "The write plan is outside the exact Windows BIOS+UEFI FAT32 profile",
        )
    requirements = {item.key: item for item in plan.requirements}
    required_keys = {
        "iso-extractor",
        "partitioner",
        "formatter-fat32",
        "windows-bios-boot-files",
        "isopropyl-windows-bios-loader",
        "efi-removable-loader-x64",
    }
    if not required_keys <= requirements.keys() or len(requirements) != len(plan.requirements):
        raise WindowsIsoFat32Error("The Windows write-plan requirements are incomplete")
    if (
        requirements["windows-bios-boot-files"].source is not RequirementSource.IMAGE
        or requirements["efi-removable-loader-x64"].source is not RequirementSource.IMAGE
        or requirements["isopropyl-windows-bios-loader"].source
        is not RequirementSource.BUNDLED
        or requirements["isopropyl-windows-bios-loader"].version_constraint
        != "project-source-reproducible-v1"
    ):
        raise WindowsIsoFat32Error("The Windows boot dependencies are not source-bound")
    has_splitter = "wim-splitter" in requirements
    if has_splitter != (plan.transformations == (Transformation.SPLIT_WINDOWS_WIM,)):
        raise WindowsIsoFat32Error("The Windows WIM transformation binding is inconsistent")


def _manifest_files(manifest: StagingTreeManifest) -> dict[str, object]:
    files: dict[str, object] = {}
    for item in manifest.files:
        key = item.path.casefold()
        if key in files:
            raise WindowsIsoFat32Error("The final Windows tree has a path collision")
        files[key] = item
    return files


def _required_file_digests(manifest: StagingTreeManifest) -> tuple[str, str, str]:
    files = _manifest_files(manifest)
    digests: list[str] = []
    for path in _REQUIRED_PATHS:
        item = files.get(path)
        if item is None or item.size <= 0 or _SHA256.fullmatch(item.sha256) is None:
            raise WindowsIsoFat32Error(
                f"The final Windows tree lacks non-empty regular file {path!r}",
            )
        digests.append(item.sha256)
    return tuple(digests)  # type: ignore[return-value]


def _validate_bootmgr_payload(manifest: StagingTreeManifest) -> None:
    """Bind the exact modern entry-at-zero ABI exported by the BIOS loader."""

    files = _manifest_files(manifest)
    item = files.get("bootmgr")
    if item is None:
        raise WindowsIsoFat32Error("The final Windows tree has no BOOTMGR")
    root_source = manifest.directories[0].source
    source = item.source
    root_fd = descriptor = -1
    try:
        root_fd = os.open(
            manifest.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        root_status = os.fstat(root_fd)
        before = os.stat(source.parts[-1], dir_fd=root_fd, follow_symlinks=False)
        descriptor = os.open(
            source.parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        opened = os.fstat(descriptor)
        header = _read_exact(descriptor, 0, 6, "BOOTMGR entry stub")
        bootmgr_profile = classify_windows_bootmgr_bios(
            header,
            file_size=source.size,
        )
        after = os.fstat(descriptor)
        rebound = os.stat(source.parts[-1], dir_fd=root_fd, follow_symlinks=False)
    except (OSError, WindowsBiosPbrError) as error:
        raise WindowsIsoFat32Error("Could not inspect the bound BOOTMGR payload") from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
    expected_file = (
        source.device,
        source.inode,
        source.size,
        source.modified_ns,
        source.changed_ns,
        source.link_count,
    )
    if (
        bootmgr_profile is not WindowsBootmgrBiosProfile.MODERN_ENTRY_ZERO
        or expected_file != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_nlink,
        )
        or expected_file != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
            opened.st_ctime_ns, opened.st_nlink,
        )
        or expected_file != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_nlink,
        )
        or expected_file != (
            rebound.st_dev, rebound.st_ino, rebound.st_size, rebound.st_mtime_ns,
            rebound.st_ctime_ns, rebound.st_nlink,
        )
        or (root_source.device, root_source.inode)
        != (root_status.st_dev, root_status.st_ino)
    ):
        raise WindowsIsoFat32Error(
            "BOOTMGR does not match the exact project BIOS loader profile",
        )


def _validate_split_tree(plan: WritePlan, manifest: StagingTreeManifest) -> None:
    files = _manifest_files(manifest)
    if plan.transformations != (Transformation.SPLIT_WINDOWS_WIM,):
        return
    if "sources/install.wim" in files:
        raise WindowsIsoFat32Error("The oversized install.wim survived its planned split")
    parts: list[object] = []
    number = 1
    while True:
        name = "sources/install.swm" if number == 1 else f"sources/install{number}.swm"
        item = files.get(name)
        if item is None:
            break
        parts.append(item)
        number += 1
    if len(parts) < 2 or any(
        item.size <= 0 or item.size > WIM_SPLIT_PART_SIZE for item in parts
    ):
        raise WindowsIsoFat32Error("The final Windows split-WIM sequence is invalid")
    if any(
        key.startswith("sources/install") and key.endswith(".swm")
        and key not in {
            "sources/install.swm",
            *(f"sources/install{index}.swm" for index in range(2, number)),
        }
        for key in files
    ):
        raise WindowsIsoFat32Error("The final Windows split-WIM sequence has a gap")


def _plan_digest(plan: WindowsIsoFat32Plan) -> str:
    try:
        payload = {
            "profile": _PLAN_PROFILE,
            "write_plan": [
                value.value if hasattr(value, "value") else value
                for value in (
                    plan.iso_plan.write_plan.mode,
                    plan.iso_plan.write_plan.firmware_target,
                    plan.iso_plan.write_plan.layout.partition_table,
                    plan.iso_plan.write_plan.layout.main_filesystem,
                    plan.iso_plan.write_plan.layout.boot_strategy,
                )
            ],
            "transformations": [
                item.value for item in plan.iso_plan.write_plan.transformations
            ],
            "blockers": list(plan.iso_plan.write_plan.blockers),
            "minimum_content_bytes": plan.iso_plan.write_plan.minimum_content_bytes,
            "minimum_target_bytes": plan.iso_plan.write_plan.minimum_target_bytes,
            "source_manifest_sha256": plan.source_manifest_sha256,
            "private_plan_sha256": plan.private_plan.plan_sha256,
            "required_files": {
                "bootmgr": plan.bootmgr_sha256,
                "boot/bcd": plan.bcd_sha256,
                "efi/boot/bootx64.efi": plan.bootx64_sha256,
            },
        }
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _snapshot(plan: WindowsIsoFat32Plan) -> tuple[object, ...]:
    return (
        _write_plan_signature(plan.iso_plan.write_plan),
        plan.source_manifest_sha256,
        plan.bootmgr_sha256,
        plan.bcd_sha256,
        plan.bootx64_sha256,
        plan.plan_sha256,
    )


def _validate_relationships(
    plan: WindowsIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    if type(plan) is not WindowsIsoFat32Plan:
        raise WindowsIsoFat32Error("An authentic Windows FAT32 plan is required")
    receipt = plan._receipt
    if (
        type(receipt) is not _CompositeReceipt
        or receipt.token is not _PLAN_WITNESS
        or receipt.plan is not plan
        or receipt.iso_plan is not plan.iso_plan
        or receipt.staging_result is not plan.staging_result
        or receipt.private_plan is not plan.private_plan
        or receipt.snapshot != _snapshot(plan)
    ):
        raise WindowsIsoFat32Error("The Windows FAT32 plan receipt is invalid")
    for digest in (
        plan.source_manifest_sha256,
        plan.bootmgr_sha256,
        plan.bcd_sha256,
        plan.bootx64_sha256,
        plan.plan_sha256,
    ):
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise WindowsIsoFat32Error("A Windows FAT32 plan digest is invalid")
    try:
        manifest = validate_published_windows_staging(
            plan.iso_plan,
            plan.staging_result,
            cancel_check=cancel_check,
        )
        validate_private_fat32_plan(plan.private_plan, cancel_check=cancel_check)
    except (IsoStagingSafetyError, PrivateFat32Error) as error:
        raise WindowsIsoFat32Error(str(error)) from error
    _validate_write_plan(
        plan.iso_plan.write_plan,
        manifest,
        plan.private_plan.geometry.image_size,
    )
    _validate_split_tree(plan.iso_plan.write_plan, manifest)
    _validate_bootmgr_payload(manifest)
    if (
        plan.private_plan.profile is not PrivateFat32BuildProfile.WINDOWS_BOOTMGR
        or manifest.root.as_posix() != plan.private_plan.source_root
        or plan.source_manifest_sha256 != manifest.manifest_sha256
        or manifest.source_directories
        != tuple(item.source for item in plan.private_plan.directories)
        or manifest.source_files
        != tuple(item.source for item in plan.private_plan.files)
        or tuple(item.sha256 for item in manifest.files)
        != tuple(item.sha256 for item in plan.private_plan.files)
        or manifest.total_bytes != plan.private_plan.total_content_bytes
        or _required_file_digests(manifest)
        != (plan.bootmgr_sha256, plan.bcd_sha256, plan.bootx64_sha256)
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise WindowsIsoFat32Error("The Windows staged tree and FAT32 plan disagree")
    _check_cancelled(cancel_check)


def build_windows_iso_fat32_plan(
    iso_plan: IsoStagingPlan,
    staging_result: IsoStagingResult,
    workspace: os.PathLike[str] | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> WindowsIsoFat32Plan:
    """Bind one complete final Windows tree to an anonymous Windows image plan."""

    try:
        source_manifest = validate_published_windows_staging(
            iso_plan,
            staging_result,
            cancel_check=cancel_check,
        )
    except IsoStagingSafetyError as error:
        raise WindowsIsoFat32Error(str(error)) from error
    _validate_write_plan(iso_plan.write_plan, source_manifest, image_size)
    _validate_split_tree(iso_plan.write_plan, source_manifest)
    _validate_bootmgr_payload(source_manifest)
    bootmgr, bcd, bootx64 = _required_file_digests(source_manifest)
    try:
        private_plan = build_windows_private_fat32_plan(
            source_manifest.root,
            workspace,
            image_size=image_size,
            cancel_check=cancel_check,
        )
    except PrivateFat32Error as error:
        raise WindowsIsoFat32Error(str(error)) from error
    candidate = WindowsIsoFat32Plan(
        iso_plan,
        staging_result,
        private_plan,
        source_manifest.manifest_sha256,
        bootmgr,
        bcd,
        bootx64,
        "",
    )
    plan = WindowsIsoFat32Plan(
        candidate.iso_plan,
        candidate.staging_result,
        candidate.private_plan,
        candidate.source_manifest_sha256,
        candidate.bootmgr_sha256,
        candidate.bcd_sha256,
        candidate.bootx64_sha256,
        _plan_digest(candidate),
    )
    object.__setattr__(
        plan,
        "_receipt",
        _CompositeReceipt(
            _PLAN_WITNESS,
            plan,
            iso_plan,
            staging_result,
            private_plan,
            _snapshot(plan),
        ),
    )
    _validate_relationships(plan, cancel_check=cancel_check)
    return plan


def validate_windows_iso_fat32_plan(
    plan: WindowsIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_relationships(plan, cancel_check=cancel_check)


def _read_exact(descriptor: int, offset: int, length: int, label: str) -> bytes:
    result = bytearray()
    while len(result) < length:
        try:
            block = os.pread(descriptor, length - len(result), offset + len(result))
        except InterruptedError:
            continue
        except OSError as error:
            raise WindowsIsoFat32Error(f"Could not read {label}") from error
        if not block:
            raise WindowsIsoFat32Error(f"Could not read {label} completely")
        result.extend(block)
    return bytes(result)


def _image_sha256(
    descriptor: int,
    image_size: int,
    cancel_check: CancelCheck | None,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < image_size:
        _check_cancelled(cancel_check)
        block = _read_exact(
            descriptor,
            offset,
            min(COPY_BLOCK_BYTES, image_size - offset),
            "the complete Windows image",
        )
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _source_and_expected_patched_sha256(
    descriptor: int,
    image_size: int,
    pbr_plan: Fat32BootmgrPbrPlan,
    cancel_check: CancelCheck | None,
) -> tuple[str, str]:
    """Hash the pre-patch image with only the four authorized writes overlaid."""

    extents = sorted(
        (write.offset, write.offset + len(write.data), write.data)
        for write in pbr_plan.writes
    )
    if any(
        start < 0
        or end <= start
        or end > image_size
        or (index and start < extents[index - 1][1])
        for index, (start, end, _data) in enumerate(extents)
    ):
        raise WindowsIsoFat32Error("The BIOS patch extents are invalid")
    source_digest = hashlib.sha256()
    patched_digest = hashlib.sha256()
    offset = 0
    while offset < image_size:
        _check_cancelled(cancel_check)
        length = min(COPY_BLOCK_BYTES, image_size - offset)
        original = _read_exact(descriptor, offset, length, "the source image")
        source_digest.update(original)
        block = bytearray(original)
        block_end = offset + length
        for start, end, data in extents:
            overlap_start = max(offset, start)
            overlap_end = min(block_end, end)
            if overlap_start < overlap_end:
                block[overlap_start - offset:overlap_end - offset] = data[
                    overlap_start - start:overlap_end - start
                ]
        patched_digest.update(block)
        offset = block_end
    return source_digest.hexdigest(), patched_digest.hexdigest()


def _identity(descriptor: int, image_size: int) -> tuple[int, int, int, int, int]:
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise WindowsIsoFat32Error("Could not inspect the anonymous Windows image") from error
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as error:
        raise WindowsIsoFat32Error("Could not inspect the anonymous image flags") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_size != image_size
        or status.st_nlink != 0
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o600
        or flags & os.O_ACCMODE != os.O_RDWR
        or flags & os.O_APPEND
    ):
        raise WindowsIsoFat32Error("The anonymous Windows image identity is unsafe")
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


class PreparedWindowsIsoFat32:
    """Exclusive owner of one patched and independently attested image."""

    __slots__ = ("_image", "_result", "_witness")

    def __init__(
        self,
        image: AnonymousFat32Image,
        result: WindowsIsoFat32Result,
        witness: object,
    ) -> None:
        if (
            witness is not _OWNER_WITNESS
            or type(image) is not AnonymousFat32Image
            or image.state is not PrivateFat32State.PATCHED_ATTESTED
            or type(result) is not WindowsIsoFat32Result
        ):
            raise WindowsIsoFat32Error("Prepared Windows images are executor-owned")
        self._image: AnonymousFat32Image | None = image
        self._result = result
        self._witness = witness

    @property
    def result(self) -> WindowsIsoFat32Result:
        if self._witness is not _OWNER_WITNESS:
            raise WindowsIsoFat32Error("The prepared Windows image owner is invalid")
        return self._result

    def chunks(self, chunk_bytes: int = COPY_BLOCK_BYTES) -> Iterator[bytes]:
        if self._witness is not _OWNER_WITNESS or self._image is None:
            raise WindowsIsoFat32Error("The prepared Windows image is closed")
        return self._image.chunks(chunk_bytes)

    def _duplicate_attested_readonly_descriptor(
        self,
        cancel_check: CancelCheck | None = None,
    ) -> tuple[int, int]:
        """Internal VM-certification bridge; the caller owns the returned fd."""

        if self._witness is not _OWNER_WITNESS or self._image is None:
            raise WindowsIsoFat32Error("The prepared Windows image is closed")
        try:
            descriptor, image_size = self._image._duplicate_attested_readonly_descriptor(
                cancel_check,
            )
        except PrivateFat32Error as error:
            raise WindowsIsoFat32Error(str(error)) from error
        if image_size != self._result.image_size:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise WindowsIsoFat32Error(
                "The prepared image size changed before VM certification",
            )
        return descriptor, image_size

    def _send_to_privileged_helper(
        self,
        channel: socket.socket,
        request_packet: bytes,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        """Transfer one re-attested descriptor without returning it to callers."""

        if self._witness is not _OWNER_WITNESS or self._image is None:
            raise WindowsIsoFat32Error("The prepared Windows image is closed")
        if (
            type(channel) is not socket.socket
            or channel.family != socket.AF_UNIX
            or channel.type & 0xF != socket.SOCK_SEQPACKET
            or type(request_packet) is not bytes
            or not request_packet
            or len(request_packet) > 4_096
        ):
            raise WindowsIsoFat32Error("The privileged helper channel is invalid")
        try:
            descriptor, image_size = self._image._duplicate_attested_descriptor(
                cancel_check,
            )
        except PrivateFat32Error as error:
            raise WindowsIsoFat32Error(str(error)) from error
        try:
            if image_size != self._result.image_size:
                raise WindowsIsoFat32Error(
                    "The prepared image size changed before helper transfer",
                )
            rights = array.array("i", [descriptor])
            try:
                sent = channel.sendmsg(
                    [request_packet],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
            except OSError as error:
                raise WindowsIsoFat32Error(
                    "Could not transfer the anonymous image to the privileged helper",
                ) from error
            if sent != len(request_packet):
                raise WindowsIsoFat32Error(
                    "The privileged helper request was not transferred atomically",
                )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def close(self) -> None:
        image = self._image
        self._image = None
        if image is not None:
            image.close()

    def __enter__(self) -> PreparedWindowsIsoFat32:
        if self._image is None:
            raise WindowsIsoFat32Error("The prepared Windows image is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class WindowsIsoFat32Builder:
    """One-shot build/patch/re-attest executor with MBR activation last."""

    def __init__(self) -> None:
        self._used = False

    def _write_exact(self, descriptor: int, data: bytes, offset: int) -> None:
        written = 0
        while written < len(data):
            try:
                count = os.pwrite(descriptor, data[written:], offset + written)
            except InterruptedError:
                continue
            if type(count) is not int or count <= 0 or count > len(data) - written:
                raise WindowsIsoFat32Error("The BIOS patch write made invalid progress")
            written += count

    def _sync_exact(self, descriptor: int) -> None:
        while True:
            try:
                os.fsync(descriptor)
                return
            except InterruptedError:
                continue

    def execute(
        self,
        plan: WindowsIsoFat32Plan,
        *,
        cancel_check: CancelCheck | None = None,
        progress: Progress = lambda _stage, _path, _done, _total: None,
    ) -> PreparedWindowsIsoFat32:
        if self._used:
            raise WindowsIsoFat32Error("A Windows FAT32 builder can only be used once")
        self._used = True
        _validate_relationships(plan, cancel_check=cancel_check)
        image: AnonymousFat32Image | None = None
        patch_started = False
        try:
            image = PrivateFat32Builder().execute(
                plan.private_plan,
                cancel_check=cancel_check,
                progress=progress,
            )
            if (
                type(image) is not AnonymousFat32Image
                or image.state is not PrivateFat32State.UNPATCHED_ATTESTED
                or image.plan is not plan.private_plan
                or image.inspection.manifest_sha256 != image.result.manifest_sha256
            ):
                raise WindowsIsoFat32Error("The Windows image builder returned an invalid image")
            _check_cancelled(cancel_check)
            descriptor = image._begin_windows_patch()
            patch_started = True
            pbr_plan = plan_fat32_bootmgr_pbr(
                descriptor,
                volume_offset=plan.private_plan.geometry.volume_offset,
                volume_size=plan.private_plan.geometry.volume_size,
            )
            if tuple(write.role for write in pbr_plan.writes) != (
                "stage", "backup-vbr", "primary-vbr", "mbr",
            ):
                raise WindowsIsoFat32Error("The BIOS activation order is invalid")
            before_expected_hash = _identity(
                descriptor,
                plan.private_plan.geometry.image_size,
            )
            source_sha256, expected_final_sha256 = _source_and_expected_patched_sha256(
                descriptor,
                plan.private_plan.geometry.image_size,
                pbr_plan,
                cancel_check,
            )
            after_expected_hash = _identity(
                descriptor,
                plan.private_plan.geometry.image_size,
            )
            if (
                before_expected_hash != after_expected_hash
                or not hmac.compare_digest(source_sha256, image.result.image_sha256)
            ):
                raise WindowsIsoFat32Error(
                    "The source Windows image changed before BIOS patching",
                )
            for write in pbr_plan.writes:
                _check_cancelled(cancel_check)
                before = _read_exact(descriptor, write.offset, len(write.data), write.role)
                if not hmac.compare_digest(hashlib.sha256(before).hexdigest(), write.before_sha256):
                    raise WindowsIsoFat32Error(
                        f"The {write.role} preimage changed before patching",
                    )
                self._write_exact(descriptor, write.data, write.offset)
                if not hmac.compare_digest(
                    _read_exact(descriptor, write.offset, len(write.data), write.role),
                    write.data,
                ):
                    raise WindowsIsoFat32Error(f"The {write.role} write failed read-back")
            self._sync_exact(descriptor)
            _check_cancelled(cancel_check)
            attest_fat32_bootmgr_pbr(descriptor, pbr_plan)
            try:
                final_inspection = inspect_regular_fat32_image(
                    descriptor,
                    cancel_check=cancel_check,
                )
            except FatImageError as error:
                raise WindowsIsoFat32Error(str(error)) from error
            if (
                final_inspection.entries != image.inspection.entries
                or final_inspection.manifest_sha256 != image.inspection.manifest_sha256
                or final_inspection.content_bytes != image.inspection.content_bytes
                or final_inspection.filesystem_offset != image.inspection.filesystem_offset
                or final_inspection.filesystem_size != image.inspection.filesystem_size
                or final_inspection.disk_signature != plan.private_plan.disk_signature
                or final_inspection.volume_id != plan.private_plan.volume_id
                or final_inspection.sectors_per_cluster
                != plan.private_plan.geometry.sectors_per_cluster
                or final_inspection.allocated_clusters != image.inspection.allocated_clusters
                or final_inspection.free_clusters != image.inspection.free_clusters
            ):
                raise WindowsIsoFat32Error("The BIOS patch changed the attested FAT32 tree")
            before_hash = _identity(descriptor, plan.private_plan.geometry.image_size)
            final_sha256 = _image_sha256(
                descriptor,
                plan.private_plan.geometry.image_size,
                cancel_check,
            )
            after_hash = _identity(descriptor, plan.private_plan.geometry.image_size)
            inspected_identity = final_inspection.source_identity
            if (
                before_hash != after_hash
                or after_hash != (
                    inspected_identity.device,
                    inspected_identity.inode,
                    inspected_identity.size,
                    inspected_identity.modified_ns,
                    inspected_identity.changed_ns,
                )
                or hmac.compare_digest(final_sha256, image.result.image_sha256)
                or not hmac.compare_digest(final_sha256, expected_final_sha256)
            ):
                raise WindowsIsoFat32Error("The final Windows image hash is inconsistent")
            image._commit_windows_patch(final_inspection, final_sha256)
            image._end_patch()
            patch_started = False
            result = WindowsIsoFat32Result(
                plan.plan_sha256,
                plan.private_plan.plan_sha256,
                pbr_plan.plan_sha256,
                plan.private_plan.disk_signature,
                plan.private_plan.volume_id,
                plan.private_plan.geometry.image_size,
                image.result.image_sha256,
                final_sha256,
                plan.source_manifest_sha256,
                final_inspection.manifest_sha256,
                image.result.files_verified,
                image.result.directories_verified,
                image.result.bytes_verified,
            )
            owner = PreparedWindowsIsoFat32(image, result, _OWNER_WITNESS)
            image = None
            try:
                progress(
                    "Complete", "", plan.private_plan.total_content_bytes,
                    plan.private_plan.total_content_bytes,
                )
            except Exception:
                pass
            return owner
        except WindowsIsoFat32Cancelled:
            raise
        except BaseException as error:
            if isinstance(error, WindowsIsoFat32Error):
                raise
            if isinstance(error, (PrivateFat32Error, WindowsBiosPbrError, OSError)):
                raise WindowsIsoFat32Error(str(error)) from error
            raise
        finally:
            if image is not None:
                if patch_started:
                    try:
                        image._poison()
                    finally:
                        image._end_patch()
                else:
                    image._poison()


def prepare_windows_iso_fat32(
    plan: WindowsIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
    progress: Progress = lambda _stage, _path, _done, _total: None,
) -> PreparedWindowsIsoFat32:
    """Build and return only the fully patched/re-attested anonymous image."""

    return WindowsIsoFat32Builder().execute(
        plan,
        cancel_check=cancel_check,
        progress=progress,
    )
