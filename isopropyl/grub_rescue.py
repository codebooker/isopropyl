from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exact Rufus-style GRUB 2.14 BIOS rescue media construction.

This profile intentionally creates an empty FAT32 filesystem.  The pinned GRUB
``core.img`` contains filesystem readers but not ``normal.mod``; boot therefore
ends at ``grub rescue>``.  It is not a GRUB menu, an operating-system image, or
a generic installer.  The private image remains unstreamable until the exact
first-stage and core have been installed, made durable, read back, and the
complete FAT tree and image have been independently re-attested.
"""

import array
import fcntl
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from .bootloaders import BoundBootArtifact, BoundBootBundle
from .descriptor_io import (
    DescriptorIoError,
    read_exact_at,
    write_all_at,
)
from .fat_image import FatImageError, inspect_regular_fat32_image
from .private_fat32 import (
    COPY_BLOCK_BYTES,
    PARTITION_START_SECTOR,
    SECTOR_SIZE,
    AnonymousFat32Image,
    PrivateFat32BuildProfile,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32Plan,
    PrivateFat32State,
    build_grub_rescue_private_fat32_plan,
    validate_private_fat32_plan,
)


PROFILE_ID = "io.github.codebooker.isopropyl/grub-2.14-bios-rescue/v1"
RESULT_SEMANTICS = "intentional-rescue-prompt"
GRUB_FAMILY = "grub"
GRUB_VERSION = "2.14"
GRUB_PURPOSE = "blank-bios-rescue-media"
GRUB_LICENSE = "GPL-3.0-or-later"
GRUB_PROVENANCE_URL = (
    "https://github.com/pbatard/rufus/tree/"
    "6d8fbf98305ff37eb531c45cbd6ff44563c53917/res/grub2"
)
BOOT_IMAGE_SIZE = 512
BOOT_IMAGE_SHA256 = "b31c4cf688e8e16ddd177b619c20b049940bab5c675f877a1aa84a15e1e6e2e6"
BOOTSTRAP_SIZE = 432
BOOTSTRAP_SHA256 = "82d8879ed51b42cab56ad071eb3b0d28d60cd83d57f24fe788014a639940e41e"
CORE_OFFSET = SECTOR_SIZE
CORE_SIZE = 42_742
CORE_SHA256 = "9a2c946704017fa8dc4e03a8a58d754d2d1607c2d2cd74f0e2920133f1192809"
CORE_PADDED_SIZE = ((CORE_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
CORE_BLOCKLIST_OFFSET = 0x1F4
CORE_BLOCKLIST = bytes.fromhex("020000000000000053002008")
EMBEDDING_LIMIT = PARTITION_START_SECTOR * SECTOR_SIZE
_PLAN_WITNESS = object()
_OWNER_WITNESS = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class GrubRescueError(RuntimeError):
    """An exact GRUB BIOS rescue image could not be proven safe."""


class GrubRescueCancelled(GrubRescueError):
    """GRUB rescue image preparation was cancelled and discarded."""


@dataclass(frozen=True)
class _PlanReceipt:
    witness: object
    plan: object
    bundle: object
    private_plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class GrubRescuePlan:
    """One closed GRUB bundle bound to one empty private FAT32 plan."""

    bundle: BoundBootBundle = field(repr=False, compare=False)
    private_plan: PrivateFat32Plan = field(repr=False)
    profile: str
    result_semantics: str
    family: str
    version: str
    purpose: str
    license: str
    provenance_url: str
    boot_image_size: int
    boot_image_sha256: str
    bootstrap_size: int
    bootstrap_sha256: str
    core_offset: int
    core_size: int
    core_sha256: str
    core_padded_size: int
    embedding_limit: int
    plan_sha256: str
    _receipt: _PlanReceipt | None = field(
        init=False, default=None, repr=False, compare=False,
    )


@dataclass(frozen=True)
class GrubRescueResult:
    """Before/after proof for one exact rescue-only anonymous image."""

    plan_sha256: str
    private_plan_sha256: str
    profile: str
    result_semantics: str
    image_size: int
    disk_signature: int
    volume_id: int
    boot_image_sha256: str
    bootstrap_sha256: str
    final_mbr_sha256: str
    core_sha256: str
    core_offset: int
    core_size: int
    core_padded_size: int
    embedding_gap_zero_verified: bool
    unpatched_image_sha256: str
    final_image_sha256: str
    final_fat_manifest_sha256: str
    files_verified: int
    directories_verified: int
    bytes_verified: int


CancelCheck = Callable[[], None]
Progress = Callable[[str, str, int, int], None]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _artifact_signature(artifact: BoundBootArtifact) -> tuple[object, ...]:
    return artifact.name, artifact.size, artifact.sha256


def _bundle_signature(bundle: BoundBootBundle) -> tuple[object, ...]:
    return (
        bundle.family,
        bundle.version,
        bundle.purpose,
        bundle.license,
        bundle.provenance_url,
        tuple(_artifact_signature(item) for item in bundle.artifacts),
    )


def _artifact(
    bundle: BoundBootBundle,
    name: str,
    size: int,
    digest: str,
) -> BoundBootArtifact:
    matches = tuple(item for item in bundle.artifacts if item.name == name)
    if len(matches) != 1:
        raise GrubRescueError(f"The GRUB bundle lacks one exact {name}")
    item = matches[0]
    if (
        type(item) is not BoundBootArtifact
        or type(item.data) is not bytes
        or type(item.sha256) is not str
        or item.size != size
        or item.sha256 != digest
        or not hmac.compare_digest(hashlib.sha256(item.data).hexdigest(), digest)
    ):
        raise GrubRescueError(f"The GRUB {name} payload is not the exact catalog artifact")
    return item


def _validate_bundle(bundle: BoundBootBundle) -> tuple[bytes, bytes]:
    if (
        type(bundle) is not BoundBootBundle
        or bundle.family != GRUB_FAMILY
        or bundle.version != GRUB_VERSION
        or bundle.purpose != GRUB_PURPOSE
        or bundle.license != GRUB_LICENSE
        or bundle.provenance_url != GRUB_PROVENANCE_URL
        or type(bundle.artifacts) is not tuple
        or tuple(item.name for item in bundle.artifacts) != ("boot.img", "core.img")
    ):
        raise GrubRescueError("An exact GRUB 2.14 rescue-media bundle is required")
    boot = _artifact(bundle, "boot.img", BOOT_IMAGE_SIZE, BOOT_IMAGE_SHA256).data
    core = _artifact(bundle, "core.img", CORE_SIZE, CORE_SHA256).data
    bootstrap = boot[:BOOTSTRAP_SIZE]
    if (
        len(bootstrap) != BOOTSTRAP_SIZE
        or not hmac.compare_digest(hashlib.sha256(bootstrap).hexdigest(), BOOTSTRAP_SHA256)
        or struct.unpack_from("<Q", bootstrap, 0x5C)[0] != 1
        or bootstrap[0x64] != 0xFF
        or bootstrap[0x66:0x68] != b"\x90\x90"
    ):
        raise GrubRescueError("The GRUB boot image has an unexpected first-stage layout")
    if (
        CORE_BLOCKLIST_OFFSET + len(CORE_BLOCKLIST) > len(core)
        or core[
            CORE_BLOCKLIST_OFFSET:CORE_BLOCKLIST_OFFSET + len(CORE_BLOCKLIST)
        ] != CORE_BLOCKLIST
    ):
        raise GrubRescueError("The GRUB core image has an unexpected diskboot blocklist")
    return boot, core


def _plan_payload(plan: GrubRescuePlan) -> dict[str, object]:
    return {
        "profile": plan.profile,
        "result_semantics": plan.result_semantics,
        "family": plan.family,
        "version": plan.version,
        "purpose": plan.purpose,
        "license": plan.license,
        "provenance_url": plan.provenance_url,
        "bundle": _bundle_signature(plan.bundle),
        "private_plan_sha256": plan.private_plan.plan_sha256,
        "image_size": plan.private_plan.geometry.image_size,
        "disk_signature": plan.private_plan.disk_signature,
        "volume_id": plan.private_plan.volume_id,
        "boot_image_size": plan.boot_image_size,
        "boot_image_sha256": plan.boot_image_sha256,
        "bootstrap_size": plan.bootstrap_size,
        "bootstrap_sha256": plan.bootstrap_sha256,
        "core_offset": plan.core_offset,
        "core_size": plan.core_size,
        "core_sha256": plan.core_sha256,
        "core_padded_size": plan.core_padded_size,
        "embedding_limit": plan.embedding_limit,
    }


def _plan_digest(plan: GrubRescuePlan) -> str:
    return hashlib.sha256(
        json.dumps(
            _plan_payload(plan),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    ).hexdigest()


def _snapshot(plan: GrubRescuePlan) -> tuple[object, ...]:
    return (
        plan.profile,
        plan.result_semantics,
        plan.family,
        plan.version,
        plan.purpose,
        plan.license,
        plan.provenance_url,
        _bundle_signature(plan.bundle),
        plan.private_plan.plan_sha256,
        plan.boot_image_size,
        plan.boot_image_sha256,
        plan.bootstrap_size,
        plan.bootstrap_sha256,
        plan.core_offset,
        plan.core_size,
        plan.core_sha256,
        plan.core_padded_size,
        plan.embedding_limit,
        plan.plan_sha256,
    )


def _validate_relationships(
    plan: GrubRescuePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> tuple[bytes, bytes]:
    if type(plan) is not GrubRescuePlan:
        raise GrubRescueError("An authentic GRUB rescue plan is required")
    receipt = plan._receipt
    if (
        type(receipt) is not _PlanReceipt
        or receipt.witness is not _PLAN_WITNESS
        or receipt.plan is not plan
        or receipt.bundle is not plan.bundle
        or receipt.private_plan is not plan.private_plan
        or receipt.snapshot != _snapshot(plan)
    ):
        raise GrubRescueError("The GRUB rescue plan receipt is invalid")
    boot, core = _validate_bundle(plan.bundle)
    try:
        validate_private_fat32_plan(plan.private_plan, cancel_check=cancel_check)
    except PrivateFat32Error as error:
        raise GrubRescueError(str(error)) from error
    private = plan.private_plan
    if (
        private.profile is not PrivateFat32BuildProfile.GRUB_RESCUE
        or len(private.directories) != 1
        or private.directories[0].source.parts
        or private.files
        or private.total_content_bytes != 0
        or plan.profile != PROFILE_ID
        or plan.result_semantics != RESULT_SEMANTICS
        or plan.family != GRUB_FAMILY
        or plan.version != GRUB_VERSION
        or plan.purpose != GRUB_PURPOSE
        or plan.license != GRUB_LICENSE
        or plan.provenance_url != GRUB_PROVENANCE_URL
        or plan.boot_image_size != BOOT_IMAGE_SIZE
        or plan.boot_image_sha256 != BOOT_IMAGE_SHA256
        or plan.bootstrap_size != BOOTSTRAP_SIZE
        or plan.bootstrap_sha256 != BOOTSTRAP_SHA256
        or plan.core_offset != CORE_OFFSET
        or plan.core_size != CORE_SIZE
        or plan.core_sha256 != CORE_SHA256
        or plan.core_padded_size != CORE_PADDED_SIZE
        or plan.embedding_limit != EMBEDDING_LIMIT
        or CORE_OFFSET + CORE_PADDED_SIZE > EMBEDDING_LIMIT
        or type(plan.plan_sha256) is not str
        or _SHA256.fullmatch(plan.plan_sha256) is None
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise GrubRescueError("The GRUB rescue plan is forged or inconsistent")
    _check_cancelled(cancel_check)
    return boot, core


def build_grub_rescue_plan(
    bundle: BoundBootBundle,
    staging_root: os.PathLike[str] | str,
    workspace: os.PathLike[str] | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> GrubRescuePlan:
    """Bind one exact closed bundle to one empty private MBR/FAT32 image."""

    _validate_bundle(bundle)
    try:
        private_plan = build_grub_rescue_private_fat32_plan(
            staging_root,
            workspace,
            image_size=image_size,
            cancel_check=cancel_check,
        )
    except PrivateFat32Error as error:
        raise GrubRescueError(str(error)) from error
    candidate = GrubRescuePlan(
        bundle=bundle,
        private_plan=private_plan,
        profile=PROFILE_ID,
        result_semantics=RESULT_SEMANTICS,
        family=GRUB_FAMILY,
        version=GRUB_VERSION,
        purpose=GRUB_PURPOSE,
        license=GRUB_LICENSE,
        provenance_url=GRUB_PROVENANCE_URL,
        boot_image_size=BOOT_IMAGE_SIZE,
        boot_image_sha256=BOOT_IMAGE_SHA256,
        bootstrap_size=BOOTSTRAP_SIZE,
        bootstrap_sha256=BOOTSTRAP_SHA256,
        core_offset=CORE_OFFSET,
        core_size=CORE_SIZE,
        core_sha256=CORE_SHA256,
        core_padded_size=CORE_PADDED_SIZE,
        embedding_limit=EMBEDDING_LIMIT,
        plan_sha256="",
    )
    plan = GrubRescuePlan(
        **{**candidate.__dict__, "plan_sha256": _plan_digest(candidate)},
    )
    object.__setattr__(
        plan,
        "_receipt",
        _PlanReceipt(_PLAN_WITNESS, plan, bundle, private_plan, _snapshot(plan)),
    )
    _validate_relationships(plan, cancel_check=cancel_check)
    return plan


def validate_grub_rescue_plan(
    plan: GrubRescuePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_relationships(plan, cancel_check=cancel_check)


def _descriptor_identity(descriptor: int, image_size: int) -> tuple[int, ...]:
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise GrubRescueError("The anonymous GRUB image descriptor was lost") from error
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 0
        or mode != 0o600
        or info.st_size != image_size
    ):
        raise GrubRescueError("The anonymous GRUB image identity is invalid")
    return info.st_dev, info.st_ino, info.st_size, info.st_nlink, mode


def _read_exact(
    descriptor: int,
    offset: int,
    length: int,
    *,
    retry_guard: Callable[[], None],
    cancel_check: CancelCheck | None,
) -> bytes:
    try:
        return read_exact_at(
            descriptor,
            length,
            offset,
            retry_guard=retry_guard,
            cancel_check=cancel_check,
        ).data
    except DescriptorIoError as error:
        raise GrubRescueError(str(error)) from error


def _write_exact(
    descriptor: int,
    offset: int,
    data: bytes,
    *,
    retry_guard: Callable[[], None],
    cancel_check: CancelCheck | None,
) -> None:
    try:
        write_all_at(
            descriptor,
            data,
            offset,
            retry_guard=retry_guard,
            cancel_check=cancel_check,
        )
    except DescriptorIoError as error:
        raise GrubRescueError(str(error)) from error


def _sync_exact(descriptor: int) -> None:
    while True:
        try:
            os.fsync(descriptor)
            return
        except InterruptedError:
            continue
        except OSError as error:
            raise GrubRescueError("The anonymous GRUB image could not be synchronized") from error


def _hash_descriptor(
    descriptor: int,
    image_size: int,
    *,
    retry_guard: Callable[[], None],
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
            retry_guard=retry_guard,
            cancel_check=cancel_check,
        )
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _require_zero_range(
    descriptor: int,
    start: int,
    end: int,
    *,
    retry_guard: Callable[[], None],
    cancel_check: CancelCheck | None,
) -> None:
    if type(start) is not int or type(end) is not int or not 0 <= start <= end:
        raise GrubRescueError("The GRUB embedding range is invalid")
    offset = start
    while offset < end:
        block = _read_exact(
            descriptor,
            offset,
            min(COPY_BLOCK_BYTES, end - offset),
            retry_guard=retry_guard,
            cancel_check=cancel_check,
        )
        if any(block):
            raise GrubRescueError("The GRUB embedding gap is not empty")
        offset += len(block)


def _expected_unpatched_mbr(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", result, 440, plan.disk_signature)
    entry = bytearray(16)
    entry[0] = 0x80
    entry[1:4] = b"\x20\x21\x00"
    entry[4] = 0x0C
    entry[5:8] = b"\xfe\xff\xff"
    struct.pack_into("<I", entry, 8, PARTITION_START_SECTOR)
    struct.pack_into("<I", entry, 12, plan.geometry.partition_sectors)
    result[446:462] = entry
    result[510:512] = b"\x55\xaa"
    return bytes(result)


class PreparedGrubRescueImage:
    """Opaque owner of one fully patched and re-attested rescue image."""

    __slots__ = ("_image", "_plan", "_result", "_witness", "_transferred")

    def __init__(
        self,
        image: AnonymousFat32Image,
        plan: GrubRescuePlan,
        result: GrubRescueResult,
        witness: object,
    ) -> None:
        if (
            witness is not _OWNER_WITNESS
            or type(image) is not AnonymousFat32Image
            or type(plan) is not GrubRescuePlan
            or type(result) is not GrubRescueResult
            or image.state is not PrivateFat32State.PATCHED_ATTESTED
            or image.plan is not plan.private_plan
            or result.plan_sha256 != plan.plan_sha256
        ):
            raise GrubRescueError("The prepared GRUB rescue image is invalid")
        self._image: AnonymousFat32Image | None = image
        self._plan = plan
        self._result = result
        self._witness = witness
        self._transferred = False

    @property
    def plan(self) -> GrubRescuePlan:
        return self._plan

    @property
    def result(self) -> GrubRescueResult:
        return self._result

    @property
    def state(self) -> PrivateFat32State:
        image = self._image
        return (
            PrivateFat32State.CLOSED
            if image is None or self._transferred
            else image.state
        )

    def chunks(self, chunk_bytes: int = COPY_BLOCK_BYTES) -> Iterator[bytes]:
        image = self._image
        if (
            image is None
            or self._witness is not _OWNER_WITNESS
            or self._transferred
        ):
            raise GrubRescueError("The prepared GRUB rescue image is closed")
        return image.chunks(chunk_bytes)

    def _duplicate_attested_descriptor(
        self,
        cancel_check: CancelCheck | None = None,
    ) -> tuple[int, int]:
        image = self._image
        if (
            image is None
            or self._witness is not _OWNER_WITNESS
            or self._transferred
        ):
            raise GrubRescueError("The prepared GRUB rescue image is closed")
        return image._duplicate_attested_descriptor(cancel_check)

    def _send_to_privileged_helper(
        self,
        channel: socket.socket,
        request_packet: bytes,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        """Atomically transfer one re-attested duplicate to the root helper.

        This bridge deliberately keeps the anonymous descriptor inside the
        prepared owner.  Both the request and descriptor remain untrusted to
        the privileged helper, which independently validates their identity,
        layout, and complete digest before requesting a write commit.
        """

        image = self._image
        if (
            image is None
            or self._witness is not _OWNER_WITNESS
            or self._transferred
        ):
            raise GrubRescueError("The prepared GRUB rescue image is closed")
        if (
            type(channel) is not socket.socket
            or channel.family != socket.AF_UNIX
            or channel.type & 0xF != socket.SOCK_SEQPACKET
            or type(request_packet) is not bytes
            or not request_packet
            or len(request_packet) > 4_096
        ):
            raise GrubRescueError("The privileged GRUB helper channel is invalid")
        # Consuming the owner before descriptor duplication makes even an
        # exceptional/ambiguous send attempt one-shot.  Closing remains safe,
        # but no caller can retry or concurrently stream the same image.
        self._transferred = True
        try:
            descriptor, image_size = image._duplicate_attested_descriptor(
                cancel_check,
            )
        except PrivateFat32Error as error:
            raise GrubRescueError(str(error)) from error
        try:
            if image_size != self._result.image_size:
                raise GrubRescueError(
                    "The prepared GRUB rescue image size changed before helper transfer",
                )
            rights = array.array("i", [descriptor])
            try:
                sent = channel.sendmsg(
                    [request_packet],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
            except OSError as error:
                raise GrubRescueError(
                    "Could not transfer the anonymous GRUB rescue image to the "
                    "privileged helper",
                ) from error
            if sent != len(request_packet):
                raise GrubRescueError(
                    "The privileged GRUB helper request was not transferred atomically",
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

    def __enter__(self) -> PreparedGrubRescueImage:
        if self._image is None:
            raise GrubRescueError("The prepared GRUB rescue image is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class GrubRescueBuilder:
    """One-shot exact core-first, MBR-last anonymous-image executor."""

    def __init__(self) -> None:
        self._used = False

    def execute(
        self,
        plan: GrubRescuePlan,
        *,
        cancel_check: CancelCheck | None = None,
        progress: Progress = lambda _stage, _path, _done, _total: None,
    ) -> PreparedGrubRescueImage:
        if self._used:
            raise GrubRescueError("A GRUB rescue builder can only be used once")
        self._used = True
        boot, core = _validate_relationships(plan, cancel_check=cancel_check)
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
                or image.inspection.entries
                or image.result.files_verified != 0
            ):
                raise GrubRescueError("The private GRUB image builder returned an invalid image")
            descriptor = image._begin_grub_rescue_patch()
            patch_started = True
            image_size = plan.private_plan.geometry.image_size
            identity = _descriptor_identity(descriptor, image_size)

            def retry_guard() -> None:
                _check_cancelled(cancel_check)
                if (
                    image is None
                    or image.state is not PrivateFat32State.PATCHING
                    or image._owned_descriptor() != descriptor
                    or _descriptor_identity(descriptor, image_size) != identity
                ):
                    raise GrubRescueError("The anonymous GRUB image changed before an I/O retry")

            def post_activation_guard() -> None:
                if (
                    image is None
                    or image.state is not PrivateFat32State.PATCHING
                    or image._owned_descriptor() != descriptor
                    or _descriptor_identity(descriptor, image_size) != identity
                ):
                    raise GrubRescueError(
                        "The anonymous GRUB image changed during final attestation",
                    )

            source_sha256 = _hash_descriptor(
                descriptor,
                image_size,
                retry_guard=retry_guard,
                cancel_check=cancel_check,
            )
            if not hmac.compare_digest(source_sha256, image.result.image_sha256):
                raise GrubRescueError("The private GRUB image changed before patching")
            source_mbr = _read_exact(
                descriptor,
                0,
                SECTOR_SIZE,
                retry_guard=retry_guard,
                cancel_check=cancel_check,
            )
            expected_unpatched = _expected_unpatched_mbr(plan.private_plan)
            if source_mbr != expected_unpatched or any(source_mbr[:BOOTSTRAP_SIZE]):
                raise GrubRescueError("The private GRUB image has a noncanonical MBR")
            _require_zero_range(
                descriptor,
                CORE_OFFSET,
                EMBEDDING_LIMIT,
                retry_guard=retry_guard,
                cancel_check=cancel_check,
            )
            final_mbr = boot[:BOOTSTRAP_SIZE] + source_mbr[BOOTSTRAP_SIZE:]

            _check_cancelled(cancel_check)
            _write_exact(
                descriptor,
                CORE_OFFSET,
                core,
                retry_guard=retry_guard,
                cancel_check=cancel_check,
            )
            _sync_exact(descriptor)
            if not hmac.compare_digest(
                _read_exact(
                    descriptor,
                    CORE_OFFSET,
                    len(core),
                    retry_guard=retry_guard,
                    cancel_check=cancel_check,
                ),
                core,
            ):
                raise GrubRescueError("The GRUB core write failed read-back")
            _require_zero_range(
                descriptor,
                CORE_OFFSET + len(core),
                EMBEDDING_LIMIT,
                retry_guard=retry_guard,
                cancel_check=cancel_check,
            )

            # Sector-zero activation is intentionally last.  Cancellation after
            # this point is observed only after the complete final attestation.
            _check_cancelled(cancel_check)
            _write_exact(
                descriptor,
                0,
                final_mbr,
                retry_guard=post_activation_guard,
                cancel_check=None,
            )
            _sync_exact(descriptor)
            if not hmac.compare_digest(
                _read_exact(
                    descriptor,
                    0,
                    SECTOR_SIZE,
                    retry_guard=post_activation_guard,
                    cancel_check=None,
                ),
                final_mbr,
            ):
                raise GrubRescueError("The GRUB MBR activation failed read-back")
            if not hmac.compare_digest(
                _read_exact(
                    descriptor,
                    CORE_OFFSET,
                    len(core),
                    retry_guard=post_activation_guard,
                    cancel_check=None,
                ),
                core,
            ):
                raise GrubRescueError("The GRUB core changed after MBR activation")
            _require_zero_range(
                descriptor,
                CORE_OFFSET + len(core),
                EMBEDDING_LIMIT,
                retry_guard=post_activation_guard,
                cancel_check=None,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                final_inspection = inspect_regular_fat32_image(descriptor)
            except FatImageError as error:
                raise GrubRescueError(str(error)) from error
            if (
                final_inspection.entries
                or final_inspection.manifest_sha256 != image.inspection.manifest_sha256
                or final_inspection.content_bytes != 0
                or final_inspection.filesystem_offset != EMBEDDING_LIMIT
                or final_inspection.filesystem_size != plan.private_plan.geometry.volume_size
                or final_inspection.disk_signature != plan.private_plan.disk_signature
                or final_inspection.volume_id != plan.private_plan.volume_id
                or final_inspection.sectors_per_cluster
                != plan.private_plan.geometry.sectors_per_cluster
                or final_inspection.allocated_clusters != image.inspection.allocated_clusters
                or final_inspection.free_clusters != image.inspection.free_clusters
                or (
                    final_inspection.source_identity.device,
                    final_inspection.source_identity.inode,
                    final_inspection.source_identity.size,
                ) != identity[:3]
            ):
                raise GrubRescueError("The GRUB patch changed the attested empty FAT32 tree")
            final_sha256 = _hash_descriptor(
                descriptor,
                image_size,
                retry_guard=post_activation_guard,
                cancel_check=None,
            )
            if hmac.compare_digest(final_sha256, source_sha256):
                raise GrubRescueError("The final GRUB image hash did not change")
            # Once sector zero is active, final read-back is intentionally
            # non-interruptible.  A late request is honored only after that
            # proof completes, and still poisons the anonymous image before it
            # can become streamable.
            _check_cancelled(cancel_check)
            image._commit_grub_rescue_patch(final_inspection, final_sha256)
            image._end_patch()
            patch_started = False
            result = GrubRescueResult(
                plan_sha256=plan.plan_sha256,
                private_plan_sha256=plan.private_plan.plan_sha256,
                profile=plan.profile,
                result_semantics=plan.result_semantics,
                image_size=image_size,
                disk_signature=plan.private_plan.disk_signature,
                volume_id=plan.private_plan.volume_id,
                boot_image_sha256=BOOT_IMAGE_SHA256,
                bootstrap_sha256=BOOTSTRAP_SHA256,
                final_mbr_sha256=hashlib.sha256(final_mbr).hexdigest(),
                core_sha256=CORE_SHA256,
                core_offset=CORE_OFFSET,
                core_size=CORE_SIZE,
                core_padded_size=CORE_PADDED_SIZE,
                embedding_gap_zero_verified=True,
                unpatched_image_sha256=source_sha256,
                final_image_sha256=final_sha256,
                final_fat_manifest_sha256=final_inspection.manifest_sha256,
                files_verified=0,
                directories_verified=image.result.directories_verified,
                bytes_verified=0,
            )
            owner = PreparedGrubRescueImage(image, plan, result, _OWNER_WITNESS)
            image = None
            try:
                progress("Complete", "GRUB 2.14 rescue image", image_size, image_size)
            except Exception:
                pass
            return owner
        except GrubRescueCancelled:
            raise
        except BaseException as error:
            if isinstance(error, GrubRescueError):
                raise
            if isinstance(error, (PrivateFat32Error, OSError)):
                raise GrubRescueError(str(error)) from error
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
