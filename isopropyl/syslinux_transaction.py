from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verified Syslinux patching for an anonymous regular-file disk image.

This backend boundary never opens a path, mounts a filesystem, publishes an
image, downloads a payload, or touches a block device.  The caller must supply
an anonymous, unpublished ``0600`` regular file that already contains the exact
unpatched root ``ldlinux.sys`` and a supported one-partition MBR/FAT32 layout.

The transaction writes loader bytes first, the backup VBR second, the primary
VBR third, and the MBR activation sector last.  Every phase is made durable and
read back.  A whole-image preimage/postimage digest proves that no byte outside
the witnessed write set changed.  Once mutation starts cancellation is deferred
until verification completes.  Any failure returns no result; the anonymous
image is poisoned and must be closed and discarded rather than rolled back.
"""

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Protocol

from .bootloaders import BoundBootBundle
from .syslinux import SECTOR_SIZE, SyslinuxPatchError, bind_syslinux_bundle, make_empty_adv
from .syslinux_fat import (
    Fat32FileMap,
    Fat32SourceIdentity,
    SyslinuxRegularFilePlan,
    map_root_ldlinux,
    prepare_syslinux_regular_file_plan,
)


MAX_SYSLINUX_REGULAR_IMAGE_BYTES = 128 * 1024**3
_HASH_CHUNK_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_WITNESS = object()


class _DigestSink(Protocol):
    def update(self, data: bytes, /) -> object:
        ...


class SyslinuxTransactionError(RuntimeError):
    """The private regular-file transaction is unsafe or incomplete."""


class SyslinuxTransactionCancelled(SyslinuxTransactionError):
    """The transaction was cancelled before its first mutation."""


class SyslinuxWriteKind(str, Enum):
    LDLINUX = "ldlinux"
    BACKUP_VBR = "backup-vbr"
    PRIMARY_VBR = "primary-vbr"
    MBR = "mbr"


@dataclass(frozen=True)
class SyslinuxBoundWrite:
    kind: SyslinuxWriteKind
    offset: int
    before: bytes
    after: bytes
    before_sha256: str
    after_sha256: str


@dataclass(frozen=True)
class SyslinuxRegularFileTransactionPlan:
    source_identity: Fat32SourceIdentity
    volume_offset: int
    volume_size: int
    file_size: int
    version: str
    config_directory: str
    unpatched_sha256: str
    patched_sha256: str
    first_cluster: int
    clusters: tuple[int, ...]
    sectors: tuple[int, ...]
    backup_boot_sector: int
    writes: tuple[SyslinuxBoundWrite, ...]
    source_image_sha256: str
    expected_image_sha256: str
    plan_sha256: str
    _witness: object = field(default=None, repr=False, compare=True)


@dataclass(frozen=True)
class SyslinuxRegularFileTransactionResult:
    final_identity: Fat32SourceIdentity
    plan_sha256: str
    final_image_sha256: str
    patched_ldlinux_sha256: str
    patched_vbr_sha256: str
    patched_mbr_sha256: str
    sectors: tuple[int, ...]
    bytes_written: int
    writes_verified: int


@dataclass(frozen=True)
class _BuiltTransaction:
    plan: SyslinuxRegularFileTransactionPlan
    regular: SyslinuxRegularFilePlan
    unpatched_file: bytes
    patched_file: bytes


def _check_cancelled(cancel_check: Callable[[], None] | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _source_identity(status: os.stat_result) -> Fat32SourceIdentity:
    return Fat32SourceIdentity(
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _private_descriptor_status(descriptor: int) -> os.stat_result:
    if type(descriptor) is not int or descriptor < 0:
        raise SyslinuxTransactionError("an open anonymous regular-file descriptor is required")
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        status = os.fstat(descriptor)
    except OSError as error:
        raise SyslinuxTransactionError(
            f"could not inspect the anonymous regular-file image: {error}",
        ) from error
    if (
        type(flags) is not int
        or flags & os.O_ACCMODE != os.O_RDWR
        or flags & os.O_APPEND
    ):
        raise SyslinuxTransactionError(
            "the anonymous image must be open O_RDWR without O_APPEND",
        )
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 0
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_size <= 0
        or status.st_size > MAX_SYSLINUX_REGULAR_IMAGE_BYTES
    ):
        raise SyslinuxTransactionError(
            "the target must be an unpublished owner-only anonymous regular-file image",
        )
    return status


def _lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as error:
        raise SyslinuxTransactionError(
            "the anonymous regular-file image is already in use",
        ) from error


def _unlock(descriptor: int, *, poisoned: bool = False) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as error:
        suffix = (
            " The anonymous image is incomplete and must be discarded."
            if poisoned else ""
        )
        raise SyslinuxTransactionError(
            f"could not release the anonymous image transaction lock.{suffix}",
        ) from error


def _read_exact(descriptor: int, offset: int, length: int, label: str) -> bytes:
    if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
        raise SyslinuxTransactionError(f"the {label} read bounds are invalid")
    value = bytearray()
    while len(value) < length:
        try:
            block = os.pread(descriptor, length - len(value), offset + len(value))
        except InterruptedError:
            continue
        except OSError as error:
            raise SyslinuxTransactionError(f"could not read the {label}: {error}") from error
        if not block:
            raise SyslinuxTransactionError(f"could not read the {label} completely")
        value.extend(block)
    return bytes(value)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bound_write(
    kind: SyslinuxWriteKind,
    offset: int,
    before: bytes,
    after: bytes,
) -> SyslinuxBoundWrite:
    if not before or len(before) != len(after):
        raise SyslinuxTransactionError("a planned Syslinux write has inconsistent lengths")
    return SyslinuxBoundWrite(
        kind,
        offset,
        before,
        after,
        _digest(before),
        _digest(after),
    )


def _validate_write_ranges(
    writes: tuple[SyslinuxBoundWrite, ...],
    image_size: int,
) -> tuple[SyslinuxBoundWrite, ...]:
    ordered = tuple(sorted(writes, key=lambda item: item.offset))
    previous_end = 0
    for item in ordered:
        end = item.offset + len(item.after)
        if item.offset < previous_end or item.offset < 0 or end > image_size:
            raise SyslinuxTransactionError(
                "the planned Syslinux write ranges overlap or leave the image",
            )
        previous_end = end
    return ordered


def _feed_region(
    descriptor: int,
    offset: int,
    length: int,
    digests: tuple[_DigestSink, ...],
    cancel_check: Callable[[], None] | None,
) -> None:
    consumed = 0
    while consumed < length:
        _check_cancelled(cancel_check)
        take = min(_HASH_CHUNK_BYTES, length - consumed)
        block = _read_exact(descriptor, offset + consumed, take, "disk-image hash input")
        for target in digests:
            target.update(block)
        consumed += take


def _image_digests(
    descriptor: int,
    image_size: int,
    writes: tuple[SyslinuxBoundWrite, ...],
    cancel_check: Callable[[], None] | None,
) -> tuple[str, str]:
    source = hashlib.sha256()
    expected = hashlib.sha256()
    cursor = 0
    for item in _validate_write_ranges(writes, image_size):
        _feed_region(
            descriptor,
            cursor,
            item.offset - cursor,
            (source, expected),
            cancel_check,
        )
        current = _read_exact(
            descriptor,
            item.offset,
            len(item.before),
            f"{item.kind.value} preimage",
        )
        if not hmac.compare_digest(current, item.before):
            raise SyslinuxTransactionError(
                f"the {item.kind.value} preimage changed while the plan was built",
            )
        source.update(current)
        expected.update(item.after)
        cursor = item.offset + len(item.before)
    _feed_region(
        descriptor,
        cursor,
        image_size - cursor,
        (source, expected),
        cancel_check,
    )
    return source.hexdigest(), expected.hexdigest()


def _plain_image_digest(descriptor: int, image_size: int) -> str:
    result = hashlib.sha256()
    _feed_region(descriptor, 0, image_size, (result,), None)
    return result.hexdigest()


def _plan_digest(plan: SyslinuxRegularFileTransactionPlan) -> str:
    payload = {
        "source_identity": [
            plan.source_identity.device,
            plan.source_identity.inode,
            plan.source_identity.size,
            plan.source_identity.modified_ns,
            plan.source_identity.changed_ns,
        ],
        "volume_offset": plan.volume_offset,
        "volume_size": plan.volume_size,
        "file_size": plan.file_size,
        "version": plan.version,
        "config_directory": plan.config_directory,
        "unpatched_sha256": plan.unpatched_sha256,
        "patched_sha256": plan.patched_sha256,
        "first_cluster": plan.first_cluster,
        "clusters": plan.clusters,
        "sectors": plan.sectors,
        "backup_boot_sector": plan.backup_boot_sector,
        "writes": [
            {
                "kind": item.kind.value,
                "offset": item.offset,
                "size": len(item.before),
                "before_sha256": item.before_sha256,
                "after_sha256": item.after_sha256,
            }
            for item in plan.writes
        ],
        "source_image_sha256": plan.source_image_sha256,
        "expected_image_sha256": plan.expected_image_sha256,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _validate_plan_shape(plan: SyslinuxRegularFileTransactionPlan) -> None:
    if (
        type(plan) is not SyslinuxRegularFileTransactionPlan
        or plan._witness is not _PLAN_WITNESS
    ):
        raise SyslinuxTransactionError("an authentic Syslinux transaction plan is required")
    identity = plan.source_identity
    integer_fields = (
        plan.volume_offset,
        plan.volume_size,
        plan.file_size,
        plan.first_cluster,
        plan.backup_boot_sector,
    )
    digest_fields = (
        plan.unpatched_sha256,
        plan.patched_sha256,
        plan.source_image_sha256,
        plan.expected_image_sha256,
        plan.plan_sha256,
    )
    if (
        type(identity) is not Fat32SourceIdentity
        or any(
            type(value) is not int or value < 0
            for value in (
                identity.device,
                identity.inode,
                identity.size,
                identity.modified_ns,
                identity.changed_ns,
            )
        )
        or any(type(value) is not int or value < 0 for value in integer_fields)
        or plan.volume_size <= 0
        or plan.file_size <= 0
        or type(plan.version) is not str
        or type(plan.config_directory) is not str
        or any(type(value) is not str or _SHA256.fullmatch(value) is None for value in digest_fields)
        or type(plan.clusters) is not tuple
        or type(plan.sectors) is not tuple
        or not plan.clusters
        or not plan.sectors
        or any(type(value) is not int or value <= 0 for value in plan.clusters)
        or any(type(value) is not int or value <= 0 for value in plan.sectors)
        or type(plan.writes) is not tuple
        or any(type(item) is not SyslinuxBoundWrite for item in plan.writes)
    ):
        raise SyslinuxTransactionError("the Syslinux transaction plan fields are invalid")
    expected_kinds = (
        (SyslinuxWriteKind.LDLINUX,) * len(plan.sectors)
        + (
            SyslinuxWriteKind.BACKUP_VBR,
            SyslinuxWriteKind.PRIMARY_VBR,
            SyslinuxWriteKind.MBR,
        )
    )
    if tuple(item.kind for item in plan.writes) != expected_kinds:
        raise SyslinuxTransactionError("the Syslinux transaction write order is invalid")
    for item in plan.writes:
        if (
            type(item.kind) is not SyslinuxWriteKind
            or type(item.offset) is not int
            or item.offset < 0
            or type(item.before) is not bytes
            or type(item.after) is not bytes
            or not item.before
            or len(item.before) != len(item.after)
            or len(item.before) > SECTOR_SIZE
            or type(item.before_sha256) is not str
            or type(item.after_sha256) is not str
            or _SHA256.fullmatch(item.before_sha256) is None
            or _SHA256.fullmatch(item.after_sha256) is None
            or not hmac.compare_digest(_digest(item.before), item.before_sha256)
            or not hmac.compare_digest(_digest(item.after), item.after_sha256)
        ):
            raise SyslinuxTransactionError("a Syslinux transaction write record is invalid")
    loader = plan.writes[:len(plan.sectors)]
    if (
        sum(len(item.before) for item in loader) != plan.file_size
        or _digest(b"".join(item.before for item in loader)) != plan.unpatched_sha256
        or _digest(b"".join(item.after for item in loader)) != plan.patched_sha256
        or tuple(item.offset for item in loader) != tuple(
            plan.volume_offset + sector * SECTOR_SIZE for sector in plan.sectors
        )
        or any(len(item.before) != SECTOR_SIZE for item in loader[:-1])
        or plan.writes[-3].offset
        != plan.volume_offset + plan.backup_boot_sector * SECTOR_SIZE
        or plan.writes[-2].offset != plan.volume_offset
        or plan.writes[-1].offset != 0
        or any(len(item.before) != SECTOR_SIZE for item in plan.writes[-3:])
    ):
        raise SyslinuxTransactionError("the Syslinux transaction write set is inconsistent")
    _validate_write_ranges(plan.writes, identity.size)
    if not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256):
        raise SyslinuxTransactionError("the Syslinux transaction plan digest is invalid")


def _build_writes(
    descriptor: int,
    regular: SyslinuxRegularFilePlan,
    unpatched_file: bytes,
) -> tuple[SyslinuxBoundWrite, ...]:
    mapping = regular.mapping
    patched_file = regular.syslinux.ldlinux_file
    if len(patched_file) != len(unpatched_file):
        raise SyslinuxTransactionError("the patched ldlinux.sys changed length")
    writes: list[SyslinuxBoundWrite] = []
    consumed = 0
    for sector in mapping.sectors:
        take = min(SECTOR_SIZE, len(unpatched_file) - consumed)
        offset = mapping.volume_offset + sector * SECTOR_SIZE
        before = _read_exact(descriptor, offset, take, "unpatched ldlinux.sys")
        expected = unpatched_file[consumed:consumed + take]
        if not hmac.compare_digest(before, expected):
            raise SyslinuxTransactionError("the mapped ldlinux.sys preimage changed")
        writes.append(_bound_write(
            SyslinuxWriteKind.LDLINUX,
            offset,
            before,
            patched_file[consumed:consumed + take],
        ))
        consumed += take
    if consumed != len(unpatched_file):
        raise SyslinuxTransactionError("the mapped ldlinux.sys write set is incomplete")

    backup_offset = (
        mapping.volume_offset + mapping.backup_boot_sector * SECTOR_SIZE
    )
    backup_before = _read_exact(descriptor, backup_offset, SECTOR_SIZE, "backup VBR")
    primary_before = _read_exact(
        descriptor,
        mapping.volume_offset,
        SECTOR_SIZE,
        "primary VBR",
    )
    if backup_before != mapping.boot_sector or primary_before != mapping.boot_sector:
        raise SyslinuxTransactionError("the formatted FAT32 VBR preimages changed")
    writes.extend((
        _bound_write(
            SyslinuxWriteKind.BACKUP_VBR,
            backup_offset,
            backup_before,
            regular.syslinux.boot_sector,
        ),
        _bound_write(
            SyslinuxWriteKind.PRIMARY_VBR,
            mapping.volume_offset,
            primary_before,
            regular.syslinux.boot_sector,
        ),
    ))
    mbr_before = _read_exact(descriptor, 0, SECTOR_SIZE, "formatted MBR")
    writes.append(_bound_write(
        SyslinuxWriteKind.MBR,
        0,
        mbr_before,
        regular.mbr.mbr,
    ))
    return tuple(writes)


def _build_transaction(
    bundle: BoundBootBundle,
    descriptor: int,
    *,
    volume_offset: int,
    volume_size: int,
    config_directory: str,
    expected_unpatched: bytes,
    cancel_check: Callable[[], None] | None,
) -> _BuiltTransaction:
    status = _private_descriptor_status(descriptor)
    payloads = bind_syslinux_bundle(bundle)
    unpatched_file = payloads.ldlinux_sys + make_empty_adv()
    if (
        type(expected_unpatched) is not bytes
        or not hmac.compare_digest(expected_unpatched, unpatched_file)
    ):
        raise SyslinuxTransactionError(
            "the staged root ldlinux.sys does not match the exact payload bundle",
        )
    mapping = map_root_ldlinux(
        descriptor,
        volume_offset=volume_offset,
        volume_size=volume_size,
        expected_file=unpatched_file,
    )
    regular = prepare_syslinux_regular_file_plan(
        bundle,
        descriptor,
        mapping,
        directory=config_directory,
    )
    writes = _build_writes(descriptor, regular, unpatched_file)
    source_sha256, expected_sha256 = _image_digests(
        descriptor,
        status.st_size,
        writes,
        cancel_check,
    )
    candidate = SyslinuxRegularFileTransactionPlan(
        source_identity=regular.mapping.source_identity,
        volume_offset=regular.mapping.volume_offset,
        volume_size=regular.mapping.volume_size,
        file_size=regular.mapping.file_size,
        version=payloads.version,
        config_directory=config_directory,
        unpatched_sha256=_digest(unpatched_file),
        patched_sha256=_digest(regular.syslinux.ldlinux_file),
        first_cluster=regular.mapping.first_cluster,
        clusters=regular.mapping.clusters,
        sectors=regular.mapping.sectors,
        backup_boot_sector=regular.mapping.backup_boot_sector,
        writes=writes,
        source_image_sha256=source_sha256,
        expected_image_sha256=expected_sha256,
        plan_sha256="",
        _witness=_PLAN_WITNESS,
    )
    plan = replace(candidate, plan_sha256=_plan_digest(candidate))
    _validate_plan_shape(plan)
    final_status = _private_descriptor_status(descriptor)
    if _source_identity(final_status) != plan.source_identity:
        raise SyslinuxTransactionError("the anonymous image changed while its plan was built")
    return _BuiltTransaction(
        plan,
        regular,
        unpatched_file,
        regular.syslinux.ldlinux_file,
    )


def _normalized_error(error: BaseException, *, mutated: bool) -> BaseException:
    if isinstance(error, (SyslinuxTransactionError, SyslinuxTransactionCancelled)):
        if not mutated:
            return error
        return SyslinuxTransactionError(
            f"{error} The anonymous image is incomplete and must be discarded.",
        )
    suffix = (
        " The anonymous image is incomplete and must be discarded."
        if mutated else ""
    )
    if isinstance(error, SyslinuxPatchError):
        return SyslinuxTransactionError(f"{error}{suffix}")
    if isinstance(error, OSError):
        return SyslinuxTransactionError(
            f"the Syslinux regular-file transaction failed: {error}{suffix}",
        )
    if mutated and isinstance(error, Exception):
        return SyslinuxTransactionError(
            f"the Syslinux regular-file transaction failed: {error}{suffix}",
        )
    return error


def build_syslinux_regular_file_transaction_plan(
    bundle: BoundBootBundle,
    descriptor: int,
    *,
    volume_offset: int,
    volume_size: int,
    config_directory: str,
    expected_unpatched: bytes,
    cancel_check: Callable[[], None] | None = None,
) -> SyslinuxRegularFileTransactionPlan:
    """Build a witnessed whole-image plan without changing content bytes."""

    _check_cancelled(cancel_check)
    _private_descriptor_status(descriptor)
    _lock(descriptor)
    try:
        os.fsync(descriptor)
        return _build_transaction(
            bundle,
            descriptor,
            volume_offset=volume_offset,
            volume_size=volume_size,
            config_directory=config_directory,
            expected_unpatched=expected_unpatched,
            cancel_check=cancel_check,
        ).plan
    except BaseException as error:
        normalized = _normalized_error(error, mutated=False)
        if normalized is error:
            raise
        raise normalized from error
    finally:
        _unlock(descriptor)


def validate_syslinux_regular_file_transaction_plan(
    plan: SyslinuxRegularFileTransactionPlan,
    bundle: BoundBootBundle,
    descriptor: int,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> None:
    """Rebuild the complete plan from the live anonymous image."""

    locked = False
    try:
        _validate_plan_shape(plan)
        payloads = bind_syslinux_bundle(bundle)
        expected_unpatched = payloads.ldlinux_sys + make_empty_adv()
        _lock(descriptor)
        locked = True
        os.fsync(descriptor)
        rebuilt = _build_transaction(
            bundle,
            descriptor,
            volume_offset=plan.volume_offset,
            volume_size=plan.volume_size,
            config_directory=plan.config_directory,
            expected_unpatched=expected_unpatched,
            cancel_check=cancel_check,
        ).plan
        if rebuilt != plan:
            raise SyslinuxTransactionError(
                "the Syslinux regular-file transaction plan is forged or stale",
            )
    except BaseException as error:
        normalized = _normalized_error(error, mutated=False)
        if normalized is error:
            raise
        raise normalized from error
    finally:
        if locked:
            _unlock(descriptor)


def _same_mapping(
    current: Fat32FileMap,
    original: Fat32FileMap,
    *,
    boot_sector: bytes,
    file_sha256: str,
) -> bool:
    return (
        current.volume_offset == original.volume_offset
        and current.volume_size == original.volume_size
        and current.file_size == original.file_size
        and current.file_sha256 == file_sha256
        and current.first_cluster == original.first_cluster
        and current.clusters == original.clusters
        and current.sectors == original.sectors
        and current.boot_sector == boot_sector
        and current.backup_boot_sector == original.backup_boot_sector
    )


class SyslinuxRegularFileTransaction:
    """Execute one witnessed transaction against its anonymous image fd."""

    def __init__(
        self,
        *,
        write_at: Callable[[int, bytes, int], int] = os.pwrite,
        sync: Callable[[int], None] = os.fsync,
    ) -> None:
        self._write_at = write_at
        self._sync = sync

    def _write_exact(self, descriptor: int, item: SyslinuxBoundWrite) -> None:
        current = _read_exact(
            descriptor,
            item.offset,
            len(item.before),
            f"{item.kind.value} immediate preimage",
        )
        if not hmac.compare_digest(current, item.before):
            raise SyslinuxTransactionError(
                f"the {item.kind.value} preimage changed before its write",
            )
        written = 0
        while written < len(item.after):
            try:
                count = self._write_at(
                    descriptor,
                    item.after[written:],
                    item.offset + written,
                )
            except InterruptedError:
                continue
            if type(count) is not int or count <= 0 or count > len(item.after) - written:
                raise SyslinuxTransactionError(
                    f"the {item.kind.value} write made invalid progress",
                )
            written += count

    @staticmethod
    def _verify_records(descriptor: int, records: tuple[SyslinuxBoundWrite, ...]) -> None:
        for item in records:
            current = _read_exact(
                descriptor,
                item.offset,
                len(item.after),
                f"{item.kind.value} read-back",
            )
            if (
                not hmac.compare_digest(current, item.after)
                or not hmac.compare_digest(_digest(current), item.after_sha256)
            ):
                raise SyslinuxTransactionError(
                    f"the {item.kind.value} write failed exact read-back",
                )

    def _write_phase(
        self,
        descriptor: int,
        records: tuple[SyslinuxBoundWrite, ...],
    ) -> None:
        for item in records:
            self._write_exact(descriptor, item)
        self._sync(descriptor)
        self._verify_records(descriptor, records)

    def execute(
        self,
        plan: SyslinuxRegularFileTransactionPlan,
        bundle: BoundBootBundle,
        descriptor: int,
        *,
        cancel_check: Callable[[], None] | None = None,
    ) -> SyslinuxRegularFileTransactionResult:
        """Patch and completely verify one unpublished anonymous disk image."""

        mutated = False
        locked = False
        try:
            _validate_plan_shape(plan)
            initial_status = _private_descriptor_status(descriptor)
            _lock(descriptor)
            locked = True
            self._sync(descriptor)
            payloads = bind_syslinux_bundle(bundle)
            unpatched = payloads.ldlinux_sys + make_empty_adv()
            built = _build_transaction(
                bundle,
                descriptor,
                volume_offset=plan.volume_offset,
                volume_size=plan.volume_size,
                config_directory=plan.config_directory,
                expected_unpatched=unpatched,
                cancel_check=cancel_check,
            )
            if built.plan != plan:
                raise SyslinuxTransactionError(
                    "the Syslinux regular-file transaction plan is forged or stale",
                )
            current_status = _private_descriptor_status(descriptor)
            if _source_identity(current_status) != _source_identity(initial_status):
                raise SyslinuxTransactionError(
                    "the anonymous image changed immediately before mutation",
                )
            _check_cancelled(cancel_check)

            loader = built.plan.writes[:len(built.plan.sectors)]
            mutated = True
            self._write_phase(descriptor, loader)
            after_loader = map_root_ldlinux(
                descriptor,
                volume_offset=built.plan.volume_offset,
                volume_size=built.plan.volume_size,
                expected_file=built.patched_file,
            )
            if not _same_mapping(
                after_loader,
                built.regular.mapping,
                boot_sector=built.regular.mapping.boot_sector,
                file_sha256=built.plan.patched_sha256,
            ):
                raise SyslinuxTransactionError(
                    "the FAT32 allocation changed after patching ldlinux.sys",
                )

            backup = (built.plan.writes[-3],)
            self._write_phase(descriptor, backup)
            primary = (built.plan.writes[-2],)
            self._write_phase(descriptor, primary)
            after_vbr = map_root_ldlinux(
                descriptor,
                volume_offset=built.plan.volume_offset,
                volume_size=built.plan.volume_size,
                expected_file=built.patched_file,
            )
            if not _same_mapping(
                after_vbr,
                built.regular.mapping,
                boot_sector=built.regular.syslinux.boot_sector,
                file_sha256=built.plan.patched_sha256,
            ):
                raise SyslinuxTransactionError(
                    "the FAT32 allocation changed after patching the VBRs",
                )

            mbr = (built.plan.writes[-1],)
            self._write_phase(descriptor, mbr)
            final_mapping = map_root_ldlinux(
                descriptor,
                volume_offset=built.plan.volume_offset,
                volume_size=built.plan.volume_size,
                expected_file=built.patched_file,
            )
            if not _same_mapping(
                final_mapping,
                built.regular.mapping,
                boot_sector=built.regular.syslinux.boot_sector,
                file_sha256=built.plan.patched_sha256,
            ):
                raise SyslinuxTransactionError(
                    "the final FAT32 allocation no longer matches its plan",
                )
            self._verify_records(descriptor, built.plan.writes)
            pre_hash_status = _private_descriptor_status(descriptor)
            final_digest = _plain_image_digest(
                descriptor,
                built.plan.source_identity.size,
            )
            if not hmac.compare_digest(
                final_digest,
                built.plan.expected_image_sha256,
            ):
                raise SyslinuxTransactionError(
                    "the final disk image changed outside the witnessed write set",
                )
            final_status = _private_descriptor_status(descriptor)
            if (
                _source_identity(pre_hash_status) != _source_identity(final_status)
                or final_status.st_dev != initial_status.st_dev
                or final_status.st_ino != initial_status.st_ino
                or final_status.st_size != initial_status.st_size
            ):
                raise SyslinuxTransactionError(
                    "the anonymous image identity changed during final attestation",
                )
            return SyslinuxRegularFileTransactionResult(
                final_identity=_source_identity(final_status),
                plan_sha256=built.plan.plan_sha256,
                final_image_sha256=final_digest,
                patched_ldlinux_sha256=built.plan.patched_sha256,
                patched_vbr_sha256=_digest(built.regular.syslinux.boot_sector),
                patched_mbr_sha256=_digest(built.regular.mbr.mbr),
                sectors=built.plan.sectors,
                bytes_written=sum(len(item.after) for item in built.plan.writes),
                writes_verified=len(built.plan.writes),
            )
        except BaseException as error:
            normalized = _normalized_error(error, mutated=mutated)
            if normalized is error:
                raise
            raise normalized from error
        finally:
            if locked:
                _unlock(descriptor, poisoned=mutated)
