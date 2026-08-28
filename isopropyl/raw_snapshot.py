from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Witnessed regular-file source -> anonymous raw-image snapshot.

The raw writer must not ask a privileged process to reopen a user pathname or
consume a mutable decoder pipe.  This module implements the narrow first
profile: one already selected, uncompressed regular file is copied into a
fully allocated, unlinked ``O_TMPFILE``.  Both the source and the private
workspace are independently rebound before creation, source identity includes
ctime, and the resulting descriptor can cross a helper boundary exactly once.

Target topology is deliberately supplied as input evidence.  This module does
not discover block devices; it only proves that neither the selected source
filesystem nor the private workspace filesystem is one of the caller's
freshly observed target/dependant device numbers.  A privileged consumer must
still derive and enforce the target topology independently.
"""

import array
import fcntl
import hashlib
import hmac
import json
import os
import socket
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


COPY_BYTES = 4 * 1024 * 1024
MAX_RAW_SNAPSHOT_BYTES = 64 * 1024 * 1024 * 1024 * 1024
MAX_REQUEST_PACKET = 4_096
_PLAN_PROFILE = "io.github.codebooker.isopropyl/raw-snapshot-plan/v1"
_PLAN_WITNESS = object()
_OWNER_WITNESS = object()
_SHA256_LENGTH = 64
_SOURCE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_WORKSPACE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class RawSnapshotError(RuntimeError):
    """The selected raw image could not be snapshotted safely."""


class RawSnapshotCancelled(RawSnapshotError):
    """Snapshot preparation was cancelled and the anonymous file discarded."""


class RawSnapshotState(str, Enum):
    READY = "ready"
    TRANSFERRED = "transferred"
    POISONED = "poisoned"
    CLOSED = "closed"


@dataclass(frozen=True)
class RawSourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @property
    def selection_tuple(self) -> tuple[int, int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.size,
            self.modified_ns,
            self.changed_ns,
        )


@dataclass(frozen=True)
class RawWorkspaceIdentity:
    device: int
    inode: int
    owner: int
    mode: int
    changed_ns: int


@dataclass(frozen=True)
class RawSnapshotIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    owner: int
    mode: int
    blocks: int


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class RawSnapshotPlan:
    source_path: str
    source_identity: RawSourceIdentity
    workspace_path: str
    workspace_identity: RawWorkspaceIdentity
    target_device_numbers: frozenset[int]
    image_size: int
    plan_sha256: str
    _authorization: _PlanReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class RawSnapshotResult:
    plan_sha256: str
    source_identity: RawSourceIdentity
    workspace_identity: RawWorkspaceIdentity
    snapshot_identity: RawSnapshotIdentity
    image_size: int
    image_sha256: str
    fully_preallocated: bool


CancelCheck = Callable[[], None]
Progress = Callable[[int, int], None]


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[-2_048:] if rendered else fallback


def _canonical_absolute(value: Path | str, label: str) -> str:
    try:
        rendered = os.fspath(value)
    except TypeError as error:
        raise RawSnapshotError(f"The {label} path is invalid") from error
    if (
        type(rendered) is not str
        or not os.path.isabs(rendered)
        or os.path.normpath(rendered) != rendered
    ):
        raise RawSnapshotError(f"The {label} path must be absolute and canonical")
    try:
        resolved = os.path.realpath(rendered, strict=True)
    except OSError as error:
        raise RawSnapshotError(
            _bounded(error, f"The {label} path is unavailable"),
        ) from error
    if resolved != rendered:
        raise RawSnapshotError(f"The {label} path must not contain symbolic links")
    return rendered


def _source_identity(info: os.stat_result) -> RawSourceIdentity:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or type(info.st_size) is not int
        or not 0 < info.st_size <= MAX_RAW_SNAPSHOT_BYTES
    ):
        raise RawSnapshotError(
            "The selected raw image must be one non-empty regular file with one link",
        )
    return RawSourceIdentity(
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _workspace_identity(info: os.stat_result) -> RawWorkspaceIdentity:
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or mode & 0o700 != 0o700
        or mode & 0o077
    ):
        raise RawSnapshotError(
            "The raw snapshot workspace must be a private 0700 directory owned "
            "by the current user",
        )
    return RawWorkspaceIdentity(
        info.st_dev,
        info.st_ino,
        info.st_uid,
        mode,
        info.st_ctime_ns,
    )


def _source_status_matches(
    info: os.stat_result,
    expected: RawSourceIdentity,
) -> bool:
    try:
        observed = _source_identity(info)
    except RawSnapshotError:
        return False
    return observed == expected


def _open_source(
    source_path: str,
    expected: RawSourceIdentity | None = None,
) -> tuple[int, RawSourceIdentity]:
    descriptor = -1
    try:
        before = os.lstat(source_path)
        descriptor = os.open(source_path, _SOURCE_FLAGS)
        opened = os.fstat(descriptor)
        after = os.lstat(source_path)
        identity = _source_identity(opened)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise RawSnapshotError(
            _bounded(error, "The selected raw image could not be opened safely"),
        ) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    if (
        not _source_status_matches(before, identity)
        or not _source_status_matches(after, identity)
        or (expected is not None and identity != expected)
    ):
        os.close(descriptor)
        raise RawSnapshotError("The selected raw image changed while it was opened")
    return descriptor, identity


def _open_workspace(
    workspace_path: str,
    expected: RawWorkspaceIdentity | None = None,
) -> tuple[int, RawWorkspaceIdentity]:
    descriptor = -1
    try:
        before = os.lstat(workspace_path)
        descriptor = os.open(workspace_path, _WORKSPACE_FLAGS)
        opened = os.fstat(descriptor)
        after = os.lstat(workspace_path)
        identity = _workspace_identity(opened)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise RawSnapshotError(
            _bounded(error, "The private raw snapshot workspace could not be opened"),
        ) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    if (
        not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
        or (expected is not None and identity != expected)
    ):
        os.close(descriptor)
        raise RawSnapshotError("The private raw snapshot workspace changed")
    return descriptor, identity


def _available_bytes(workspace_descriptor: int) -> int:
    try:
        info = os.fstatvfs(workspace_descriptor)
    except OSError as error:
        raise RawSnapshotError("Could not measure private workspace free space") from error
    fragment = info.f_frsize or info.f_bsize
    if (
        type(fragment) is not int
        or fragment <= 0
        or type(info.f_bavail) is not int
        or info.f_bavail < 0
    ):
        raise RawSnapshotError("The private workspace reported invalid free space")
    return fragment * info.f_bavail


def _require_capacity(workspace_descriptor: int, image_size: int) -> None:
    if _available_bytes(workspace_descriptor) < image_size:
        raise RawSnapshotError(
            "The private workspace does not have enough free space for a complete "
            "raw image snapshot",
        )


def _validate_target_device_numbers(value: object) -> frozenset[int]:
    if (
        type(value) is not frozenset
        or not value
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise RawSnapshotError(
            "Fresh target-topology device-number evidence is required",
        )
    return value


def _require_nonresident(
    source: RawSourceIdentity,
    workspace: RawWorkspaceIdentity,
    target_device_numbers: frozenset[int],
) -> None:
    if (
        source.device in target_device_numbers
        or workspace.device in target_device_numbers
    ):
        raise RawSnapshotError(
            "The selected source or private workspace resides on the target topology",
        )


def observe_raw_source(source: Path | str) -> RawSourceIdentity:
    """Safely capture the exact identity used by a later selection receipt."""

    source_path = _canonical_absolute(source, "raw image")
    descriptor, identity = _open_source(source_path)
    os.close(descriptor)
    return identity


def _plan_snapshot(plan: RawSnapshotPlan) -> tuple[object, ...]:
    return (
        plan.source_path,
        plan.source_identity,
        plan.workspace_path,
        plan.workspace_identity,
        plan.target_device_numbers,
        plan.image_size,
        plan.plan_sha256,
    )


def _plan_digest(plan: RawSnapshotPlan) -> str:
    try:
        payload = json.dumps(
            {
                "profile": _PLAN_PROFILE,
                "source_path": plan.source_path,
                "source_identity": plan.source_identity.selection_tuple,
                "workspace_path": plan.workspace_path,
                "workspace_identity": (
                    plan.workspace_identity.device,
                    plan.workspace_identity.inode,
                    plan.workspace_identity.owner,
                    plan.workspace_identity.mode,
                    plan.workspace_identity.changed_ns,
                ),
                "target_device_numbers": sorted(plan.target_device_numbers),
                "image_size": plan.image_size,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(payload).hexdigest()


def build_raw_snapshot_plan(
    source: Path | str,
    workspace: Path | str,
    *,
    expected_source_identity: RawSourceIdentity,
    target_device_numbers: frozenset[int],
) -> RawSnapshotPlan:
    """Bind one selected regular source and private workspace without writing."""

    if type(expected_source_identity) is not RawSourceIdentity:
        raise RawSnapshotError("An exact selected raw-image identity is required")
    topology = _validate_target_device_numbers(target_device_numbers)
    source_path = _canonical_absolute(source, "raw image")
    workspace_path = _canonical_absolute(workspace, "raw snapshot workspace")
    source_descriptor = workspace_descriptor = -1
    try:
        source_descriptor, source_identity = _open_source(
            source_path,
            expected_source_identity,
        )
        workspace_descriptor, workspace_identity = _open_workspace(workspace_path)
        _require_nonresident(source_identity, workspace_identity, topology)
        _require_capacity(workspace_descriptor, source_identity.size)
        if not _source_status_matches(os.fstat(source_descriptor), source_identity):
            raise RawSnapshotError("The selected raw image changed during planning")
        try:
            path_status = os.lstat(source_path)
        except OSError as error:
            raise RawSnapshotError("The selected raw image disappeared during planning") from error
        if not _source_status_matches(path_status, source_identity):
            raise RawSnapshotError("The selected raw image changed during planning")
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if workspace_descriptor >= 0:
            os.close(workspace_descriptor)
    candidate = RawSnapshotPlan(
        source_path,
        source_identity,
        workspace_path,
        workspace_identity,
        topology,
        source_identity.size,
        "",
    )
    plan = RawSnapshotPlan(
        source_path,
        source_identity,
        workspace_path,
        workspace_identity,
        topology,
        source_identity.size,
        _plan_digest(candidate),
    )
    receipt = _PlanReceipt(_PLAN_WITNESS, plan, _plan_snapshot(plan))
    object.__setattr__(plan, "_authorization", receipt)
    return plan


def _validate_plan_shape(plan: RawSnapshotPlan) -> None:
    if type(plan) is not RawSnapshotPlan:
        raise RawSnapshotError("An authentic raw snapshot plan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_WITNESS
        or receipt.plan is not plan
        or receipt.snapshot != _plan_snapshot(plan)
        or type(plan.source_identity) is not RawSourceIdentity
        or type(plan.workspace_identity) is not RawWorkspaceIdentity
        or type(plan.image_size) is not int
        or plan.image_size != plan.source_identity.size
        or not 0 < plan.image_size <= MAX_RAW_SNAPSHOT_BYTES
        or type(plan.plan_sha256) is not str
        or len(plan.plan_sha256) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in plan.plan_sha256)
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise RawSnapshotError("The raw snapshot plan is forged or inconsistent")
    _validate_target_device_numbers(plan.target_device_numbers)
    if (
        _canonical_absolute(plan.source_path, "raw image") != plan.source_path
        or _canonical_absolute(plan.workspace_path, "raw snapshot workspace")
        != plan.workspace_path
    ):
        raise RawSnapshotError("The raw snapshot plan paths changed")


def validate_raw_snapshot_plan(plan: RawSnapshotPlan) -> None:
    """Rebind every live input and repeat nonresidency/free-space checks."""

    _validate_plan_shape(plan)
    source_descriptor = workspace_descriptor = -1
    try:
        source_descriptor, source_identity = _open_source(
            plan.source_path,
            plan.source_identity,
        )
        workspace_descriptor, workspace_identity = _open_workspace(
            plan.workspace_path,
            plan.workspace_identity,
        )
        _require_nonresident(
            source_identity,
            workspace_identity,
            plan.target_device_numbers,
        )
        _require_capacity(workspace_descriptor, plan.image_size)
        if not _source_status_matches(os.fstat(source_descriptor), source_identity):
            raise RawSnapshotError("The selected raw image changed during validation")
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if workspace_descriptor >= 0:
            os.close(workspace_descriptor)


def _snapshot_identity(
    info: os.stat_result,
    expected_size: int,
) -> RawSnapshotIdentity:
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 0
        or info.st_uid != os.geteuid()
        or mode != 0o600
        or info.st_size != expected_size
        or info.st_blocks * 512 < expected_size
    ):
        raise RawSnapshotError(
            "The anonymous raw snapshot is not a fully allocated private regular file",
        )
    return RawSnapshotIdentity(
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        mode,
        info.st_blocks,
    )


def _read_exact(
    descriptor: int,
    offset: int,
    length: int,
    *,
    read_at: Callable[[int, int, int], bytes] = os.pread,
) -> bytes:
    result = bytearray()
    while len(result) < length:
        try:
            block = read_at(
                descriptor,
                length - len(result),
                offset + len(result),
            )
        except InterruptedError:
            continue
        if type(block) is not bytes or not block or len(block) > length - len(result):
            raise RawSnapshotError("A raw snapshot read made invalid progress")
        result.extend(block)
    return bytes(result)


def _hash_descriptor(
    descriptor: int,
    size: int,
    *,
    cancel_check: CancelCheck | None = None,
    read_at: Callable[[int, int, int], bytes] = os.pread,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        if cancel_check is not None:
            cancel_check()
        block = _read_exact(
            descriptor,
            offset,
            min(COPY_BYTES, size - offset),
            read_at=read_at,
        )
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


class PreparedRawSnapshot:
    """Opaque one-shot owner of an attested anonymous raw-image descriptor."""

    __slots__ = (
        "_descriptor",
        "_lifecycle",
        "_result",
        "_state",
        "_witness",
    )

    def __init__(
        self,
        descriptor: int,
        result: RawSnapshotResult,
        witness: object,
    ) -> None:
        if witness is not _OWNER_WITNESS or type(result) is not RawSnapshotResult:
            raise RawSnapshotError("Prepared raw snapshots are builder-owned")
        self._descriptor = descriptor
        self._result = result
        self._lifecycle = threading.RLock()
        self._state = RawSnapshotState.READY
        self._witness = witness

    @property
    def result(self) -> RawSnapshotResult:
        if self._witness is not _OWNER_WITNESS:
            raise RawSnapshotError("The prepared raw snapshot owner is invalid")
        return self._result

    @property
    def state(self) -> RawSnapshotState:
        return self._state

    def _poison_locked(self) -> None:
        if self._descriptor >= 0:
            descriptor = self._descriptor
            self._descriptor = -1
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._state = RawSnapshotState.POISONED

    def _duplicate_for_transfer(
        self,
        cancel_check: CancelCheck | None = None,
    ) -> int:
        """Consume this owner and return one freshly re-attested duplicate."""

        with self._lifecycle:
            if (
                self._witness is not _OWNER_WITNESS
                or self._state is not RawSnapshotState.READY
                or self._descriptor < 0
            ):
                raise RawSnapshotError("The prepared raw snapshot is not transferable")
            duplicate = -1
            try:
                duplicate = os.dup(self._descriptor)
                os.set_inheritable(duplicate, False)
                flags = fcntl.fcntl(duplicate, fcntl.F_GETFL)
                before = _snapshot_identity(
                    os.fstat(duplicate),
                    self._result.image_size,
                )
                digest = _hash_descriptor(
                    duplicate,
                    self._result.image_size,
                    cancel_check=cancel_check,
                )
                after = _snapshot_identity(
                    os.fstat(duplicate),
                    self._result.image_size,
                )
                if (
                    flags & os.O_ACCMODE != os.O_RDWR
                    or flags & os.O_APPEND
                    or before != self._result.snapshot_identity
                    or after != before
                    or not hmac.compare_digest(digest, self._result.image_sha256)
                ):
                    raise RawSnapshotError(
                        "The anonymous raw snapshot changed before helper transfer",
                    )
            except BaseException:
                if duplicate >= 0:
                    os.close(duplicate)
                self._poison_locked()
                raise
            original = self._descriptor
            self._descriptor = -1
            self._state = RawSnapshotState.TRANSFERRED
            try:
                os.close(original)
            except OSError:
                # The successfully duplicated open-file description remains
                # the sole transferable owner.  A close diagnostic must not
                # leak that duplicate or make a consumed owner reusable.
                pass
            return duplicate

    def transfer_to_helper(
        self,
        channel: socket.socket,
        request_packet: bytes,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        """Atomically send one packet and the sole attested descriptor copy."""

        if (
            type(channel) is not socket.socket
            or channel.family != socket.AF_UNIX
            or channel.type & 0xF != socket.SOCK_SEQPACKET
            or type(request_packet) is not bytes
            or not request_packet
            or len(request_packet) > MAX_REQUEST_PACKET
        ):
            raise RawSnapshotError("The privileged helper transfer request is invalid")
        duplicate = self._duplicate_for_transfer(cancel_check)
        try:
            rights = array.array("i", [duplicate])
            sent = channel.sendmsg(
                [request_packet],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            )
            if sent != len(request_packet):
                raise RawSnapshotError(
                    "The privileged helper request was not transferred atomically",
                )
        except BaseException as error:
            with self._lifecycle:
                self._state = RawSnapshotState.POISONED
            if isinstance(error, RawSnapshotError):
                raise
            raise RawSnapshotError(
                "Could not transfer the anonymous raw snapshot to the privileged helper",
            ) from error
        finally:
            try:
                os.close(duplicate)
            except OSError:
                pass

    # Keep parity with the existing helper bridge while the generic runner is
    # introduced; the descriptor remains inaccessible to GUI callers.
    def _send_to_privileged_helper(
        self,
        channel: socket.socket,
        request_packet: bytes,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        self.transfer_to_helper(
            channel,
            request_packet,
            cancel_check=cancel_check,
        )

    def close(self) -> None:
        with self._lifecycle:
            if self._descriptor >= 0:
                descriptor = self._descriptor
                self._descriptor = -1
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            self._state = RawSnapshotState.CLOSED

    def __enter__(self) -> PreparedRawSnapshot:
        with self._lifecycle:
            if self._state is not RawSnapshotState.READY:
                raise RawSnapshotError("The prepared raw snapshot is not ready")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class RawSnapshotOperations:
    pread: Callable[[int, int, int], bytes] = os.pread
    pwrite: Callable[[int, bytes, int], int] = os.pwrite
    preallocate: Callable[[int, int, int], None] = os.posix_fallocate
    fsync: Callable[[int], None] = os.fsync


class RawSnapshotBuilder:
    """One-shot materializer for one authentic :class:`RawSnapshotPlan`."""

    def __init__(self, *, operations: RawSnapshotOperations = RawSnapshotOperations()) -> None:
        if type(operations) is not RawSnapshotOperations:
            raise RawSnapshotError("Raw snapshot operations are invalid")
        self._operations = operations
        self._used = False
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def _check_cancelled(self, external: CancelCheck | None) -> None:
        if self._cancelled.is_set():
            raise RawSnapshotCancelled("Raw snapshot preparation was cancelled")
        if external is not None:
            external()

    def _preallocate_exact(self, descriptor: int, size: int) -> None:
        while True:
            try:
                self._operations.preallocate(descriptor, 0, size)
                return
            except InterruptedError:
                continue

    def _write_exact(self, descriptor: int, data: bytes, offset: int) -> None:
        written = 0
        while written < len(data):
            try:
                count = self._operations.pwrite(
                    descriptor,
                    data[written:],
                    offset + written,
                )
            except InterruptedError:
                continue
            if (
                type(count) is not int
                or count <= 0
                or count > len(data) - written
            ):
                raise RawSnapshotError("The anonymous snapshot write made invalid progress")
            written += count

    def _sync_exact(self, descriptor: int) -> None:
        while True:
            try:
                self._operations.fsync(descriptor)
                return
            except InterruptedError:
                continue

    @staticmethod
    def _open_anonymous(workspace_descriptor: int) -> int:
        if not hasattr(os, "O_TMPFILE"):
            raise RawSnapshotError("This Linux filesystem runtime lacks O_TMPFILE")
        flags = (
            os.O_TMPFILE
            | os.O_EXCL
            | os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            return os.open(
                ".",
                flags,
                0o600,
                dir_fd=workspace_descriptor,
            )
        except OSError as error:
            raise RawSnapshotError(
                _bounded(error, "The workspace cannot create a strict anonymous file"),
            ) from error

    def execute(
        self,
        plan: RawSnapshotPlan,
        *,
        cancel_check: CancelCheck | None = None,
        progress: Progress = lambda _done, _total: None,
    ) -> PreparedRawSnapshot:
        if self._used:
            raise RawSnapshotError("A raw snapshot builder can only be used once")
        self._used = True
        validate_raw_snapshot_plan(plan)
        self._check_cancelled(cancel_check)
        source_descriptor = workspace_descriptor = snapshot_descriptor = -1
        try:
            source_descriptor, source_identity = _open_source(
                plan.source_path,
                plan.source_identity,
            )
            workspace_descriptor, workspace_identity = _open_workspace(
                plan.workspace_path,
                plan.workspace_identity,
            )
            _require_nonresident(
                source_identity,
                workspace_identity,
                plan.target_device_numbers,
            )
            _require_capacity(workspace_descriptor, plan.image_size)
            source_before = os.fstat(source_descriptor)
            if not _source_status_matches(source_before, plan.source_identity):
                raise RawSnapshotError("The selected raw image changed before snapshotting")

            snapshot_descriptor = self._open_anonymous(workspace_descriptor)
            os.fchmod(snapshot_descriptor, 0o600)
            fcntl.flock(snapshot_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._preallocate_exact(snapshot_descriptor, plan.image_size)
            os.ftruncate(snapshot_descriptor, plan.image_size)
            _snapshot_identity(os.fstat(snapshot_descriptor), plan.image_size)
            self._check_cancelled(cancel_check)

            copied = 0
            digest = hashlib.sha256()
            progress(0, plan.image_size)
            while copied < plan.image_size:
                self._check_cancelled(cancel_check)
                wanted = min(COPY_BYTES, plan.image_size - copied)
                block = _read_exact(
                    source_descriptor,
                    copied,
                    wanted,
                    read_at=self._operations.pread,
                )
                # No bytes obtained after a metadata change reach the private
                # snapshot.  ctime makes a same-size/mtime restoration fail.
                if not _source_status_matches(
                    os.fstat(source_descriptor),
                    plan.source_identity,
                ):
                    raise RawSnapshotError("The selected raw image changed while copying")
                self._write_exact(snapshot_descriptor, block, copied)
                digest.update(block)
                copied += len(block)
                progress(copied, plan.image_size)

            try:
                source_path_status = os.lstat(plan.source_path)
                source_after = os.fstat(source_descriptor)
            except OSError as error:
                raise RawSnapshotError("The selected raw image disappeared after copying") from error
            if (
                not _source_status_matches(source_after, plan.source_identity)
                or not _source_status_matches(source_path_status, plan.source_identity)
            ):
                raise RawSnapshotError("The selected raw image changed while copying")
            self._sync_exact(snapshot_descriptor)
            snapshot_before = _snapshot_identity(
                os.fstat(snapshot_descriptor),
                plan.image_size,
            )
            copied_sha256 = digest.hexdigest()
            snapshot_sha256 = _hash_descriptor(
                snapshot_descriptor,
                plan.image_size,
                cancel_check=lambda: self._check_cancelled(cancel_check),
                read_at=self._operations.pread,
            )
            snapshot_after = _snapshot_identity(
                os.fstat(snapshot_descriptor),
                plan.image_size,
            )
            if (
                snapshot_before != snapshot_after
                or not hmac.compare_digest(copied_sha256, snapshot_sha256)
            ):
                raise RawSnapshotError(
                    "The anonymous raw snapshot failed complete read-back attestation",
                )
            if (
                not _source_status_matches(
                    os.fstat(source_descriptor),
                    plan.source_identity,
                )
                or not _source_status_matches(
                    os.lstat(plan.source_path),
                    plan.source_identity,
                )
            ):
                raise RawSnapshotError("The selected raw image changed after snapshotting")
            result = RawSnapshotResult(
                plan.plan_sha256,
                plan.source_identity,
                plan.workspace_identity,
                snapshot_after,
                plan.image_size,
                snapshot_sha256,
                True,
            )
            prepared = PreparedRawSnapshot(
                snapshot_descriptor,
                result,
                _OWNER_WITNESS,
            )
            snapshot_descriptor = -1
            return prepared
        except RawSnapshotCancelled:
            raise
        except BaseException as error:
            if isinstance(error, RawSnapshotError):
                raise
            if isinstance(error, OSError):
                raise RawSnapshotError(
                    _bounded(error, "Raw snapshot preparation failed"),
                ) from error
            raise
        finally:
            if snapshot_descriptor >= 0:
                os.close(snapshot_descriptor)
            if source_descriptor >= 0:
                os.close(source_descriptor)
            if workspace_descriptor >= 0:
                os.close(workspace_descriptor)


def prepare_raw_snapshot(
    plan: RawSnapshotPlan,
    *,
    cancel_check: CancelCheck | None = None,
    progress: Progress = lambda _done, _total: None,
) -> PreparedRawSnapshot:
    """Convenience one-shot preparation entry point."""

    return RawSnapshotBuilder().execute(
        plan,
        cancel_check=cancel_check,
        progress=progress,
    )
