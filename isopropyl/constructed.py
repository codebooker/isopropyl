from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Construct narrowly scoped, verified UEFI removable media.

This backend consumes an already staged directory tree.  It does not extract
archives and does not install or repair bootloaders.  A plan is accepted only
when the tree contains at least one non-empty removable-media UEFI fallback
loader at ``EFI/BOOT/BOOT*.EFI``.  FAT32 is the default; NTFS content copying is
available only to a higher-level plan that supplies a separate UEFI boot path.
No BIOS bootloader installation is implied.
"""

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeVar

from .devices import Device, parse_lsblk, path_is_on_device
from .conflicts import conflict_diagnostic_suffix, unmount_response_is_inactive
from .formatting import (
    Filesystem,
    FormatCancelled,
    FormatExecutor,
    FormatPlan,
    FormattingError,
    PartitionTable,
    create_format_plan,
    resolve_tools as resolve_format_tools,
    validate_device,
)
from .staging_tree import (
    FAT32_MAX_FILE_BYTES,
    MAX_TREE_DEPTH,
    MAX_TREE_ENTRIES,
    StagedDirectory,
    StagedFile,
    StagingTreeSafetyError,
    scan_staging_tree as _scan_staging_tree,
    staged_case_key as _case_key,
    staged_directory_from_stat as _staged_directory_from_stat,
    staged_file_from_stat as _staged_file_from_stat,
    validate_staged_component as _validate_staged_component,
)
from .timestamps import (
    FAT_MTIME_TOLERANCE_NS,
    MAX_PORTABLE_ARCHIVE_MTIME_NS,
    MIN_PORTABLE_ARCHIVE_MTIME_NS,
    NTFS_MTIME_TOLERANCE_NS,
    TimestampPreservationError,
    apply_descriptor_mtime,
)

COPY_BLOCK_BYTES = 4 * 1024 * 1024
MINIMUM_CAPACITY_RESERVE_BYTES = 64 * 1024 * 1024
PARTITION_RESERVE_BYTES = 2 * 1024 * 1024
MAX_ERROR_CHARACTERS = 2048
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = tuple(_TRUSTED_TOOL_PATH.split(":"))
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_FALLBACK_LOADER = re.compile(r"boot[A-Za-z0-9]+\.efi", re.IGNORECASE)
_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
_T = TypeVar("_T")


class ConstructedMediaError(RuntimeError):
    pass


class ConstructedMediaUnavailable(ConstructedMediaError):
    pass


class ConstructedMediaSafetyError(ConstructedMediaError, StagingTreeSafetyError):
    pass


class ConstructedMediaCancelled(ConstructedMediaError):
    pass


def _translate_staging_error(operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except StagingTreeSafetyError as error:
        raise ConstructedMediaSafetyError(str(error)) from error


def _validate_component(component: str, rendered_path: str) -> None:
    _translate_staging_error(
        lambda: _validate_staged_component(component, rendered_path),
    )


def _directory_from_stat(
    parts: tuple[str, ...], info: os.stat_result,
) -> StagedDirectory:
    return _translate_staging_error(
        lambda: _staged_directory_from_stat(parts, info),
    )


def _file_from_stat(parts: tuple[str, ...], info: os.stat_result) -> StagedFile:
    return _translate_staging_error(
        lambda: _staged_file_from_stat(parts, info),
    )


def scan_staging_tree(
    root: Path | str,
    *,
    max_file_bytes: int | None = FAT32_MAX_FILE_BYTES,
) -> tuple[Path, tuple[StagedDirectory, ...], tuple[StagedFile, ...]]:
    return _translate_staging_error(
        lambda: _scan_staging_tree(root, max_file_bytes=max_file_bytes),
    )


@dataclass(frozen=True)
class ConstructedTools:
    udisksctl: str
    findmnt: str
    lsblk: str


@dataclass(frozen=True)
class ConstructedMediaPlan:
    device: Device
    staging_root: Path
    directories: tuple[StagedDirectory, ...]
    files: tuple[StagedFile, ...]
    fallback_loaders: tuple[str, ...]
    total_bytes: int
    required_capacity: int
    partition_table: PartitionTable
    volume_label: str
    filesystem: Filesystem
    format_plan: FormatPlan
    tools: ConstructedTools

    @property
    def uefi_only(self) -> bool:
        return True


@dataclass(frozen=True)
class ConstructedProgress:
    stage: str
    relative_path: str
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 0.0 if self.stage != "Complete" else 1.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class ConstructedMediaResult:
    device_identity: tuple[str, int, str, str, str, str]
    partition: str
    mountpoint: str
    files_copied: int
    bytes_copied: int
    unmounted: bool
    powered_off: bool
    cleanup_diagnostic: str = ""


Progress = Callable[[ConstructedProgress], None]
DeviceLister = Callable[[], Sequence[Device]]
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def _bounded_message(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-MAX_ERROR_CHARACTERS:] if rendered else fallback


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _trusted_tool(name: str, finder: Callable[[str], str | None]) -> str:
    value = finder(name)
    if not value:
        raise ConstructedMediaUnavailable(
            f"{name} is required for constructed-media writing but was not found"
        )
    if not os.path.isabs(value):
        raise ConstructedMediaUnavailable(f"Could not resolve a safe absolute path for {name}")
    normalized = os.path.normpath(value)
    if (
        os.path.dirname(normalized) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(normalized) != name
    ):
        raise ConstructedMediaUnavailable(f"Refusing untrusted {name} path: {value!r}")
    return normalized


def resolve_constructed_tools(
    finder: Callable[[str], str | None] = _trusted_which,
) -> ConstructedTools:
    return ConstructedTools(
        udisksctl=_trusted_tool("udisksctl", finder),
        findmnt=_trusted_tool("findmnt", finder),
        lsblk=_trusted_tool("lsblk", finder),
    )


def _fallback_loaders(files: Sequence[StagedFile]) -> tuple[str, ...]:
    found = [
        item.path for item in files
        if len(item.parts) == 3
        and item.parts[0].casefold() == "efi"
        and item.parts[1].casefold() == "boot"
        and _FALLBACK_LOADER.fullmatch(item.parts[2])
        and item.size > 0
    ]
    if not found:
        raise ConstructedMediaSafetyError(
            "The staged tree has no non-empty EFI/BOOT/BOOT*.EFI fallback loader"
        )
    return tuple(sorted(found, key=str.casefold))


def _required_capacity(
    total_bytes: int, entry_count: int,
) -> int:
    filesystem_overhead = max(
        MINIMUM_CAPACITY_RESERVE_BYTES,
        (total_bytes + 19) // 20 + entry_count * 4096,
    )
    return total_bytes + filesystem_overhead + PARTITION_RESERVE_BYTES


def build_constructed_media_plan(
    staging_root: Path | str,
    device: Device,
    partition_table: PartitionTable,
    *,
    volume_label: str = "ISOPROPYL",
    filesystem: Filesystem = Filesystem.FAT32,
    finder: Callable[[str], str | None] = _trusted_which,
    source_on_device: Callable[[str, Device], bool] = path_is_on_device,
) -> ConstructedMediaPlan:
    if not isinstance(partition_table, PartitionTable):
        raise ConstructedMediaSafetyError("The partition table must be MBR or GPT")
    try:
        validate_device(device)
    except (FormattingError, ValueError) as error:
        raise ConstructedMediaSafetyError(str(error)) from error
    if filesystem not in {Filesystem.FAT32, Filesystem.NTFS}:
        raise ConstructedMediaSafetyError(
            "Constructed-media copying supports FAT32 or NTFS only"
        )
    staging, directories, files = scan_staging_tree(
        staging_root,
        max_file_bytes=(
            FAT32_MAX_FILE_BYTES if filesystem is Filesystem.FAT32 else None
        ),
    )
    if source_on_device(str(staging), device):
        raise ConstructedMediaSafetyError(
            "The staging tree is stored on the target drive and would be destroyed"
        )
    loaders = _fallback_loaders(files)
    total = sum(item.size for item in files)
    required = _required_capacity(total, len(directories) + len(files))
    if required > device.size:
        raise ConstructedMediaSafetyError(
            f"The staged tree requires {required} bytes, but the target has {device.size}"
        )
    try:
        format_plan = create_format_plan(
            device, filesystem, partition_table, volume_label,
        )
        # Resolve every formatting dependency during planning, before a caller
        # can present the plan as executable.
        resolve_format_tools(format_plan, finder)
    except FormattingError as error:
        if "missing system tool" in str(error).casefold():
            raise ConstructedMediaUnavailable(str(error)) from error
        raise ConstructedMediaSafetyError(str(error)) from error
    tools = resolve_constructed_tools(finder)
    return ConstructedMediaPlan(
        device=device,
        staging_root=staging,
        directories=directories,
        files=files,
        fallback_loaders=loaders,
        total_bytes=total,
        required_capacity=required,
        partition_table=partition_table,
        volume_label=volume_label,
        filesystem=filesystem,
        format_plan=format_plan,
        tools=tools,
    )


def validate_constructed_media_plan(plan: ConstructedMediaPlan) -> None:
    if not isinstance(plan, ConstructedMediaPlan):
        raise ConstructedMediaSafetyError("A ConstructedMediaPlan is required")
    if not isinstance(plan.partition_table, PartitionTable):
        raise ConstructedMediaSafetyError("The plan contains an invalid partition table")
    if plan.filesystem not in {Filesystem.FAT32, Filesystem.NTFS}:
        raise ConstructedMediaSafetyError("The plan contains an unsupported filesystem")
    try:
        validate_device(plan.device)
    except (FormattingError, ValueError) as error:
        raise ConstructedMediaSafetyError(str(error)) from error
    if (
        not plan.staging_root.is_absolute()
        or plan.staging_root != Path(os.path.normpath(plan.staging_root))
    ):
        raise ConstructedMediaSafetyError("The plan contains a relative staging path")
    if not plan.directories or plan.directories[0].parts != ():
        raise ConstructedMediaSafetyError("The plan does not bind its staging root")
    if any(not isinstance(item, StagedDirectory) for item in plan.directories):
        raise ConstructedMediaSafetyError("The plan contains an invalid directory entry")
    if any(not isinstance(item, StagedFile) for item in plan.files):
        raise ConstructedMediaSafetyError("The plan contains an invalid file entry")
    occupied: dict[tuple[str, ...], str] = {}
    directory_parts: set[tuple[str, ...]] = set()
    for item in plan.directories:
        if any(
            not isinstance(value, int) or value < 0
            for value in (item.device, item.inode, item.modified_ns, item.changed_ns)
        ):
            raise ConstructedMediaSafetyError("The plan contains an invalid directory identity")
        if not (
            MIN_PORTABLE_ARCHIVE_MTIME_NS
            <= item.modified_ns
            <= MAX_PORTABLE_ARCHIVE_MTIME_NS
        ):
            raise ConstructedMediaSafetyError(
                "The plan contains a directory timestamp outside the portable range"
            )
        for length, component in enumerate(item.parts, start=1):
            _validate_component(component, item.path)
            if length < len(item.parts) and item.parts[:length] not in directory_parts:
                raise ConstructedMediaSafetyError("The plan contains a directory with no parent")
        key = _case_key(item.parts)
        if key in occupied:
            raise ConstructedMediaSafetyError("The plan contains colliding staged paths")
        occupied[key] = item.path
        directory_parts.add(item.parts)
    for item in plan.files:
        if not item.parts or item.parts[:-1] not in directory_parts:
            raise ConstructedMediaSafetyError("The plan contains a file with no staged parent")
        for component in item.parts:
            _validate_component(component, item.path)
        if (
            any(
                not isinstance(value, int) or value < 0
                for value in (
                    item.device, item.inode, item.size,
                    item.modified_ns, item.changed_ns,
                )
            )
            or item.link_count != 1
            or (
                plan.filesystem is Filesystem.FAT32
                and item.size > FAT32_MAX_FILE_BYTES
            )
        ):
            raise ConstructedMediaSafetyError("The plan contains an invalid file identity")
        if not (
            MIN_PORTABLE_ARCHIVE_MTIME_NS
            <= item.modified_ns
            <= MAX_PORTABLE_ARCHIVE_MTIME_NS
        ):
            raise ConstructedMediaSafetyError(
                "The plan contains a file timestamp outside the portable range"
            )
        key = _case_key(item.parts)
        if key in occupied:
            raise ConstructedMediaSafetyError("The plan contains colliding staged paths")
        occupied[key] = item.path
    expected_directories = tuple(sorted(
        plan.directories, key=lambda item: (len(item.parts), _case_key(item.parts)),
    ))
    expected_files = tuple(sorted(plan.files, key=lambda item: _case_key(item.parts)))
    if plan.directories != expected_directories or plan.files != expected_files:
        raise ConstructedMediaSafetyError("The plan contains non-canonical staged entry order")
    if plan.fallback_loaders != _fallback_loaders(plan.files):
        raise ConstructedMediaSafetyError("The plan contains invalid UEFI fallback loaders")
    total = sum(item.size for item in plan.files)
    required = _required_capacity(total, len(plan.directories) + len(plan.files))
    if plan.total_bytes != total or plan.required_capacity != required:
        raise ConstructedMediaSafetyError("The plan contains invalid capacity accounting")
    if required > plan.device.size:
        raise ConstructedMediaSafetyError("The plan no longer fits on the target drive")
    try:
        expected_format = create_format_plan(
            plan.device, plan.filesystem, plan.partition_table, plan.volume_label,
        )
    except FormattingError as error:
        raise ConstructedMediaSafetyError(str(error)) from error
    if plan.format_plan != expected_format:
        raise ConstructedMediaSafetyError(
            "The plan is not an exact constructed-media format plan"
        )
    for name in ("udisksctl", "findmnt", "lsblk"):
        try:
            _trusted_tool(name, lambda requested, n=name: (
                getattr(plan.tools, n, None) if requested == n else None
            ))
        except ConstructedMediaUnavailable as error:
            raise ConstructedMediaSafetyError("The plan contains an untrusted tool path") from error


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def _open_bound_root(plan: ConstructedMediaPlan) -> int:
    try:
        root_fd = os.open(plan.staging_root, _DIR_FLAGS)
    except OSError as error:
        raise ConstructedMediaSafetyError(
            _bounded_message(error, "Could not safely reopen the staging root")
        ) from error
    try:
        opened = os.fstat(root_fd)
    except OSError as error:
        os.close(root_fd)
        raise ConstructedMediaSafetyError(
            _bounded_message(error, "Could not verify the reopened staging root")
        ) from error
    expected = plan.directories[0]
    if _directory_from_stat((), opened) != expected:
        os.close(root_fd)
        raise ConstructedMediaSafetyError("The staging root changed after planning")
    return root_fd


def _open_directory_chain(
    root_fd: int,
    parts: tuple[str, ...],
    expected: dict[tuple[str, ...], StagedDirectory] | None = None,
    destination_device: int | None = None,
) -> int:
    current = os.dup(root_fd)
    walked: tuple[str, ...] = ()
    try:
        for component in parts:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = next_fd
            walked += (component,)
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode):
                raise ConstructedMediaSafetyError(
                    f"Path component is no longer a directory: {PurePosixPath(*walked)}"
                )
            if expected is not None:
                bound = expected.get(walked)
                if bound is None or _directory_from_stat(walked, info) != bound:
                    raise ConstructedMediaSafetyError(
                        f"Staged directory changed after planning: {PurePosixPath(*walked)}"
                    )
            if destination_device is not None and info.st_dev != destination_device:
                raise ConstructedMediaSafetyError(
                    "A destination directory escaped the mounted data filesystem"
                )
        return current
    except OSError as error:
        os.close(current)
        raise ConstructedMediaSafetyError(
            _bounded_message(error, "Could not safely traverse a directory")
        ) from error
    except BaseException:
        os.close(current)
        raise


def read_bound_staged_file(
    plan: ConstructedMediaPlan,
    entry: StagedFile,
    *,
    max_bytes: int,
    cancel_check: Callable[[], None] | None = None,
) -> bytes:
    """Read one plan-bound regular file without following a replaced path."""
    if not isinstance(plan, ConstructedMediaPlan):
        raise ConstructedMediaSafetyError("A ConstructedMediaPlan is required")
    if not isinstance(entry, StagedFile) or entry not in plan.files:
        raise ConstructedMediaSafetyError("The staged file is not bound to the plan")
    if type(max_bytes) is not int or max_bytes < 0 or entry.size > max_bytes:
        raise ConstructedMediaSafetyError("The staged file exceeds its read limit")
    if cancel_check is not None:
        cancel_check()
    root_fd = _open_bound_root(plan)
    directories = {item.parts: item for item in plan.directories}
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = _open_directory_chain(
            root_fd, entry.parts[:-1], expected=directories,
        )
        before = os.stat(
            entry.parts[-1], dir_fd=parent_fd, follow_symlinks=False,
        )
        if _file_from_stat(entry.parts, before) != entry:
            raise ConstructedMediaSafetyError(
                f"Staged file changed after planning: {entry.path!r}"
            )
        descriptor = os.open(entry.parts[-1], _READ_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if _file_from_stat(entry.parts, opened) != entry:
            raise ConstructedMediaSafetyError(
                f"Staged file changed while opening: {entry.path!r}"
            )
        chunks: list[bytes] = []
        remaining = entry.size
        while remaining:
            if cancel_check is not None:
                cancel_check()
            block = os.read(descriptor, min(COPY_BLOCK_BYTES, remaining))
            if not block:
                raise ConstructedMediaSafetyError(
                    f"Staged file ended while reading: {entry.path!r}"
                )
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ConstructedMediaSafetyError(
                f"Staged file grew while reading: {entry.path!r}"
            )
        final = os.fstat(descriptor)
        if _file_from_stat(entry.parts, final) != entry:
            raise ConstructedMediaSafetyError(
                f"Staged file changed while reading: {entry.path!r}"
            )
        if cancel_check is not None:
            cancel_check()
        return b"".join(chunks)
    except OSError as error:
        raise ConstructedMediaSafetyError(
            _bounded_message(error, f"Could not safely read staged file {entry.path!r}")
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


class ConstructedMediaExecutor:
    def __init__(
        self,
        *,
        format_executor: FormatExecutor | None = None,
        run_command: RunCommand = subprocess.run,
        device_lister: DeviceLister | None = None,
        stat_func: Callable[[str], os.stat_result] = os.stat,
        access_func: Callable[[str, int], bool] = os.access,
    ) -> None:
        self._formatter = format_executor or FormatExecutor()
        self._run_command = run_command
        self._device_lister = device_lister
        self._stat = stat_func
        self._access = access_func
        self._cancelled = threading.Event()
        self._started = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        self._formatter.cancel()

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise ConstructedMediaCancelled("Constructed-media writing was cancelled")

    def _list_devices(self, plan: ConstructedMediaPlan) -> Sequence[Device]:
        if self._device_lister is not None:
            return self._device_lister()
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        result = self._run_command(
            [
                plan.tools.lsblk, "--tree", "--bytes", "--json", "--output",
                fields, plan.device.path,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        if result.returncode:
            message = (result.stdout or "") + (result.stderr or "")
            raise ConstructedMediaSafetyError(
                _bounded_message(message, "Could not revalidate the target drive")
            )
        try:
            return parse_lsblk(result.stdout, include_usb_hdds=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ConstructedMediaSafetyError("lsblk returned invalid target information") from error

    def _verify_device(self, plan: ConstructedMediaPlan) -> Device:
        self._check_cancelled()
        try:
            matching = [
                item for item in self._list_devices(plan)
                if item.path == plan.device.path
            ]
        except ConstructedMediaError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise ConstructedMediaSafetyError(
                _bounded_message(error, "Could not revalidate the target drive")
            ) from error
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise ConstructedMediaSafetyError(
                "The target drive disappeared or changed identity; rebuild the plan"
            )
        current = matching[0]
        try:
            validate_device(current)
            info = self._stat(plan.device.path)
        except (OSError, FormattingError, ValueError) as error:
            raise ConstructedMediaSafetyError(
                _bounded_message(error, "The target is no longer a safe block device")
            ) from error
        if not stat.S_ISBLK(info.st_mode):
            raise ConstructedMediaSafetyError("The target path is not a block device")
        actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if actual != plan.device.major_minor:
            raise ConstructedMediaSafetyError(
                "The target device number changed; rebuild the plan"
            )
        return current

    def _verify_staging(self, plan: ConstructedMediaPlan) -> None:
        self._check_cancelled()
        staging, directories, files = scan_staging_tree(
            plan.staging_root,
            max_file_bytes=(
                FAT32_MAX_FILE_BYTES
                if plan.filesystem is Filesystem.FAT32 else None
            ),
        )
        if (
            staging != plan.staging_root
            or directories != plan.directories
            or files != plan.files
        ):
            raise ConstructedMediaSafetyError(
                "The staged tree changed after planning; rebuild the plan"
            )

    def _verify_staging_not_on_target(
        self, plan: ConstructedMediaPlan, current: Device,
    ) -> None:
        source_device = plan.directories[0].device
        for block_path in (current.path, *current.partitions):
            try:
                info = self._stat(block_path)
            except OSError:
                continue
            if stat.S_ISBLK(info.st_mode) and info.st_rdev == source_device:
                raise ConstructedMediaSafetyError(
                    "The staging tree is stored on the target drive and would be destroyed"
                )

    def verify_pre_destructive(self, plan: ConstructedMediaPlan) -> None:
        """Revalidate the complete source tree and target before media is changed.

        Higher-level multi-partition executors must call this immediately before
        their first destructive operation.  Population rechecks the same
        invariants later so a source or target swap is also caught before copy.
        """
        self._check_cancelled()
        validate_constructed_media_plan(plan)
        self._verify_staging(plan)
        current = self._verify_device(plan)
        self._verify_staging_not_on_target(plan, current)

    def _validate_partition(self, plan: ConstructedMediaPlan, partition: str) -> None:
        if (
            not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(plan.device.path, partition)
        ):
            raise ConstructedMediaSafetyError(
                "The formatter returned a partition outside the selected drive"
            )
        try:
            info = self._stat(partition)
        except OSError as error:
            raise ConstructedMediaSafetyError(
                _bounded_message(error, "The new partition is unavailable")
            ) from error
        if not stat.S_ISBLK(info.st_mode):
            raise ConstructedMediaSafetyError("The new partition path is not a block device")
        try:
            result = self._run_command(
                [
                    plan.tools.lsblk, "--json", "--paths", "--output",
                    "PATH,TYPE,PKNAME,FSTYPE", partition,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ConstructedMediaError(
                _bounded_message(error, "Could not inspect the new partition")
            ) from error
        try:
            nodes = json.loads(result.stdout or "").get("blockdevices", [])
        except (AttributeError, TypeError, json.JSONDecodeError) as error:
            raise ConstructedMediaSafetyError("lsblk returned invalid partition information") from error
        if (
            result.returncode or not isinstance(nodes, list)
            or len(nodes) != 1 or not isinstance(nodes[0], dict)
        ):
            raise ConstructedMediaSafetyError("Could not uniquely validate the new partition")
        node = nodes[0]
        parent = str(node.get("pkname") or "")
        if parent and not parent.startswith("/dev/"):
            parent = "/dev/" + parent
        reported_filesystem = str(node.get("fstype") or "").casefold()
        expected_filesystems = (
            {"vfat"}
            if plan.filesystem is Filesystem.FAT32
            else {"ntfs", "ntfs3", "fuseblk"}
        )
        if not (
            str(node.get("path") or "") == partition
            and node.get("type") == "part"
            and parent == plan.device.path
            and reported_filesystem in expected_filesystems
        ):
            raise ConstructedMediaSafetyError(
                "The new partition is not the expected filesystem child of the target"
            )

    def _mount_partition(self, plan: ConstructedMediaPlan, partition: str) -> None:
        self._check_cancelled()
        try:
            result = self._run_command(
                [
                    plan.tools.udisksctl, "mount", "--block-device", partition,
                    "--no-user-interaction",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ConstructedMediaError(
                _bounded_message(error, "Could not mount the new data partition")
            ) from error
        if result.returncode:
            message = (result.stdout or "") + (result.stderr or "")
            raise ConstructedMediaError(
                _bounded_message(message, "Could not mount the new data partition")
            )

    def _find_mount(self, plan: ConstructedMediaPlan, partition: str) -> Path:
        self._check_cancelled()
        try:
            result = self._run_command(
                [
                    plan.tools.findmnt, "--json", "--output",
                    "SOURCE,TARGET,FSTYPE,OPTIONS", "--source", partition,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ConstructedMediaError(
                _bounded_message(error, "Could not inspect the new mount")
            ) from error
        try:
            filesystems = json.loads(result.stdout or "").get("filesystems", [])
        except (AttributeError, TypeError, json.JSONDecodeError) as error:
            raise ConstructedMediaSafetyError("findmnt returned invalid mount information") from error
        if (
            result.returncode or not isinstance(filesystems, list)
            or len(filesystems) != 1 or not isinstance(filesystems[0], dict)
        ):
            raise ConstructedMediaSafetyError("Could not uniquely identify the new mount")
        entry = filesystems[0]
        options = {
            item.casefold() for item in str(entry.get("options") or "").split(",") if item
        }
        reported_filesystem = str(entry.get("fstype") or "").casefold()
        expected_filesystems = (
            {"vfat"}
            if plan.filesystem is Filesystem.FAT32
            else {"ntfs", "ntfs3", "fuseblk"}
        )
        if (
            str(entry.get("source") or "") != partition
            or reported_filesystem not in expected_filesystems
            or "rw" not in options
            or "ro" in options
        ):
            raise ConstructedMediaSafetyError(
                "The mounted source, filesystem type, or write mode is not the expected data partition"
            )
        target = Path(str(entry.get("target") or ""))
        if not target.is_absolute():
            raise ConstructedMediaSafetyError("findmnt returned an unsafe mount directory")
        try:
            info = os.lstat(target)
        except OSError as error:
            raise ConstructedMediaSafetyError(
                _bounded_message(error, "The data mount directory is unavailable")
            ) from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ConstructedMediaSafetyError(
                "The data mount target is not a real directory"
            )
        if not self._access(str(target), os.W_OK | os.X_OK):
            raise ConstructedMediaSafetyError("The data mount directory is not writable")
        return target

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("Destination write made no progress")
            view = view[written:]

    def _copy_file(
        self,
        plan: ConstructedMediaPlan,
        source_root_fd: int,
        destination_root_fd: int,
        destination_device: int,
        directory_map: dict[tuple[str, ...], StagedDirectory],
        item: StagedFile,
        completed: int,
        progress: Progress,
    ) -> None:
        source_parent = _open_directory_chain(
            source_root_fd, item.parts[:-1], directory_map,
        )
        destination_parent = _open_directory_chain(
            destination_root_fd, item.parts[:-1], destination_device=destination_device,
        )
        source_fd = -1
        destination_fd = -1
        try:
            source_fd = os.open(item.parts[-1], _READ_FLAGS, dir_fd=source_parent)
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or _file_from_stat(item.parts, before) != item:
                raise ConstructedMediaSafetyError(
                    f"Staged file changed after planning: {item.path!r}"
                )
            destination_fd = os.open(
                item.parts[-1], _WRITE_FLAGS, 0o600, dir_fd=destination_parent,
            )
            destination_info = os.fstat(destination_fd)
            if not stat.S_ISREG(destination_info.st_mode) or destination_info.st_dev != destination_device:
                raise ConstructedMediaSafetyError(
                    f"Destination escaped the mounted filesystem: {item.path!r}"
                )
            source_hash = hashlib.sha256()
            copied = 0
            while copied < item.size:
                self._check_cancelled()
                block = os.read(source_fd, min(COPY_BLOCK_BYTES, item.size - copied))
                if not block:
                    raise ConstructedMediaSafetyError(
                        f"Staged file ended early while copying: {item.path!r}"
                    )
                source_hash.update(block)
                self._write_all(destination_fd, block)
                copied += len(block)
                progress(ConstructedProgress(
                    "Copying", item.path, completed + copied, plan.total_bytes,
                ))
            if os.read(source_fd, 1):
                raise ConstructedMediaSafetyError(
                    f"Staged file grew while copying: {item.path!r}"
                )
            after = os.fstat(source_fd)
            if _file_from_stat(item.parts, after) != item:
                raise ConstructedMediaSafetyError(
                    f"Staged file changed while copying: {item.path!r}"
                )
            try:
                applied_mtime_ns = apply_descriptor_mtime(
                    destination_fd,
                    item.modified_ns,
                    tolerance_ns=(
                        FAT_MTIME_TOLERANCE_NS
                        if plan.filesystem is Filesystem.FAT32
                        else NTFS_MTIME_TOLERANCE_NS
                    ),
                )
            except TimestampPreservationError as error:
                raise ConstructedMediaError(
                    f"Could not preserve destination file timestamp "
                    f"{item.path!r}: {error}"
                ) from error
            os.close(destination_fd)
            destination_fd = -1

            verify_fd = os.open(item.parts[-1], _READ_FLAGS, dir_fd=destination_parent)
            try:
                verify_info = os.fstat(verify_fd)
                if (
                    not stat.S_ISREG(verify_info.st_mode)
                    or verify_info.st_dev != destination_device
                    or verify_info.st_size != item.size
                    or verify_info.st_mtime_ns != applied_mtime_ns
                ):
                    raise ConstructedMediaError(
                        f"Destination file has the wrong identity, size, or timestamp: {item.path!r}"
                    )
                destination_hash = hashlib.sha256()
                verified = 0
                while verified < item.size:
                    self._check_cancelled()
                    block = os.read(verify_fd, min(COPY_BLOCK_BYTES, item.size - verified))
                    if not block:
                        raise ConstructedMediaError(
                            f"Destination file ended early during verification: {item.path!r}"
                        )
                    destination_hash.update(block)
                    verified += len(block)
                if os.read(verify_fd, 1):
                    raise ConstructedMediaError(
                        f"Destination file grew during verification: {item.path!r}"
                    )
                if not hmac.compare_digest(source_hash.digest(), destination_hash.digest()):
                    raise ConstructedMediaError(
                        f"Read-back verification failed: {item.path!r}"
                    )
            finally:
                os.close(verify_fd)
            os.fsync(destination_parent)
        except OSError as error:
            raise ConstructedMediaError(
                _bounded_message(error, f"Could not copy staged file {item.path!r}")
            ) from error
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if destination_fd >= 0:
                os.close(destination_fd)
            os.close(source_parent)
            os.close(destination_parent)

    def _apply_directory_mtimes(
        self,
        plan: ConstructedMediaPlan,
        destination_root_fd: int,
        destination_device: int,
    ) -> None:
        for directory in sorted(
            plan.directories, key=lambda item: len(item.parts), reverse=True,
        ):
            self._check_cancelled()
            descriptor = _open_directory_chain(
                destination_root_fd, directory.parts,
                destination_device=destination_device,
            )
            try:
                applied_mtime_ns = apply_descriptor_mtime(
                    descriptor,
                    directory.modified_ns,
                    tolerance_ns=(
                        FAT_MTIME_TOLERANCE_NS
                        if plan.filesystem is Filesystem.FAT32
                        else NTFS_MTIME_TOLERANCE_NS
                    ),
                )
                after = os.fstat(descriptor)
                if after.st_mtime_ns != applied_mtime_ns:
                    raise ConstructedMediaError(
                        f"Destination directory timestamp was not preserved: {directory.path!r}"
                    )
            except (OSError, TimestampPreservationError) as error:
                raise ConstructedMediaError(
                    f"Could not preserve destination directory timestamp "
                    f"{directory.path!r}: "
                    + _bounded_message(error, "unknown timestamp error")
                ) from error
            finally:
                os.close(descriptor)

    def _copy_tree(
        self,
        plan: ConstructedMediaPlan,
        mountpoint: Path,
        progress: Progress,
    ) -> None:
        source_root_fd = _open_bound_root(plan)
        try:
            destination_root_fd = os.open(mountpoint, _DIR_FLAGS)
        except OSError as error:
            os.close(source_root_fd)
            raise ConstructedMediaSafetyError(
                _bounded_message(error, "Could not safely open the data mount directory")
            ) from error
        try:
            destination_root_info = os.fstat(destination_root_fd)
            if not stat.S_ISDIR(destination_root_info.st_mode):
                raise ConstructedMediaSafetyError("The mount target is no longer a directory")
            if os.listdir(destination_root_fd):
                raise ConstructedMediaSafetyError(
                    "The newly formatted data partition is unexpectedly non-empty"
                )
            destination_device = destination_root_info.st_dev
            directory_map = {item.parts: item for item in plan.directories}
            for directory in plan.directories[1:]:
                self._check_cancelled()
                parent_fd = _open_directory_chain(
                    destination_root_fd, directory.parts[:-1],
                    destination_device=destination_device,
                )
                try:
                    os.mkdir(directory.parts[-1], 0o700, dir_fd=parent_fd)
                    child_fd = os.open(directory.parts[-1], _DIR_FLAGS, dir_fd=parent_fd)
                    try:
                        if os.fstat(child_fd).st_dev != destination_device:
                            raise ConstructedMediaSafetyError(
                                "A created directory escaped the mounted filesystem"
                            )
                        os.fsync(child_fd)
                    finally:
                        os.close(child_fd)
                    os.fsync(parent_fd)
                except OSError as error:
                    raise ConstructedMediaError(
                        _bounded_message(
                            error, f"Could not create directory {directory.path!r}",
                        )
                    ) from error
                finally:
                    os.close(parent_fd)

            completed = 0
            progress(ConstructedProgress("Copying", "", 0, plan.total_bytes))
            for item in plan.files:
                self._copy_file(
                    plan, source_root_fd, destination_root_fd,
                    destination_device, directory_map, item, completed, progress,
                )
                completed += item.size
            self._apply_directory_mtimes(
                plan, destination_root_fd, destination_device,
            )
            os.fsync(destination_root_fd)
        except OSError as error:
            raise ConstructedMediaError(
                _bounded_message(error, "The constructed-media copy operation failed")
            ) from error
        finally:
            os.close(destination_root_fd)
            os.close(source_root_fd)

    def _best_effort_cleanup(
        self,
        plan: ConstructedMediaPlan,
        partition: str | None,
        mounted: bool,
        *,
        power_off: bool = True,
    ) -> tuple[bool, bool, str]:
        unmounted = not mounted
        cleanup_diagnostic = ""
        if partition and mounted:
            try:
                result = self._run_command(
                    [
                        plan.tools.udisksctl, "unmount", "--block-device", partition,
                        "--no-user-interaction",
                    ],
                    capture_output=True, text=True, timeout=30, shell=False,
                )
                combined = (result.stdout or "") + (result.stderr or "")
                normalized_nonzero = (
                    result.returncode != 0
                    and unmount_response_is_inactive(combined)
                )
                unmounted = result.returncode == 0
                if normalized_nonzero:
                    try:
                        current = self._verify_device(plan)
                    except (ConstructedMediaError, OSError, ValueError) as error:
                        cleanup_diagnostic = _bounded_message(
                            error,
                            "Could not verify the target mount state after unmounting",
                        )
                    else:
                        unmounted = not current.mountpoints
                        if not unmounted:
                            cleanup_diagnostic = (
                                "The target still reports mounted filesystems after "
                                "unmounting"
                                + conflict_diagnostic_suffix(partition)
                            )
                if not unmounted:
                    if not cleanup_diagnostic:
                        cleanup_diagnostic = (
                            _bounded_message(
                                combined, f"Could not unmount {partition}",
                            )
                            + conflict_diagnostic_suffix(partition)
                        )
            except (OSError, subprocess.SubprocessError) as error:
                unmounted = False
                cleanup_diagnostic = (
                    _bounded_message(error, f"Could not unmount {partition}")
                    + conflict_diagnostic_suffix(partition)
                )
        powered_off = False
        if not power_off:
            return unmounted, powered_off, cleanup_diagnostic
        try:
            result = self._run_command(
                [
                    plan.tools.udisksctl, "power-off", "--block-device",
                    plan.device.path, "--no-user-interaction",
                ],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            powered_off = result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        return unmounted, powered_off, cleanup_diagnostic

    def _populate_partition(
        self,
        plan: ConstructedMediaPlan,
        partition: str,
        progress: Progress,
        *,
        power_off: bool,
    ) -> ConstructedMediaResult:
        mounted = False
        mountpoint: Path | None = None
        try:
            self._check_cancelled()
            self._verify_device(plan)
            self._verify_staging(plan)
            self._validate_partition(plan, partition)
            self._mount_partition(plan, partition)
            mounted = True
            mountpoint = self._find_mount(plan, partition)
            self._verify_device(plan)
            self._verify_staging(plan)
            self._copy_tree(plan, mountpoint, progress)
            self._verify_staging(plan)
            self._verify_device(plan)
            progress(ConstructedProgress(
                "Complete", "", plan.total_bytes, plan.total_bytes,
            ))
        finally:
            unmounted, powered_off, cleanup_diagnostic = self._best_effort_cleanup(
                plan, partition, mounted, power_off=power_off,
            )
        assert mountpoint is not None
        return ConstructedMediaResult(
            device_identity=plan.device.identity,
            partition=partition,
            mountpoint=str(mountpoint),
            files_copied=len(plan.files),
            bytes_copied=plan.total_bytes,
            unmounted=unmounted,
            powered_off=powered_off,
            cleanup_diagnostic=cleanup_diagnostic,
        )

    def populate_existing_partition(
        self,
        plan: ConstructedMediaPlan,
        partition: str,
        progress: Progress = lambda _progress: None,
        *,
        power_off: bool = False,
    ) -> ConstructedMediaResult:
        """Populate a preformatted partition from a separately bound layout.

        This entry point performs every source, target, mount, copy, and
        read-back check used by :meth:`execute`, but deliberately does not
        partition or format the drive.  It is intended for a higher-level
        multi-partition executor that has already frozen and created the exact
        layout.  The caller remains responsible for validating that outer plan.
        """
        if self._started:
            raise ConstructedMediaSafetyError("A constructed-media executor cannot be reused")
        self._started = True
        self.verify_pre_destructive(plan)
        return self._populate_partition(
            plan, partition, progress, power_off=power_off,
        )

    def execute(
        self,
        plan: ConstructedMediaPlan,
        progress: Progress = lambda _progress: None,
    ) -> ConstructedMediaResult:
        if self._started:
            raise ConstructedMediaSafetyError("A constructed-media executor cannot be reused")
        self._started = True
        # Both source and target are checked before the first destructive call.
        self.verify_pre_destructive(plan)
        progress(ConstructedProgress("Formatting", "", 0, plan.total_bytes))
        try:
            partition = self._formatter.execute(
                plan.device,
                plan.format_plan,
                lambda stage: progress(ConstructedProgress(
                    f"Formatting: {stage}", "", 0, plan.total_bytes,
                )),
            )
        except BaseException as error:
            self._best_effort_cleanup(plan, None, False)
            if isinstance(error, FormatCancelled):
                raise ConstructedMediaCancelled(
                    "Constructed-media writing was cancelled"
                ) from error
            if isinstance(error, FormattingError):
                raise ConstructedMediaError(
                    _bounded_message(error, "Formatting failed")
                ) from error
            raise

        return self._populate_partition(
            plan, partition, progress, power_off=True,
        )
