from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unprivileged, path-safe ISO extraction into a new regular directory.

This is a staging primitive, not a block-device writer.  It validates the
complete member catalog first, creates files through directory descriptors
with O_NOFOLLOW, streams each regular member from 7-Zip, and atomically
publishes the finished tree.  Privilege is neither requested nor accepted.
"""

import os
import selectors
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .iso import ArchiveEntry, EntryKind, validate_extraction_entries
from .timestamps import (
    STAGING_MTIME_TOLERANCE_NS,
    TimestampPreservationError,
    apply_descriptor_mtime,
)

CHUNK_SIZE = 1024 * 1024
OUTPUT_SPACE_RESERVE = 64 * 1024 * 1024
MAX_ERROR_BYTES = 16 * 1024
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class ExtractionError(RuntimeError):
    pass


class ExtractionUnavailable(ExtractionError):
    pass


class ExtractionCancelled(ExtractionError):
    pass


class ExtractionSafetyError(ExtractionError):
    pass


FileIdentity = tuple[int, int, int, int]


@dataclass(frozen=True)
class ExtractionPlan:
    image: Path
    image_identity: FileIdentity
    destination: Path
    destination_parent_identity: tuple[int, int]
    entries: tuple[ArchiveEntry, ...]
    content_bytes: int
    seven_zip: str


@dataclass(frozen=True)
class ExtractionProgress:
    member: str
    member_bytes_done: int
    member_size: int
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 1.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class ExtractionResult:
    destination: Path
    files: int
    directories: int
    links: int
    bytes_written: int


Progress = Callable[[ExtractionProgress], None]
CancelCheck = Callable[[], None]
MemberStreamer = Callable[[Path, str, BinaryIO, CancelCheck], int]


def _identity(path: Path) -> FileIdentity:
    status = path.stat()
    if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
        raise ExtractionSafetyError("The ISO source must be a non-empty regular file")
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _trusted_7z() -> str:
    executable = shutil.which("7z", path=TRUSTED_PATH)
    if not executable or executable not in {"/usr/bin/7z", "/usr/sbin/7z", "/bin/7z", "/sbin/7z"}:
        raise ExtractionUnavailable("7-Zip was not found in a trusted system directory")
    return executable


def extraction_command(seven_zip: str, image: Path, member: str) -> tuple[str, ...]:
    if seven_zip not in {"/usr/bin/7z", "/usr/sbin/7z", "/bin/7z", "/sbin/7z"}:
        raise ExtractionSafetyError("The extraction plan contains an untrusted 7-Zip path")
    # Re-run the same catalog validator for this exact member. This prevents a
    # manually forged plan from turning option-like text into an archive query.
    normalized = validate_extraction_entries((ArchiveEntry(member),))[0].path
    return (seven_zip, "x", "-so", "-spd", "-y", "--", str(image), normalized)


def build_extraction_plan(
    image: Path,
    destination: Path,
    entries: Sequence[ArchiveEntry],
    *,
    seven_zip: str | None = None,
) -> ExtractionPlan:
    source = image.expanduser().resolve(strict=True)
    source_identity = _identity(source)
    safe_entries = validate_extraction_entries(entries)
    if not safe_entries:
        raise ExtractionSafetyError("The ISO member catalog is empty")
    output = destination.expanduser()
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        raise ExtractionSafetyError("Extraction requires a new absolute destination directory")
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if os.path.lexists(output):
        raise ExtractionSafetyError("The extraction destination already exists")
    parent_status = parent.stat()
    if not stat.S_ISDIR(parent_status.st_mode) or not os.access(parent, os.W_OK | os.X_OK):
        raise ExtractionSafetyError("The extraction destination parent is not writable")
    content_bytes = sum(
        entry.size for entry in safe_entries if entry.kind is EntryKind.FILE
    )
    free = shutil.disk_usage(parent).free
    if free < content_bytes + OUTPUT_SPACE_RESERVE:
        raise ExtractionSafetyError("There is not enough free space to stage the ISO contents")
    tool = seven_zip or _trusted_7z()
    extraction_command(tool, source, safe_entries[0].path)
    return ExtractionPlan(
        source, source_identity, output, (parent_status.st_dev, parent_status.st_ino),
        safe_entries, content_bytes, tool,
    )


def _open_directory(parent_fd: int, component: str, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(component, 0o700, dir_fd=parent_fd)
        return os.open(component, flags, dir_fd=parent_fd)


def _parent_fd(root_fd: int, path: PurePosixPath) -> int:
    current = os.dup(root_fd)
    try:
        for component in path.parts[:-1]:
            following = _open_directory(current, component, True)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _apply_mtime(descriptor: int, modified_ns: int, member: str) -> int:
    """Apply one validated timestamp and return any bounded normalization."""

    try:
        return apply_descriptor_mtime(
            descriptor,
            modified_ns,
            tolerance_ns=STAGING_MTIME_TOLERANCE_NS,
        )
    except TimestampPreservationError as error:
        raise ExtractionError(
            f"Could not preserve the modification time for {member!r}: {error}"
        ) from error


class SafeIsoExtractor:
    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        streamer: MemberStreamer | None = None,
    ) -> None:
        self._popen = popen
        self._streamer = streamer
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._used = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def cancel_event(self) -> threading.Event:
        """Share cancellation with a bounded follow-on inspection command."""
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise ExtractionCancelled("ISO extraction was cancelled")

    def _stream_member(
        self, plan: ExtractionPlan, member: str, expected_size: int, output: BinaryIO,
    ) -> int:
        if self._streamer is not None:
            return self._streamer(plan.image, member, output, self._check_cancelled)
        process = self._popen(
            list(extraction_command(plan.seven_zip, plan.image, member)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"}, shell=False,
        )
        with self._lock:
            self._process = process
        if process.stdout is None or process.stderr is None:
            process.terminate()
            raise ExtractionError("Could not capture 7-Zip output")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        error = bytearray()
        written = 0
        try:
            while selector.get_map():
                self._check_cancelled()
                for key, _ in selector.select(0.2):
                    block = os.read(key.fileobj.fileno(), CHUNK_SIZE)
                    if not block:
                        selector.unregister(key.fileobj)
                    elif key.data == "stdout":
                        if written + len(block) > expected_size:
                            raise ExtractionError(
                                f"{member} produced more data than its cataloged size"
                            )
                        output.write(block)
                        written += len(block)
                    else:
                        error.extend(block)
                        if len(error) > MAX_ERROR_BYTES:
                            del error[:-MAX_ERROR_BYTES]
            code = process.wait()
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            with self._lock:
                if self._process is process:
                    self._process = None
        self._check_cancelled()
        if code:
            message = bytes(error).decode(errors="replace").strip()
            raise ExtractionError(message or f"7-Zip could not extract {member}")
        return written

    def execute(
        self,
        plan: ExtractionPlan,
        progress: Progress = lambda _update: None,
    ) -> ExtractionResult:
        if self._used:
            raise ExtractionSafetyError("An ISO extractor can only be used once")
        self._used = True
        self._check_cancelled()
        # Rebuild the immutable safety facts without allowing the tool or
        # destination to be silently changed.
        if _identity(plan.image) != plan.image_identity:
            raise ExtractionSafetyError("The ISO source changed after extraction was planned")
        if validate_extraction_entries(plan.entries) != plan.entries:
            raise ExtractionSafetyError("The extraction plan contains non-normalized members")
        extraction_command(plan.seven_zip, plan.image, plan.entries[0].path)
        parent_status = plan.destination.parent.stat()
        if (parent_status.st_dev, parent_status.st_ino) != plan.destination_parent_identity:
            raise ExtractionSafetyError("The extraction destination parent changed")
        if os.path.lexists(plan.destination):
            raise ExtractionSafetyError("The extraction destination appeared before execution")
        staging = Path(tempfile.mkdtemp(
            prefix=f".{plan.destination.name}.", suffix=".partial",
            dir=plan.destination.parent,
        ))
        root_fd = os.open(
            staging, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
            getattr(os, "O_NOFOLLOW", 0),
        )
        done = 0
        files = directories = links = 0
        directory_mtimes: list[tuple[PurePosixPath, int]] = []
        try:
            for entry in plan.entries:
                self._check_cancelled()
                path = PurePosixPath(entry.path)
                parent_fd = _parent_fd(root_fd, path)
                try:
                    name = path.name
                    if entry.kind is EntryKind.DIRECTORY:
                        directory_fd = _open_directory(parent_fd, name, True)
                        os.close(directory_fd)
                        if entry.modified_ns is not None:
                            directory_mtimes.append((path, entry.modified_ns))
                        directories += 1
                        continue
                    if entry.kind is EntryKind.SYMLINK:
                        os.symlink(entry.link_target or "", name, dir_fd=parent_fd)
                        links += 1
                        continue
                    if entry.kind is EntryKind.HARDLINK:
                        target = PurePosixPath(path.parent, entry.link_target or "").as_posix()
                        os.link(
                            target, entry.path, src_dir_fd=root_fd, dst_dir_fd=root_fd,
                            follow_symlinks=False,
                        )
                        links += 1
                        continue
                    descriptor = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent_fd,
                    )
                    with os.fdopen(descriptor, "wb", buffering=0) as output:
                        member_written = self._stream_member(
                            plan, entry.path, entry.size, output
                        )
                        output.flush()
                        os.fsync(output.fileno())
                        if entry.modified_ns is not None:
                            _apply_mtime(
                                output.fileno(), entry.modified_ns, entry.path,
                            )
                    if member_written != entry.size:
                        raise ExtractionError(
                            f"{entry.path} produced {member_written} bytes; expected {entry.size}"
                        )
                    done += member_written
                    files += 1
                    progress(ExtractionProgress(
                        entry.path, member_written, entry.size, done, plan.content_bytes,
                    ))
                finally:
                    os.close(parent_fd)
            for path, modified_ns in sorted(
                directory_mtimes, key=lambda item: len(item[0].parts), reverse=True,
            ):
                self._check_cancelled()
                parent_fd = _parent_fd(root_fd, path)
                try:
                    directory_fd = _open_directory(parent_fd, path.name, False)
                    try:
                        _apply_mtime(directory_fd, modified_ns, path.as_posix())
                    finally:
                        os.close(directory_fd)
                finally:
                    os.close(parent_fd)
            self._check_cancelled()
            if done != plan.content_bytes:
                raise ExtractionError(
                    f"Extracted {done} bytes; expected {plan.content_bytes} from the catalog"
                )
            if _identity(plan.image) != plan.image_identity:
                raise ExtractionSafetyError("The ISO source changed during extraction")
            os.fsync(root_fd)
            if os.path.lexists(plan.destination):
                raise ExtractionSafetyError("The extraction destination appeared during execution")
            staging.rename(plan.destination)
            parent_fd = os.open(
                plan.destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return ExtractionResult(plan.destination, files, directories, links, done)
        finally:
            os.close(root_fd)
            if staging.exists():
                shutil.rmtree(staging)
