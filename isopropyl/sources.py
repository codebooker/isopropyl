from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import bz2
import gzip
import hashlib
import io
import lzma
import os
import select
import shutil
import stat
import subprocess
import weakref
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .vtsi import (
    VTSI_MAX_DISK_BYTES,
    VTSI_SECTOR_BYTES,
    VtsiChanged,
    VtsiError,
    VtsiPlan,
    inspect_vtsi_descriptor,
    iter_vtsi_chunks,
    read_vtsi_at,
    validate_vtsi_plan,
)


CHUNK_SIZE = 4 * 1024 * 1024
DECODER_ERROR_LIMIT = 16 * 1024
DECODER_WAIT_SECONDS = 5.0
DECODER_POLL_SECONDS = 0.2
ZIP_CENTRAL_DIRECTORY_MAX_BYTES = 16 * 1024 * 1024
ZIP_MEMBER_MAX_COUNT = 4096
CancelCheck = Callable[[], None]


class ImageSourceError(RuntimeError):
    """The selected source cannot be safely decoded as one disk image."""


class ExpandedImageTooLarge(ImageSourceError):
    pass


class SourceChanged(ImageSourceError):
    pass


@dataclass(frozen=True)
class SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _identity(path: Path) -> SourceIdentity:
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise ImageSourceError("The selected image must be a regular file")
    return SourceIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def _identity_from_status(status: os.stat_result) -> SourceIdentity:
    if not stat.S_ISREG(status.st_mode):
        raise ImageSourceError("The selected image must be a regular file")
    return SourceIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def _bound_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


class _DescriptorReader(io.RawIOBase):
    """An independently positioned reader anchored to an already-open file."""

    def __init__(
        self,
        descriptor: int,
        *,
        cancel_check: CancelCheck | None = None,
        unchanged_check: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self._descriptor = os.dup(descriptor)
        self._position = 0
        self._cancel_check = cancel_check
        self._unchanged_check = unchanged_check

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def fileno(self) -> int:
        self._checkClosed()
        return self._descriptor

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = os.fstat(self._descriptor).st_size + offset
        else:
            raise ValueError(f"unsupported whence value: {whence}")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def readinto(self, buffer: object) -> int:
        self._checkClosed()
        view = memoryview(buffer).cast("B")
        if self._cancel_check is not None:
            self._cancel_check()
        data = os.pread(self._descriptor, len(view), self._position)
        if self._unchanged_check is not None:
            self._unchanged_check()
        if self._cancel_check is not None:
            self._cancel_check()
        view[:len(data)] = data
        self._position += len(data)
        return len(data)

    def close(self) -> None:
        if not self.closed:
            os.close(self._descriptor)
        super().close()


class _InterruptiblePipeReader(io.RawIOBase):
    """Read decoder stdout without hiding cancellation behind a blocking pipe."""

    def __init__(self, stream: BinaryIO, cancel_check: CancelCheck) -> None:
        super().__init__()
        self._descriptor = stream.fileno()
        self._cancel_check = cancel_check

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        self._checkClosed()
        return self._descriptor

    def readinto(self, buffer: object) -> int:
        self._checkClosed()
        view = memoryview(buffer).cast("B")
        if not view:
            return 0
        while True:
            self._cancel_check()
            try:
                readable, _, _ = select.select(
                    (self._descriptor,), (), (), DECODER_POLL_SECONDS,
                )
            except InterruptedError:
                continue
            if not readable:
                continue
            data = os.read(self._descriptor, len(view))
            self._cancel_check()
            view[:len(data)] = data
            return len(data)


class ImageSource:
    """A repeatable stream of the raw bytes that will be written to a device.

    Compressed inputs are deliberately decoded once to measure them before a
    destructive write. The subsequent stream must have exactly that length.
    """

    def __init__(
        self,
        path: Path,
        *,
        cancel_check: CancelCheck | None = None,
        maximum_sparse_bytes: int = VTSI_MAX_DISK_BYTES,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._descriptor: int | None = None
        self._descriptor_identity: tuple[int, int, int, int, int] | None = None
        self._descriptor_finalizer: weakref.finalize | None = None
        self._vtsi_plan: VtsiPlan | None = None
        self.sparse_format = ""
        self.requires_exact_target_size = False
        self.required_logical_sector_size = 0
        self.compression = self._detect_compression()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(self.path, flags)
        except OSError as error:
            raise ImageSourceError(
                "The selected image could not be opened safely"
            ) from error
        try:
            status = os.fstat(descriptor)
            self.identity = _identity_from_status(status)
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        self._descriptor_identity = _bound_identity(status)
        self._descriptor_finalizer = weakref.finalize(self, os.close, descriptor)
        if self.path.suffix.casefold() == ".vtsi":
            cancel_failure: BaseException | None = None

            def check_cancelled() -> None:
                nonlocal cancel_failure
                if cancel_check is None:
                    return
                try:
                    cancel_check()
                except BaseException as error:
                    cancel_failure = error
                    raise

            try:
                self._vtsi_plan = inspect_vtsi_descriptor(
                    descriptor,
                    self.path,
                    cancel_check=check_cancelled,
                    maximum_disk_size=maximum_sparse_bytes,
                )
            except VtsiChanged as error:
                self.close()
                if error is cancel_failure:
                    raise
                raise SourceChanged(str(error)) from error
            except VtsiError as error:
                self.close()
                if error is cancel_failure:
                    raise
                raise ImageSourceError(f"Could not inspect {self.path.name}: {error}") from error
            except BaseException:
                self.close()
                raise
            self.sparse_format = "vtsi"
            self.requires_exact_target_size = True
            self.required_logical_sector_size = VTSI_SECTOR_BYTES

    @property
    def compressed(self) -> bool:
        return self.compression != "none"

    def _detect_compression(self) -> str:
        original_name = self.path.name
        name = original_name.casefold()
        for suffix, kind in (
            (".bzip2", "bz2"),
            (".bz2", "bz2"),
            (".gzip", "gzip"),
            (".gz", "gzip"),
            (".lzma", "lzma"),
            (".xz", "xz"),
            (".zstd", "zstd"),
            (".zst", "zstd"),
            (".zip", "zip"),
        ):
            if name.endswith(suffix):
                return kind
        # UNIX `compress` traditionally uses an uppercase .Z suffix. Accept a
        # lowercase spelling too, but keep it separate from zstd's .zst/.zstd.
        if original_name.endswith(".Z") or name.endswith(".z"):
            return "compress-z"
        return "none"

    def _ensure_unchanged(self) -> None:
        if self._descriptor is not None:
            try:
                status = os.fstat(self._descriptor)
            except OSError as error:
                raise SourceChanged("The selected image is no longer available") from error
            if (
                not stat.S_ISREG(status.st_mode)
                or _bound_identity(status) != self._descriptor_identity
            ):
                raise SourceChanged("The selected image changed while it was being prepared")
            return
        try:
            current = _identity(self.path)
        except OSError as error:
            raise SourceChanged("The selected image is no longer available") from error
        if current != self.identity:
            raise SourceChanged("The selected image changed while it was being prepared")

    def close(self) -> None:
        if self._descriptor_finalizer is not None and self._descriptor_finalizer.alive:
            self._descriptor_finalizer()
        self._descriptor = None

    def __enter__(self) -> ImageSource:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _require_descriptor(self) -> int:
        if self._descriptor is None:
            raise ImageSourceError("The selected image is no longer open")
        return self._descriptor

    def fileno(self) -> int:
        """Return the immutable source descriptor while this source is open."""

        self._ensure_unchanged()
        return self._require_descriptor()

    def _validate_zip_directory_bounds(
        self,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        """Bound ZIP metadata before ``zipfile`` allocates its member catalog."""

        if cancel_check is not None:
            cancel_check()
        descriptor = self._require_descriptor()
        size = os.fstat(descriptor).st_size
        tail_size = min(size, 22 + 65535)
        tail_offset = size - tail_size
        tail = os.pread(descriptor, tail_size, tail_offset)
        if cancel_check is not None:
            cancel_check()
        signature = b"PK\x05\x06"
        eocd_index = tail.rfind(signature)
        if eocd_index < 0 or eocd_index + 22 > len(tail):
            raise ImageSourceError("The ZIP end-of-central-directory record is invalid")
        comment_size = int.from_bytes(
            tail[eocd_index + 20:eocd_index + 22], "little",
        )
        # zipfile selects the final signature. Require that exact record to end
        # at EOF so our bounded preflight and the library cannot parse different
        # central-directory metadata.
        if tail_offset + eocd_index + 22 + comment_size != size:
            raise ImageSourceError("The ZIP end-of-central-directory record is invalid")

        eocd = tail[eocd_index:eocd_index + 22]
        disk_number = int.from_bytes(eocd[4:6], "little")
        directory_disk = int.from_bytes(eocd[6:8], "little")
        entries_on_disk = int.from_bytes(eocd[8:10], "little")
        entry_count = int.from_bytes(eocd[10:12], "little")
        directory_size = int.from_bytes(eocd[12:16], "little")
        directory_offset = int.from_bytes(eocd[16:20], "little")
        eocd_offset = tail_offset + eocd_index
        directory_end = eocd_offset
        if disk_number or directory_disk or entries_on_disk != entry_count:
            raise ImageSourceError("Multi-disk ZIP sources are not supported")

        classic_zip64 = (
            entry_count == 0xFFFF
            or directory_size == 0xFFFFFFFF
            or directory_offset == 0xFFFFFFFF
        )
        locator_offset = eocd_offset - 20
        locator = (
            os.pread(descriptor, 20, locator_offset)
            if locator_offset >= 0 else b""
        )
        has_zip64_locator = len(locator) == 20 and locator[:4] == b"PK\x06\x07"
        if classic_zip64 and not has_zip64_locator:
            raise ImageSourceError("The ZIP64 directory locator is invalid")
        # CPython's zipfile parser honors an adjacent ZIP64 locator even when
        # the classic EOCD fields are not sentinels. Mirror that behavior so a
        # forged classic record cannot understate the catalog before allocation.
        if has_zip64_locator:
            if int.from_bytes(locator[4:8], "little") != 0:
                raise ImageSourceError("Multi-disk ZIP64 sources are not supported")
            relative_zip64_offset = int.from_bytes(locator[8:16], "little")
            if int.from_bytes(locator[16:20], "little") != 1:
                raise ImageSourceError("Multi-disk ZIP64 sources are not supported")
            record_offset = locator_offset - 56
            if record_offset < 0 or relative_zip64_offset > record_offset:
                raise ImageSourceError("The ZIP64 directory locator is invalid")
            record = os.pread(descriptor, 56, relative_zip64_offset)
            record_location = relative_zip64_offset
            extensible_size = record_offset - relative_zip64_offset
            if (
                (len(record) != 56 or record[:4] != b"PK\x06\x06")
                and relative_zip64_offset != record_offset
            ):
                # Self-extracting archives express the locator relative to the
                # ZIP payload rather than to prepended executable bytes.
                record = os.pread(descriptor, 56, record_offset)
                record_location = record_offset
                extensible_size = 0
            if len(record) != 56 or record[:4] != b"PK\x06\x06":
                raise ImageSourceError("The ZIP64 directory record is invalid")
            if (
                int.from_bytes(record[16:20], "little") != 0
                or int.from_bytes(record[20:24], "little") != 0
                or int.from_bytes(record[24:32], "little")
                != int.from_bytes(record[32:40], "little")
            ):
                raise ImageSourceError("Multi-disk ZIP64 sources are not supported")
            entry_count = int.from_bytes(record[32:40], "little")
            directory_size = int.from_bytes(record[40:48], "little")
            directory_offset = int.from_bytes(record[48:56], "little")
            if (
                directory_offset + directory_size != relative_zip64_offset
                or int.from_bytes(record[4:12], "little") + 12
                != 56 + extensible_size
            ):
                raise ImageSourceError("The ZIP64 directory record is inconsistent")
            directory_end = record_location

        if entry_count > ZIP_MEMBER_MAX_COUNT:
            raise ImageSourceError(
                f"The ZIP contains too many entries ({entry_count:,}; "
                f"limit {ZIP_MEMBER_MAX_COUNT:,})"
            )
        if directory_size > ZIP_CENTRAL_DIRECTORY_MAX_BYTES:
            raise ImageSourceError(
                "The ZIP central directory is too large to inspect safely"
            )
        concatenated_prefix = directory_end - directory_size - directory_offset
        directory_start = directory_offset + concatenated_prefix
        if (
            concatenated_prefix < 0
            or directory_start < 0
            or directory_start > size
            or directory_size > size - directory_start
            or directory_start + directory_size != directory_end
        ):
            raise ImageSourceError("The ZIP central directory lies outside the file")
        directory = os.pread(descriptor, directory_size, directory_start)
        if cancel_check is not None:
            cancel_check()
        if len(directory) != directory_size:
            raise ImageSourceError("The ZIP central directory is truncated")
        position = 0
        actual_entries = 0
        while position < directory_size:
            if (
                directory_size - position < 46
                or directory[position:position + 4] != b"PK\x01\x02"
            ):
                raise ImageSourceError("The ZIP central directory is malformed")
            variable_size = sum(
                int.from_bytes(
                    directory[position + offset:position + offset + 2], "little",
                )
                for offset in (28, 30, 32)
            )
            record_size = 46 + variable_size
            if record_size > directory_size - position:
                raise ImageSourceError("The ZIP central directory record is truncated")
            actual_entries += 1
            if actual_entries > ZIP_MEMBER_MAX_COUNT:
                raise ImageSourceError(
                    f"The ZIP contains too many entries (more than "
                    f"{ZIP_MEMBER_MAX_COUNT:,})"
                )
            position += record_size
        if actual_entries != entry_count:
            raise ImageSourceError(
                "The ZIP central-directory entry count is inconsistent"
            )

    @contextmanager
    def _open_bound_stream(
        self,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> Iterator[BinaryIO]:
        self._ensure_unchanged()
        raw = _DescriptorReader(
            self._require_descriptor(),
            cancel_check=cancel_check,
            unchanged_check=self._ensure_unchanged,
        )
        with io.BufferedReader(raw) as stream:
            yield stream

    def measure(
        self,
        maximum: int | None = None,
        cancel_check: CancelCheck | None = None,
    ) -> int:
        if self._vtsi_plan is not None:
            cancel_failure: BaseException | None = None

            def check_cancelled() -> None:
                nonlocal cancel_failure
                if cancel_check is None:
                    return
                try:
                    cancel_check()
                except BaseException as error:
                    cancel_failure = error
                    raise

            check_cancelled()
            try:
                validate_vtsi_plan(
                    self._require_descriptor(), self._vtsi_plan,
                    cancel_check=check_cancelled,
                )
            except VtsiChanged as error:
                if error is cancel_failure:
                    raise
                raise SourceChanged(str(error)) from error
            except VtsiError as error:
                if error is cancel_failure:
                    raise
                raise ImageSourceError(
                    f"Could not validate {self.path.name}: {error}"
                ) from error
            size = self._vtsi_plan.disk_size
            if maximum is not None and size > maximum:
                raise ExpandedImageTooLarge(
                    f"The image contains {size} bytes, larger than the {maximum}-byte target"
                )
            check_cancelled()
            return size
        if not self.compressed:
            size = self.identity.size
            if maximum is not None and size > maximum:
                raise ExpandedImageTooLarge(
                    f"The image contains {size} bytes, larger than the {maximum}-byte target"
                )
            return size

        total = 0
        for block in self.chunks(cancel_check=cancel_check):
            total += len(block)
            if maximum is not None and total > maximum:
                raise ExpandedImageTooLarge(
                    "The decompressed image is larger than the selected target drive"
                )
        return total

    def chunks(
        self,
        expected_size: int | None = None,
        cancel_check: CancelCheck | None = None,
    ) -> Iterator[bytes]:
        self._ensure_unchanged()
        done = 0
        cancel_failure: BaseException | None = None

        def check_cancelled() -> None:
            nonlocal cancel_failure
            if cancel_check is None:
                return
            try:
                cancel_check()
            except BaseException as error:
                # Cancellation is caller control flow, not a decoder failure.
                # Preserve its exact type even when it derives from OSError or
                # RuntimeError.
                cancel_failure = error
                raise

        if self._vtsi_plan is not None:
            try:
                for block in iter_vtsi_chunks(
                    self._require_descriptor(), self._vtsi_plan,
                    chunk_size=CHUNK_SIZE, cancel_check=check_cancelled,
                ):
                    check_cancelled()
                    self._ensure_unchanged()
                    done += len(block)
                    if expected_size is not None and done > expected_size:
                        raise ImageSourceError(
                            "The sparse image produced more data than its measured size"
                        )
                    yield block
                self._ensure_unchanged()
                if expected_size is not None and done != expected_size:
                    raise ImageSourceError(
                        f"The sparse image ended at {done} bytes; expected {expected_size}"
                    )
                return
            except SourceChanged:
                raise
            except VtsiChanged as error:
                if error is cancel_failure:
                    raise
                raise SourceChanged(str(error)) from error
            except VtsiError as error:
                if error is cancel_failure:
                    raise
                raise ImageSourceError(
                    f"Could not decode {self.path.name}: {error}"
                ) from error

        try:
            with self._open(cancel_check=check_cancelled) as stream:
                while True:
                    check_cancelled()
                    block = stream.read(CHUNK_SIZE)
                    check_cancelled()
                    # Recheck the descriptor after every read and before any
                    # newly obtained bytes can reach a destructive consumer.
                    # Decoder buffering can only make this more conservative:
                    # a metadata change still suppresses the next yield.
                    self._ensure_unchanged()
                    if not block:
                        break
                    done += len(block)
                    if expected_size is not None and done > expected_size:
                        raise ImageSourceError(
                            "The decoded image produced more data than its measured size"
                        )
                    yield block
        except ImageSourceError:
            raise
        except (EOFError, OSError, RuntimeError, zipfile.BadZipFile) as error:
            if error is cancel_failure:
                raise
            raise ImageSourceError(
                f"Could not decode {self.path.name}: {error}"
            ) from error
        self._ensure_unchanged()
        if expected_size is not None and done != expected_size:
            raise ImageSourceError(
                f"The decoded image ended at {done} bytes; expected {expected_size}"
            )

    def read_sparse_at(
        self,
        offset: int,
        length: int,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> bytes:
        """Read a bounded range from the expanded sparse-disk view."""

        if self._vtsi_plan is None:
            raise ImageSourceError("The selected image is not a supported sparse image")
        cancel_failure: BaseException | None = None

        def check_cancelled() -> None:
            nonlocal cancel_failure
            if cancel_check is None:
                return
            try:
                cancel_check()
            except BaseException as error:
                cancel_failure = error
                raise

        try:
            payload = read_vtsi_at(
                self._require_descriptor(), self._vtsi_plan, offset, length,
                cancel_check=check_cancelled,
            )
        except VtsiChanged as error:
            if error is cancel_failure:
                raise
            raise SourceChanged(str(error)) from error
        except VtsiError as error:
            if error is cancel_failure:
                raise
            raise ImageSourceError(
                f"Could not read {self.path.name}: {error}"
            ) from error
        self._ensure_unchanged()
        return payload

    @contextmanager
    def _open(
        self,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> Iterator[BinaryIO]:
        if self.compression == "none":
            with self._open_bound_stream(cancel_check=cancel_check) as stream:
                yield stream
            return
        if self.compression == "gzip":
            with self._open_bound_stream(cancel_check=cancel_check) as compressed:
                with gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
                    yield stream
            return
        if self.compression == "bz2":
            with self._open_bound_stream(cancel_check=cancel_check) as compressed:
                with bz2.BZ2File(compressed, "rb") as stream:
                    yield stream
            return
        if self.compression in {"xz", "lzma"}:
            with self._open_bound_stream(cancel_check=cancel_check) as compressed:
                with lzma.LZMAFile(compressed, "rb") as stream:
                    yield stream
            return
        if self.compression == "zip":
            self._validate_zip_directory_bounds(cancel_check=cancel_check)
            with self._open_bound_stream(cancel_check=cancel_check) as compressed:
                with zipfile.ZipFile(compressed) as archive:
                    members = [item for item in archive.infolist() if not item.is_dir()]
                    if len(members) != 1:
                        raise ImageSourceError(
                            "ZIP sources must contain exactly one disk image file"
                        )
                    member = members[0]
                    mode = member.external_attr >> 16
                    if mode and stat.S_ISLNK(mode):
                        raise ImageSourceError("A ZIP disk image cannot be a symbolic link")
                    with archive.open(member, "r") as stream:
                        yield stream
            return
        if self.compression == "zstd":
            with self._open_zstd(cancel_check=cancel_check) as stream:
                yield stream
            return
        if self.compression == "compress-z":
            with self._open_external_decoder(
                "gzip", ("--decompress", "--stdout", "--quiet", "--"),
                cancel_check=cancel_check,
            ) as stream:
                yield stream
            return
        raise AssertionError(f"Unsupported compression kind: {self.compression}")

    @contextmanager
    def _open_external_decoder(
        self,
        program: str,
        arguments: tuple[str, ...],
        *,
        cancel_check: CancelCheck | None = None,
        missing_message: str | None = None,
        failure_message: str | None = None,
    ) -> Iterator[BinaryIO]:
        executable = shutil.which(program, path="/usr/sbin:/usr/bin:/sbin:/bin")
        if not executable:
            raise ImageSourceError(
                missing_message
                or f"Reading {self.path.suffix} images requires the {program} command"
            )
        self._ensure_unchanged()
        descriptor = self._require_descriptor()
        descriptor_path = f"/proc/self/fd/{descriptor}"
        try:
            if _bound_identity(os.stat(descriptor_path)) != self._descriptor_identity:
                raise OSError("descriptor identity mismatch")
            process = subprocess.Popen(
                [executable, *arguments, descriptor_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                pass_fds=(descriptor,),
            )
        except OSError as error:
            raise ImageSourceError(
                "The external decoder could not be bound to the selected image"
            ) from error
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            yield (
                _InterruptiblePipeReader(process.stdout, cancel_check)
                if cancel_check is not None else process.stdout
            )
        except BaseException:
            process.stdout.close()
            self._stop_decoder(process)
            raise
        else:
            process.stdout.close()
            try:
                code = process.wait(timeout=DECODER_WAIT_SECONDS)
            except subprocess.TimeoutExpired as error:
                self._stop_decoder(process)
                raise ImageSourceError("The image decoder did not exit cleanly") from error
        error = process.stderr.read(DECODER_ERROR_LIMIT + 1)
        process.stderr.close()
        if code:
            raise ImageSourceError(
                error[:DECODER_ERROR_LIMIT].decode(errors="replace").strip()
                or failure_message
                or f"Could not decompress the {self.path.suffix} image"
            )

    @staticmethod
    def _stop_decoder(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=DECODER_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=DECODER_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        if process.stderr is not None:
            process.stderr.close()

    @contextmanager
    def _open_zstd(
        self,
        *,
        cancel_check: CancelCheck | None = None,
    ) -> Iterator[BinaryIO]:
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError:
            zstandard = None

        if zstandard is not None:
            with self._open_bound_stream(cancel_check=cancel_check) as compressed:
                with zstandard.ZstdDecompressor().stream_reader(compressed) as stream:
                    yield stream
            return

        with self._open_external_decoder(
            "zstd",
            ("--decompress", "--stdout", "--quiet", "--"),
            cancel_check=cancel_check,
            missing_message=(
                "Reading .zst images requires the zstd command or Python zstandard package"
            ),
            failure_message="Could not decompress the zstd image",
        ) as stream:
            yield stream


def open_image_source(
    path: Path,
    *,
    cancel_check: CancelCheck | None = None,
    maximum_sparse_bytes: int = VTSI_MAX_DISK_BYTES,
) -> ImageSource:
    return ImageSource(
        path, cancel_check=cancel_check,
        maximum_sparse_bytes=maximum_sparse_bytes,
    )


def sha256_source(
    source: ImageSource,
    total: int,
    progress: Callable[[int, int], None] | None = None,
    cancel_check: CancelCheck | None = None,
) -> str:
    digest = hashlib.sha256()
    done = 0
    for block in source.chunks(expected_size=total, cancel_check=cancel_check):
        digest.update(block)
        done += len(block)
        if progress:
            progress(done, total)
    return digest.hexdigest()
