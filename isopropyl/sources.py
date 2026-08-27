from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import bz2
import gzip
import hashlib
import lzma
import shutil
import stat
import subprocess
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


CHUNK_SIZE = 4 * 1024 * 1024
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


def _identity(path: Path) -> SourceIdentity:
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise ImageSourceError("The selected image must be a regular file")
    return SourceIdentity(status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)


class ImageSource:
    """A repeatable stream of the raw bytes that will be written to a device.

    Compressed inputs are deliberately decoded once to measure them before a
    destructive write. The subsequent stream must have exactly that length.
    """

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.identity = _identity(self.path)
        self.compression = self._detect_compression()

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
        try:
            current = _identity(self.path)
        except OSError as error:
            raise SourceChanged("The selected image is no longer available") from error
        if current != self.identity:
            raise SourceChanged("The selected image changed while it was being prepared")

    def measure(
        self,
        maximum: int | None = None,
        cancel_check: CancelCheck | None = None,
    ) -> int:
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
        try:
            with self._open() as stream:
                while True:
                    if cancel_check:
                        cancel_check()
                    block = stream.read(CHUNK_SIZE)
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
            raise ImageSourceError(
                f"Could not decode {self.path.name}: {error}"
            ) from error
        self._ensure_unchanged()
        if expected_size is not None and done != expected_size:
            raise ImageSourceError(
                f"The decoded image ended at {done} bytes; expected {expected_size}"
            )

    @contextmanager
    def _open(self) -> Iterator[BinaryIO]:
        if self.compression == "none":
            with self.path.open("rb", buffering=0) as stream:
                yield stream
            return
        if self.compression == "gzip":
            with gzip.open(self.path, "rb") as stream:
                yield stream
            return
        if self.compression == "bz2":
            with bz2.open(self.path, "rb") as stream:
                yield stream
            return
        if self.compression in {"xz", "lzma"}:
            with lzma.open(self.path, "rb") as stream:
                yield stream
            return
        if self.compression == "zip":
            with zipfile.ZipFile(self.path) as archive:
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
            with self._open_zstd() as stream:
                yield stream
            return
        if self.compression == "compress-z":
            with self._open_external_decoder(
                "gzip", ("--decompress", "--stdout", "--quiet", "--")
            ) as stream:
                yield stream
            return
        raise AssertionError(f"Unsupported compression kind: {self.compression}")

    @contextmanager
    def _open_external_decoder(
        self, program: str, arguments: tuple[str, ...],
    ) -> Iterator[BinaryIO]:
        executable = shutil.which(program, path="/usr/sbin:/usr/bin:/sbin:/bin")
        if not executable:
            raise ImageSourceError(
                f"Reading {self.path.suffix} images requires the {program} command"
            )
        process = subprocess.Popen(
            [executable, *arguments, str(self.path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        assert process.stdout is not None
        try:
            yield process.stdout
        except BaseException:
            if process.poll() is None:
                process.terminate()
            process.wait()
            raise
        finally:
            process.stdout.close()
        assert process.stderr is not None
        error = process.stderr.read(16 * 1024)
        code = process.wait()
        if code:
            raise ImageSourceError(
                error.decode(errors="replace").strip()
                or f"Could not decompress the {self.path.suffix} image"
            )

    @contextmanager
    def _open_zstd(self) -> Iterator[BinaryIO]:
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError:
            zstandard = None

        if zstandard is not None:
            with self.path.open("rb", buffering=0) as compressed:
                with zstandard.ZstdDecompressor().stream_reader(compressed) as stream:
                    yield stream
            return

        executable = shutil.which("zstd", path="/usr/sbin:/usr/bin:/sbin:/bin")
        if not executable:
            raise ImageSourceError(
                "Reading .zst images requires the zstd command or Python zstandard package"
            )
        process = subprocess.Popen(
            [executable, "--decompress", "--stdout", "--quiet", "--", str(self.path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        try:
            yield process.stdout
        except BaseException:
            if process.poll() is None:
                process.terminate()
            process.wait()
            raise
        finally:
            process.stdout.close()
        assert process.stderr is not None
        error = process.stderr.read()
        code = process.wait()
        if code:
            raise ImageSourceError(
                error.decode(errors="replace").strip() or "Could not decompress the zstd image"
            )


def open_image_source(path: Path) -> ImageSource:
    return ImageSource(path)


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
