#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Opt-in, device-free FreeDOS boot certification under QEMU TCG.

This development tool accepts an already extracted catalog image.  It never
opens block devices and never gives QEMU the source pathname: QEMU sees only an
inherited, sealed in-memory snapshot of a catalog-bound regular file.  VGA text
is collected noninteractively through QEMU's curses display and a private
pseudo-terminal.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

# Direct execution puts ``tools/`` rather than the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.freedos_downloads import (
    FreeDosImageRelease,
    load_freedos_image_catalog,
)


BOOT_MARKERS = (
    "Booting from Hard Disk...",
    "FreeDOS kernel 2043",
    "FreeCom version 0.86",
    "Done processing startup files FDCONFIG.SYS and FDAUTO.BAT",
)
DEFAULT_TIMEOUT = 90
MIN_TIMEOUT = 5
MAX_TIMEOUT = 300
SCREEN_ROWS = 25
SCREEN_COLUMNS = 80
MAX_TERMINAL_STREAM = 4 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_VERSION_BYTES = 16 * 1024
STOP_GRACE_SECONDS = 3
QEMU_VERSION_TIMEOUT = 5
DEFAULT_EXECUTABLE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
REQUIRED_MEMFD_SEALS = (
    getattr(fcntl, "F_SEAL_WRITE", 0)
    | getattr(fcntl, "F_SEAL_GROW", 0)
    | getattr(fcntl, "F_SEAL_SHRINK", 0)
    | getattr(fcntl, "F_SEAL_SEAL", 0)
)


class BootCertificationError(RuntimeError):
    """The image could not be safely certified."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass
class VerifiedImage:
    path: Path
    release: FreeDosImageRelease
    fd: int
    identity: FileIdentity
    sha256: str
    snapshot_fd: int

    def close(self) -> None:
        if self.snapshot_fd >= 0:
            os.close(self.snapshot_fd)
            self.snapshot_fd = -1
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "VerifiedImage":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass
class QemuIdentity:
    path: Path
    fd: int
    identity: FileIdentity
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "QemuIdentity":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class BootCapture:
    markers: tuple[str, ...]
    terminal_stream_bytes: int
    elapsed_seconds: float


def _identity(status: os.stat_result) -> FileIdentity:
    return FileIdentity(
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _sha256_fd(fd: int, size: int, *, description: str = "image") -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise BootCertificationError(
                f"The {description} became truncated while hashing"
            )
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(fd, 1, size):
        raise BootCertificationError(f"The {description} grew while hashing")
    return digest.hexdigest()


def _write_all(fd: int, data: bytes, offset: int) -> None:
    written = 0
    while written < len(data):
        count = os.pwrite(fd, data[written:], offset + written)
        if count <= 0:
            raise BootCertificationError("Could not populate the sealed image snapshot")
        written += count


def _copy_hash_and_seal(source_fd: int, size: int) -> tuple[int, str]:
    required = (
        "memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING",
    )
    if any(not hasattr(os, name) for name in required):
        raise BootCertificationError("Safe certification requires Linux sealed memfd support")
    seal_names = (
        "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
        "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL",
    )
    if any(not hasattr(fcntl, name) for name in seal_names):
        raise BootCertificationError("Safe certification requires Linux file seals")

    writable_fd = -1
    readonly_fd = -1
    try:
        writable_fd = os.memfd_create(
            "isopropyl-freedos-verified",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            chunk = os.pread(source_fd, min(1024 * 1024, size - offset), offset)
            if not chunk:
                raise BootCertificationError(
                    "The image became truncated while creating its sealed snapshot"
                )
            digest.update(chunk)
            _write_all(writable_fd, chunk, offset)
            offset += len(chunk)
        if os.pread(source_fd, 1, size):
            raise BootCertificationError(
                "The image grew while creating its sealed snapshot"
            )
        if os.fstat(writable_fd).st_size != size:
            raise BootCertificationError("The sealed image snapshot has the wrong size")
        fcntl.fcntl(writable_fd, fcntl.F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        seals = fcntl.fcntl(writable_fd, fcntl.F_GET_SEALS)
        if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
            raise BootCertificationError("The in-memory image snapshot could not be sealed")
        readonly_fd = os.open(
            f"/proc/self/fd/{writable_fd}", os.O_RDONLY | os.O_CLOEXEC,
        )
        if _sha256_fd(readonly_fd, size, description="sealed image snapshot") != digest.hexdigest():
            raise BootCertificationError("The sealed image snapshot does not match its source")
        result = readonly_fd
        readonly_fd = -1
        return result, digest.hexdigest()
    except OSError as error:
        raise BootCertificationError(
            f"Could not create a sealed image snapshot: {error}"
        ) from error
    finally:
        if readonly_fd >= 0:
            os.close(readonly_fd)
        if writable_fd >= 0:
            os.close(writable_fd)


def _matching_release(
    path: Path, catalog: Sequence[FreeDosImageRelease],
) -> FreeDosImageRelease:
    matches = [release for release in catalog if release.image_filename == path.name]
    if len(matches) != 1:
        raise BootCertificationError(
            "The image filename must exactly match one project-catalog image"
        )
    return matches[0]


def _path_identity(path: Path, *, description: str = "image") -> FileIdentity:
    try:
        return _identity(path.stat(follow_symlinks=False))
    except OSError as error:
        raise BootCertificationError(
            f"Could not recheck the {description} path: {error}"
        ) from error


def open_verified_image(
    image_path: Path,
    *,
    catalog: Sequence[FreeDosImageRelease] | None = None,
) -> VerifiedImage:
    """Bind and verify one catalog image without ever opening a device for I/O."""

    path = Path(os.path.abspath(os.fspath(image_path)))
    releases = tuple(load_freedos_image_catalog() if catalog is None else catalog)
    release = _matching_release(path, releases)
    if not hasattr(os, "O_PATH"):
        raise BootCertificationError("Safe image binding requires Linux O_PATH support")

    path_fd = -1
    data_fd = -1
    snapshot_fd = -1
    try:
        # O_PATH obtains a name handle without opening a device driver.  With
        # O_NOFOLLOW it also binds a symlink itself, which is rejected below.
        path_fd = os.open(
            path,
            os.O_PATH | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        path_status = os.fstat(path_fd)
        if not stat.S_ISREG(path_status.st_mode):
            raise BootCertificationError("The image must be a no-follow regular file")
        if path_status.st_size != release.image_size:
            raise BootCertificationError("The image size does not match the project catalog")

        data_fd = os.open(f"/proc/self/fd/{path_fd}", os.O_RDONLY | os.O_CLOEXEC)
        before = _identity(os.fstat(data_fd))
        if before.device != path_status.st_dev or before.inode != path_status.st_ino:
            raise BootCertificationError("The image identity changed while it was opened")
        snapshot_fd, digest = _copy_hash_and_seal(data_fd, release.image_size)
        after_hash = _identity(os.fstat(data_fd))
        if after_hash != before or _path_identity(path) != before:
            raise BootCertificationError("The image changed while its source hash was verified")
        if digest != release.image_sha256:
            raise BootCertificationError("The image SHA-256 does not match the project catalog")
        result = VerifiedImage(
            path, release, data_fd, before, digest, snapshot_fd,
        )
        data_fd = -1
        snapshot_fd = -1
        return result
    except OSError as error:
        raise BootCertificationError(f"Could not safely open the image: {error}") from error
    finally:
        if data_fd >= 0:
            os.close(data_fd)
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        if path_fd >= 0:
            os.close(path_fd)


def verify_image_unchanged(image: VerifiedImage) -> None:
    """Recheck the original and sealed snapshot after QEMU."""

    current = _identity(os.fstat(image.fd))
    if current != image.identity or _path_identity(image.path) != image.identity:
        raise BootCertificationError("The source image identity changed during certification")
    digest = _sha256_fd(image.fd, image.release.image_size)
    if (
        _identity(os.fstat(image.fd)) != image.identity
        or _path_identity(image.path) != image.identity
    ):
        raise BootCertificationError("The source image changed during the final hash")
    if digest != image.sha256 or digest != image.release.image_sha256:
        raise BootCertificationError("The source image hash changed during certification")
    try:
        snapshot_status = os.fstat(image.snapshot_fd)
        seals = fcntl.fcntl(image.snapshot_fd, fcntl.F_GET_SEALS)
    except OSError as error:
        raise BootCertificationError(
            f"Could not recheck the sealed image snapshot: {error}"
        ) from error
    if not stat.S_ISREG(snapshot_status.st_mode):
        raise BootCertificationError("The sealed image snapshot is no longer regular")
    if snapshot_status.st_size != image.release.image_size:
        raise BootCertificationError("The sealed image snapshot changed size")
    if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        raise BootCertificationError("The image snapshot lost its required seals")
    if (
        _sha256_fd(
            image.snapshot_fd,
            image.release.image_size,
            description="sealed image snapshot",
        )
        != image.sha256
    ):
        raise BootCertificationError("The sealed image snapshot changed during certification")


def resolve_qemu(path: Path | None = None) -> QemuIdentity:
    if path is None:
        found = shutil.which(
            "qemu-system-x86_64", path=DEFAULT_EXECUTABLE_PATH,
        )
        if found is None:
            raise BootCertificationError("qemu-system-x86_64 is not installed")
        candidate = Path(found)
    else:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise BootCertificationError("The QEMU executable path must be absolute")
    fd = -1
    try:
        resolved = candidate.resolve(strict=True)
        fd = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        status = os.fstat(fd)
    except OSError as error:
        if fd >= 0:
            os.close(fd)
        raise BootCertificationError(f"Could not resolve qemu-system-x86_64: {error}") from error
    if resolved.name != "qemu-system-x86_64":
        os.close(fd)
        raise BootCertificationError("The executable must be named qemu-system-x86_64")
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or not os.access(resolved, os.X_OK)
    ):
        os.close(fd)
        raise BootCertificationError(
            "qemu-system-x86_64 must be an executable, non-set-ID regular file"
        )
    identity = _identity(status)
    try:
        digest = _sha256_fd(fd, status.st_size, description="QEMU executable")
        if (
            _identity(os.fstat(fd)) != identity
            or _path_identity(resolved, description="QEMU executable") != identity
        ):
            raise BootCertificationError(
                "qemu-system-x86_64 changed while it was bound"
            )
        return QemuIdentity(resolved, fd, identity, digest)
    except BaseException:
        os.close(fd)
        raise


def _descriptor_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"


def build_qemu_command(qemu_fd: int, source_fd: int) -> tuple[str, ...]:
    """Build the fixed device-free TCG/snapshot QEMU command."""

    # -add-fd preserves the descriptor's O_RDONLY access mode.  /dev/fdset/1
    # is QEMU's internal fd-set name, not a host device node.
    return (
        _descriptor_path(qemu_fd),
        "-no-user-config",
        "-sandbox",
        "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
        "-machine", "pc,accel=tcg",
        "-cpu", "qemu32",
        "-m", "64M",
        "-snapshot",
        "-boot", "order=c,strict=on",
        "-add-fd", f"fd={source_fd},set=1,opaque=freedos-source",
        "-drive",
        (
            "file=/dev/fdset/1,if=ide,index=0,media=disk,"
            "format=raw,snapshot=on"
        ),
        "-nic", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-display", "curses,charset=CP437",
        "-no-reboot",
        "-no-shutdown",
    )


class TerminalScreenCapture:
    """Apply a bounded ANSI/VT stream to one fixed 80x25 text screen.

    Evidence is accepted only when an entire marker exists contiguously in a
    rendered row.  Cursor movement, erasure, and overwrites therefore cannot
    concatenate unrelated byte-stream fragments into a false marker.
    """

    def __init__(self, limit: int = MAX_TERMINAL_STREAM) -> None:
        self._limit = limit
        self._stream_bytes = 0
        self._screen = [list(" " * SCREEN_COLUMNS) for _ in range(SCREEN_ROWS)]
        self._row = 0
        self._column = 0
        self._saved_cursor = (0, 0)
        self._scroll_top = 0
        self._scroll_bottom = SCREEN_ROWS - 1
        self._wrap_pending = False
        self._state = "text"
        self._csi = bytearray()
        self._escape_in_string = False
        self._markers: list[str] = []

    @property
    def size(self) -> int:
        return self._stream_bytes

    @property
    def markers(self) -> tuple[str, ...]:
        return tuple(self._markers)

    @property
    def complete(self) -> bool:
        return len(self._markers) == len(BOOT_MARKERS)

    @property
    def screen_text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self._screen)

    def _blank_row(self) -> list[str]:
        return list(" " * SCREEN_COLUMNS)

    def _check_row(self, row: int) -> None:
        if self.complete:
            return
        expected = BOOT_MARKERS[len(self._markers)]
        if expected in "".join(self._screen[row]):
            self._markers.append(expected)

    def _index(self) -> None:
        self._wrap_pending = False
        if self._row == self._scroll_bottom:
            del self._screen[self._scroll_top]
            self._screen.insert(self._scroll_bottom, self._blank_row())
        else:
            self._row = min(SCREEN_ROWS - 1, self._row + 1)

    def _reverse_index(self) -> None:
        self._wrap_pending = False
        if self._row == self._scroll_top:
            del self._screen[self._scroll_bottom]
            self._screen.insert(self._scroll_top, self._blank_row())
        else:
            self._row = max(0, self._row - 1)

    def _put(self, character: str) -> None:
        if self._wrap_pending:
            self._column = 0
            self._index()
        self._screen[self._row][self._column] = character
        self._check_row(self._row)
        if self._column == SCREEN_COLUMNS - 1:
            self._wrap_pending = True
        else:
            self._column += 1

    @staticmethod
    def _parameters(raw: bytes) -> list[int]:
        text = raw.decode("ascii", "ignore")
        while text[:1] in ("?", ">", "!", "="):
            text = text[1:]
        values: list[int] = []
        for item in text.split(";"):
            try:
                values.append(int(item, 10) if item else 0)
            except ValueError:
                values.append(0)
        return values or [0]

    @staticmethod
    def _count(parameters: list[int], index: int = 0) -> int:
        if index >= len(parameters) or parameters[index] == 0:
            return 1
        return parameters[index]

    def _cursor(self, row: int, column: int) -> None:
        self._row = min(max(row, 0), SCREEN_ROWS - 1)
        self._column = min(max(column, 0), SCREEN_COLUMNS - 1)
        self._wrap_pending = False

    def _erase_display(self, mode: int) -> None:
        if mode in (2, 3):
            self._screen = [self._blank_row() for _ in range(SCREEN_ROWS)]
        elif mode == 0:
            self._screen[self._row][self._column:] = [
                " "
            ] * (SCREEN_COLUMNS - self._column)
            for row in range(self._row + 1, SCREEN_ROWS):
                self._screen[row] = self._blank_row()
        elif mode == 1:
            for row in range(0, self._row):
                self._screen[row] = self._blank_row()
            self._screen[self._row][:self._column + 1] = [
                " "
            ] * (self._column + 1)

    def _erase_line(self, mode: int) -> None:
        if mode == 0:
            self._screen[self._row][self._column:] = [
                " "
            ] * (SCREEN_COLUMNS - self._column)
        elif mode == 1:
            self._screen[self._row][:self._column + 1] = [
                " "
            ] * (self._column + 1)
        elif mode == 2:
            self._screen[self._row] = self._blank_row()

    def _handle_csi(self, final: int) -> None:
        parameters = self._parameters(bytes(self._csi))
        character = chr(final)
        self._wrap_pending = False
        if character in ("H", "f"):
            row = self._count(parameters, 0) - 1
            column = self._count(parameters, 1) - 1
            self._cursor(row, column)
        elif character == "A":
            self._cursor(self._row - self._count(parameters), self._column)
        elif character == "B":
            self._cursor(self._row + self._count(parameters), self._column)
        elif character == "C":
            self._cursor(self._row, self._column + self._count(parameters))
        elif character == "D":
            self._cursor(self._row, self._column - self._count(parameters))
        elif character == "E":
            self._cursor(self._row + self._count(parameters), 0)
        elif character == "F":
            self._cursor(self._row - self._count(parameters), 0)
        elif character in ("G", "`"):
            self._cursor(self._row, self._count(parameters) - 1)
        elif character == "d":
            self._cursor(self._count(parameters) - 1, self._column)
        elif character == "J":
            self._erase_display(parameters[0])
        elif character == "K":
            self._erase_line(parameters[0])
        elif character == "s":
            self._saved_cursor = (self._row, self._column)
        elif character == "u":
            self._cursor(*self._saved_cursor)
        elif character == "r":
            top = self._count(parameters, 0) - 1
            bottom = (
                self._count(parameters, 1) - 1
                if len(parameters) > 1 and parameters[1]
                else SCREEN_ROWS - 1
            )
            if 0 <= top < bottom < SCREEN_ROWS:
                self._scroll_top, self._scroll_bottom = top, bottom
                self._cursor(0, 0)
        elif character == "@":
            count = min(self._count(parameters), SCREEN_COLUMNS - self._column)
            row = self._screen[self._row]
            row[self._column:self._column] = [" "] * count
            del row[SCREEN_COLUMNS:]
            self._check_row(self._row)
        elif character == "P":
            count = min(self._count(parameters), SCREEN_COLUMNS - self._column)
            row = self._screen[self._row]
            del row[self._column:self._column + count]
            row.extend([" "] * count)
            self._check_row(self._row)
        elif character == "X":
            count = min(self._count(parameters), SCREEN_COLUMNS - self._column)
            self._screen[self._row][self._column:self._column + count] = [
                " "
            ] * count
        elif character == "L" and self._scroll_top <= self._row <= self._scroll_bottom:
            count = min(self._count(parameters), self._scroll_bottom - self._row + 1)
            for _ in range(count):
                self._screen.insert(self._row, self._blank_row())
                del self._screen[self._scroll_bottom + 1]
        elif character == "M" and self._scroll_top <= self._row <= self._scroll_bottom:
            count = min(self._count(parameters), self._scroll_bottom - self._row + 1)
            for _ in range(count):
                del self._screen[self._row]
                self._screen.insert(self._scroll_bottom, self._blank_row())
        elif character == "S":
            count = min(
                self._count(parameters), self._scroll_bottom - self._scroll_top + 1,
            )
            for _ in range(count):
                del self._screen[self._scroll_top]
                self._screen.insert(self._scroll_bottom, self._blank_row())
        elif character == "T":
            count = min(
                self._count(parameters), self._scroll_bottom - self._scroll_top + 1,
            )
            for _ in range(count):
                del self._screen[self._scroll_bottom]
                self._screen.insert(self._scroll_top, self._blank_row())

    def _handle_escape(self, byte: int) -> None:
        if byte == ord("["):
            self._state = "csi"
            self._csi.clear()
        elif byte in (ord("]"), ord("P"), ord("^"), ord("_")):
            self._state = "string"
            self._escape_in_string = False
        elif byte in b"()*+-./":
            self._state = "escape-one"
        else:
            self._state = "text"
            if byte == ord("7"):
                self._saved_cursor = (self._row, self._column)
            elif byte == ord("8"):
                self._cursor(*self._saved_cursor)
            elif byte == ord("D"):
                self._index()
            elif byte == ord("E"):
                self._column = 0
                self._index()
            elif byte == ord("M"):
                self._reverse_index()
            elif byte == ord("c"):
                self._screen = [self._blank_row() for _ in range(SCREEN_ROWS)]
                self._cursor(0, 0)
                self._scroll_top, self._scroll_bottom = 0, SCREEN_ROWS - 1

    def feed(self, data: bytes) -> None:
        if self._stream_bytes + len(data) > self._limit:
            raise BootCertificationError("QEMU produced too much terminal output")
        self._stream_bytes += len(data)
        for byte in data:
            if self._state == "text":
                if byte == 0x1B:
                    self._state = "escape"
                elif 0x20 <= byte <= 0x7E:
                    self._put(chr(byte))
                elif byte == 0x08:
                    self._cursor(self._row, self._column - 1)
                elif byte == 0x09:
                    self._cursor(self._row, min((self._column // 8 + 1) * 8, SCREEN_COLUMNS - 1))
                elif byte in (0x0A, 0x0B, 0x0C):
                    self._index()
                elif byte == 0x0D:
                    self._cursor(self._row, 0)
            elif self._state == "escape":
                self._handle_escape(byte)
            elif self._state == "csi":
                if 0x40 <= byte <= 0x7E:
                    self._handle_csi(byte)
                    self._state = "text"
                    self._csi.clear()
                elif len(self._csi) < 128:
                    self._csi.append(byte)
                else:
                    raise BootCertificationError("QEMU produced an overlong terminal escape")
            elif self._state == "escape-one":
                self._state = "text"
            elif self._state == "string":
                if byte == 0x07 or (self._escape_in_string and byte == ord("\\")):
                    self._state = "text"
                    self._escape_in_string = False
                else:
                    self._escape_in_string = byte == 0x1B


def _bounded_diagnostic(data: bytearray) -> str:
    return bytes(data).decode("utf-8", "replace").strip()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_process_group(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.025)
    return True


def _stop_and_reap(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    group_gone = _wait_for_process_group(process_group, STOP_GRACE_SECONDS)
    if not group_gone:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise BootCertificationError("QEMU could not be reaped after SIGKILL") from error
    if not _wait_for_process_group(process_group, STOP_GRACE_SECONDS):
        raise BootCertificationError(
            "The QEMU process group remained after SIGKILL"
        )


def verify_qemu_unchanged(qemu: QemuIdentity) -> None:
    try:
        current = _identity(os.fstat(qemu.fd))
    except OSError as error:
        raise BootCertificationError(f"Could not recheck QEMU: {error}") from error
    if (
        current != qemu.identity
        or _path_identity(qemu.path, description="QEMU executable") != qemu.identity
    ):
        raise BootCertificationError("qemu-system-x86_64 changed during certification")
    digest = _sha256_fd(
        qemu.fd, qemu.identity.size, description="QEMU executable",
    )
    if (
        digest != qemu.sha256
        or _identity(os.fstat(qemu.fd)) != qemu.identity
        or _path_identity(qemu.path, description="QEMU executable") != qemu.identity
    ):
        raise BootCertificationError("qemu-system-x86_64 changed during certification")


def query_qemu_version(qemu: QemuIdentity) -> str:
    """Return bounded version evidence from the bound QEMU descriptor."""

    verify_qemu_unchanged(qemu)
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    timed_out = False
    try:
        process = subprocess.Popen(
            (_descriptor_path(qemu.fd), "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            pass_fds=(qemu.fd,),
            start_new_session=True,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH,
            },
        )
        if process.stdout is None:
            raise BootCertificationError("QEMU version output pipe was not created")
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + QEMU_VERSION_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if process.poll() is not None and not selector.get_map():
                break
            for key, _mask in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                elif len(output) < MAX_VERSION_BYTES:
                    available = MAX_VERSION_BYTES - len(output)
                    output.extend(chunk[:available])
        if timed_out:
            raise BootCertificationError("QEMU version query timed out")
    except OSError as error:
        raise BootCertificationError(f"Could not query QEMU version: {error}") from error
    finally:
        selector.close()
        if process is not None:
            _stop_and_reap(process)
            if process.stdout is not None:
                process.stdout.close()
    if process is None or process.returncode != 0:
        raise BootCertificationError("QEMU version query failed")
    verify_qemu_unchanged(qemu)
    decoded = bytes(output).decode("utf-8", "replace")
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise BootCertificationError("QEMU returned no version information")
    version = "".join(character for character in lines[0] if character.isprintable())
    if not version:
        raise BootCertificationError("QEMU returned invalid version information")
    return version[:512]


def capture_qemu_boot(
    qemu: QemuIdentity,
    source_fd: int,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> BootCapture:
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be an integer from {MIN_TIMEOUT} to {MAX_TIMEOUT}")

    verify_qemu_unchanged(qemu)
    command = build_qemu_command(qemu.fd, source_fd)
    master_fd = -1
    slave_fd = -1
    process: subprocess.Popen[bytes] | None = None
    terminal = TerminalScreenCapture()
    diagnostic = bytearray()
    started = time.monotonic()
    deadline = started + timeout
    selector = selectors.DefaultSelector()
    complete = False
    try:
        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(slave_fd, termios_tiocswinsz(), struct.pack("HHHH", 25, 80, 0, 0))
        os.set_blocking(master_fd, False)
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": DEFAULT_EXECUTABLE_PATH,
            "TERM": "xterm-256color",
        }
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(qemu.fd, source_fd),
            start_new_session=True,
            env=environment,
        )
        os.close(slave_fd)
        slave_fd = -1
        selector.register(master_fd, selectors.EVENT_READ, "terminal")
        if process.stderr is None:
            raise BootCertificationError("QEMU diagnostic pipe was not created")
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stderr, selectors.EVENT_READ, "diagnostic")

        while True:
            if terminal.complete:
                complete = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if process.poll() is not None and not selector.get_map():
                break
            events = selector.select(min(remaining, 0.25))
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO and key.data == "terminal":
                        chunk = b""
                    elif error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    else:
                        raise BootCertificationError(
                            f"Could not read QEMU {key.data} output: {error}"
                        ) from error
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "terminal":
                    terminal.feed(chunk)
                elif len(diagnostic) < MAX_DIAGNOSTIC_BYTES:
                    available = MAX_DIAGNOSTIC_BYTES - len(diagnostic)
                    diagnostic.extend(chunk[:available])

        if not complete:
            missing = list(BOOT_MARKERS[len(terminal.markers):])
            reason = (
                "QEMU exited before certification"
                if process.poll() is not None
                else "QEMU boot timed out"
            )
            details = _bounded_diagnostic(diagnostic)
            suffix = f"; diagnostic: {details}" if details else ""
            raise BootCertificationError(
                f"{reason}; missing exact markers: {missing!r}{suffix}"
            )
        return BootCapture(
            terminal.markers,
            terminal.size,
            round(time.monotonic() - started, 3),
        )
    except OSError as error:
        raise BootCertificationError(f"Could not run qemu-system-x86_64: {error}") from error
    finally:
        selector.close()
        stop_error: BootCertificationError | None = None
        if process is not None:
            try:
                _stop_and_reap(process)
            except BootCertificationError as error:
                stop_error = error
            if process.stderr is not None:
                process.stderr.close()
        if master_fd >= 0:
            os.close(master_fd)
        if slave_fd >= 0:
            os.close(slave_fd)
        if stop_error is not None:
            raise stop_error


def termios_tiocswinsz() -> int:
    """Keep the platform constant behind a tiny unit-testable boundary."""

    import termios

    return termios.TIOCSWINSZ


def certify_freedos_boot(
    image_path: Path,
    *,
    qemu_path: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    if os.geteuid() == 0:
        raise BootCertificationError(
            "FreeDOS certification refuses to run QEMU as root"
        )
    with resolve_qemu(qemu_path) as qemu, open_verified_image(image_path) as image:
        qemu_version = query_qemu_version(qemu)
        # The original is rechecked after all preparatory subprocess work and
        # immediately before the sealed snapshot is handed to QEMU.
        verify_image_unchanged(image)
        capture_error: BaseException | None = None
        capture: BootCapture | None = None
        try:
            capture = capture_qemu_boot(qemu, image.snapshot_fd, timeout=timeout)
        except BaseException as error:
            capture_error = error
        try:
            verify_image_unchanged(image)
            verify_qemu_unchanged(qemu)
        except BootCertificationError:
            raise
        if capture_error is not None:
            raise capture_error
        assert capture is not None

        return {
            "schema_version": 1,
            "certified": True,
            "release_id": image.release.id,
            "image_filename": image.release.image_filename,
            "image_size": image.release.image_size,
            "image_sha256": image.release.image_sha256,
            "markers": list(capture.markers),
            "capture": {
                "method": "qemu-curses-private-pty-80x25-screen",
                "terminal_stream_bytes": capture.terminal_stream_bytes,
                "elapsed_seconds": capture.elapsed_seconds,
            },
            "isolation": {
                "acceleration": "tcg",
                "snapshot": True,
                "source_read_only": True,
                "source_sealed_memfd": True,
                "network": "none",
                "attached_host_block_devices": [],
                "unprivileged_process": True,
                "qemu_executable_set_id": False,
                "qemu_seccomp": True,
                "qemu_seccomp_policy": (
                    "on,obsolete=deny,spawn=deny,resourcecontrol=deny"
                ),
            },
            "qemu": {
                "executable": str(qemu.path),
                "sha256": qemu.sha256,
                "version": qemu_version,
            },
        }


def _timeout(value: str) -> int:
    try:
        timeout = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be from {MIN_TIMEOUT} to {MAX_TIMEOUT} seconds"
        )
    return timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="already extracted catalog .img path")
    parser.add_argument(
        "--run",
        action="store_true",
        help=(
            "explicitly opt in to booting the verified image under TCG QEMU "
            "with no attached host devices"
        ),
    )
    parser.add_argument("--qemu", type=Path, help="absolute qemu-system-x86_64 path")
    parser.add_argument("--timeout", type=_timeout, default=DEFAULT_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("certification is opt-in; pass --run to start QEMU")
    try:
        observation = certify_freedos_boot(
            args.image, qemu_path=args.qemu, timeout=args.timeout,
        )
    except (BootCertificationError, ValueError) as error:
        print(f"certification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
