from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import configparser
import fcntl
import io
import os
import secrets
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import QSettings


PORTABLE_SETTINGS_FILENAME = "isopropyl.ini"
PORTABLE_SETTINGS_SECTION = "General"
MAX_PORTABLE_SETTINGS_BYTES = 1024 * 1024

_DIRECTORY_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_TEMP_PREFIX = f".{PORTABLE_SETTINGS_FILENAME}.tmp-"


@dataclass(frozen=True)
class ApplicationArguments:
    portable: bool
    image: Path | None


def parse_application_arguments(
    arguments: list[str] | tuple[str, ...],
) -> ApplicationArguments:
    """Parse ISOpropyl options without swallowing misspelled switches."""

    portable = False
    positional: list[str] = []
    after_options = False
    for argument in tuple(arguments)[1:]:
        if not after_options and argument == "--":
            after_options = True
        elif not after_options and argument == "--portable":
            portable = True
        elif not after_options and argument.startswith("-"):
            raise ValueError(f"Unknown option: {argument}")
        else:
            positional.append(argument)
    if len(positional) > 1:
        raise ValueError("Choose at most one image on the command line")
    return ApplicationArguments(portable, Path(positional[0]) if positional else None)


def _launcher_path(*, environment: dict[str, str], executable: str) -> tuple[Path, bool]:
    appimage = environment.get("APPIMAGE", "").strip()
    if appimage:
        candidate = Path(appimage).expanduser()
        if not candidate.is_absolute():
            raise ValueError("APPIMAGE must identify an absolute application path")
        # AppImage's convention is tied to the actual outer image, not an
        # invocation symlink.
        return candidate.resolve(strict=False), True

    candidate = Path(executable).expanduser()
    if not candidate.is_absolute() and candidate.parent == Path("."):
        located = shutil.which(str(candidate))
        if located:
            candidate = Path(located)
    # Keep the invoked launcher's final symlink component so "beside the
    # launcher" continues to mean the directory the user actually invoked.
    return Path(os.path.abspath(candidate)), False


def portable_settings_path(
    arguments: list[str] | tuple[str, ...] | None = None,
    *,
    environment: dict[str, str] | None = None,
    executable: str | None = None,
) -> Path | None:
    """Resolve explicit, marker-based, and AppImage portable settings."""

    args = tuple(sys.argv if arguments is None else arguments)
    parsed = parse_application_arguments(args)
    env = dict(os.environ if environment is None else environment)
    launcher, is_appimage = _launcher_path(
        environment=env,
        executable=sys.argv[0] if executable is None else executable,
    )

    if is_appimage:
        appimage_config = Path(f"{launcher}.config")
        try:
            info = appimage_config.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ValueError(f"Could not inspect AppImage portable config: {error}") from error
        else:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("The AppImage .config path must be a real directory")
            return appimage_config / PORTABLE_SETTINGS_FILENAME

    marker = launcher.parent / PORTABLE_SETTINGS_FILENAME
    if parsed.portable or os.path.lexists(marker):
        return marker
    return None


class PortableSettings:
    """Small QSettings-compatible store bound to no-follow descriptors.

    The parent directory, writer lock, and settings file remain open for the
    object's lifetime. Saves use a private no-follow temporary file and atomic
    replacement, so a failed write cannot truncate the live settings and a
    pathname swap cannot redirect bytes through a symlink.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._directory_fd = -1
        self._file_fd = -1
        self._status = QSettings.Status.NoError
        self.error_message = ""
        self.last_sync_committed = False
        self._values: dict[str, str] = {}
        try:
            self._directory_fd = os.open(path.parent, _DIRECTORY_FLAGS)
            directory_info = os.fstat(self._directory_fd)
            if not stat.S_ISDIR(directory_info.st_mode):
                raise OSError("Portable settings parent is not a directory")
            try:
                # Lock the pinned directory inode itself. A replaceable named
                # lock file always leaves a validation-to-publish race in which
                # another writer can lock a freshly substituted inode.
                fcntl.flock(
                    self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as error:
                raise ValueError(
                    "portable settings are already in use by another ISOpropyl instance"
                ) from error
            try:
                self._file_fd = os.open(
                    path.name, _FILE_FLAGS, dir_fd=self._directory_fd,
                )
            except FileNotFoundError:
                self._create_initial_file(
                    f"[{PORTABLE_SETTINGS_SECTION}]\n".encode("utf-8")
                )
            self._identity = self._validated_identity()
            self._values = self._read_values()
        except (OSError, ValueError, configparser.Error, UnicodeError) as error:
            self.close()
            raise ValueError(f"Portable settings are unavailable: {error}") from error

    def _validated_identity(self, descriptor: int | None = None) -> tuple[int, int]:
        checked_fd = self._file_fd if descriptor is None else descriptor
        file_info = os.fstat(checked_fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1:
            raise ValueError(
                "the settings file must be a singly linked regular file"
            )
        path_info = os.stat(
            self.path.name, dir_fd=self._directory_fd, follow_symlinks=False,
        )
        if not stat.S_ISREG(path_info.st_mode) or path_info.st_nlink != 1:
            raise ValueError("the settings pathname is a link or special file")
        if (path_info.st_dev, path_info.st_ino) != (file_info.st_dev, file_info.st_ino):
            raise ValueError("the settings pathname changed while it was opened")
        return file_info.st_dev, file_info.st_ino

    @staticmethod
    def _write_descriptor(descriptor: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("portable settings write made no progress")
            offset += written
        os.fsync(descriptor)

    def _create_temp(self, data: bytes) -> tuple[str, int]:
        descriptor = -1
        name = ""
        for _attempt in range(16):
            name = _TEMP_PREFIX + secrets.token_hex(12)
            try:
                descriptor = os.open(
                    name, _FILE_FLAGS | os.O_CREAT | os.O_EXCL, 0o600,
                    dir_fd=self._directory_fd,
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise OSError("could not allocate a private portable-settings file")
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise OSError("private portable-settings file has unsafe metadata")
            self._write_descriptor(descriptor, data)
            return name, descriptor
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(name, dir_fd=self._directory_fd)
            except OSError:
                pass
            raise

    def _create_initial_file(self, data: bytes) -> None:
        name, descriptor = self._create_temp(data)
        try:
            try:
                os.link(
                    name, self.path.name,
                    src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass
            os.unlink(name, dir_fd=self._directory_fd)
            name = ""
            os.fsync(self._directory_fd)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
            if name:
                try:
                    os.unlink(name, dir_fd=self._directory_fd)
                except OSError:
                    pass
        self._file_fd = os.open(
            self.path.name, _FILE_FLAGS, dir_fd=self._directory_fd,
        )

    def _read_values(self) -> dict[str, str]:
        size = os.fstat(self._file_fd).st_size
        if size > MAX_PORTABLE_SETTINGS_BYTES:
            raise ValueError("the settings file is larger than 1 MiB")
        os.lseek(self._file_fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(self._file_fd, min(65536, remaining))
            if not chunk:
                raise ValueError("the settings file ended unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        text = b"".join(chunks).decode("utf-8")
        if not text.strip():
            return {}
        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.read_string(text)
        if parser.defaults() or set(parser.sections()) - {PORTABLE_SETTINGS_SECTION}:
            raise ValueError("the settings file contains unsupported sections")
        if not parser.has_section(PORTABLE_SETTINGS_SECTION):
            return {}
        return dict(parser.items(PORTABLE_SETTINGS_SECTION, raw=True))

    def _serialized(self) -> bytes:
        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.add_section(PORTABLE_SETTINGS_SECTION)
        for key, value in sorted(self._values.items()):
            parser.set(PORTABLE_SETTINGS_SECTION, key, value)
        output = io.StringIO()
        parser.write(output, space_around_delimiters=False)
        data = output.getvalue().encode("utf-8")
        if len(data) > MAX_PORTABLE_SETTINGS_BYTES:
            raise ValueError("portable settings exceed the 1 MiB limit")
        return data

    def value(self, key: str, default: object = None) -> object:
        return self._values.get(key, default)

    def setValue(self, key: str, value: object) -> None:  # noqa: N802 - Qt API parity
        self._values[str(key)] = str(value)

    def remove(self, key: str) -> None:
        self._values.pop(key, None)

    def clear(self) -> None:
        self._values.clear()

    def sync(self) -> None:
        self._status = QSettings.Status.NoError
        self.error_message = ""
        self.last_sync_committed = False
        temp_name = ""
        temp_fd = -1
        try:
            if self._validated_identity() != self._identity:
                raise OSError("the portable settings file identity changed")
            temp_name, temp_fd = self._create_temp(self._serialized())
            if self._validated_identity() != self._identity:
                raise OSError("the portable settings pathname changed during save")
            replacement_info = os.fstat(temp_fd)
            if (
                not stat.S_ISREG(replacement_info.st_mode)
                or replacement_info.st_nlink != 1
                or replacement_info.st_uid != os.geteuid()
                or stat.S_IMODE(replacement_info.st_mode) != 0o600
            ):
                raise OSError("private portable-settings file changed before publish")
            replacement_identity = (
                replacement_info.st_dev, replacement_info.st_ino,
            )
            os.replace(
                temp_name, self.path.name,
                src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd,
            )
            temp_name = ""
            # The fully written and fsynced temporary descriptor is already an
            # authoritative handle to the inode that replace() just published.
            # Rebind to it before any post-commit operation can fail; reopening
            # by pathname would leave us attached to the old unlinked inode if
            # the reopen or directory durability check failed.
            old_fd = self._file_fd
            self._file_fd = temp_fd
            temp_fd = -1
            self._identity = replacement_identity
            try:
                os.close(old_fd)
            except OSError:
                pass
            self.last_sync_committed = True
            try:
                os.fsync(self._directory_fd)
            except OSError as error:
                self._status = QSettings.Status.AccessError
                self.error_message = (
                    "The settings update was committed, but its directory "
                    "durability check failed. The new settings are active, but "
                    "might not survive an unexpected power loss: "
                    f"{error}"
                )
        except (OSError, ValueError, configparser.Error, UnicodeError) as error:
            self._status = QSettings.Status.AccessError
            self.error_message = str(error)
        finally:
            if temp_fd >= 0:
                try:
                    os.close(temp_fd)
                except OSError:
                    pass
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=self._directory_fd)
                except OSError:
                    pass

    def status(self) -> QSettings.Status:
        return self._status

    def close(self) -> None:
        for attribute in ("_file_fd", "_directory_fd"):
            descriptor = getattr(self, attribute, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, attribute, -1)

    def __del__(self) -> None:
        self.close()


SettingsStore = QSettings | PortableSettings


def application_settings(
    arguments: list[str] | tuple[str, ...] | None = None,
    *,
    environment: dict[str, str] | None = None,
    executable: str | None = None,
) -> SettingsStore:
    path = portable_settings_path(
        arguments, environment=environment, executable=executable,
    )
    if path is not None:
        return PortableSettings(path)
    return QSettings("codebooker", "ISOpropyl")


def settings_sync_error(settings: SettingsStore) -> str:
    settings.sync()
    if settings.status() == QSettings.Status.NoError:
        return ""
    detail = getattr(settings, "error_message", "")
    return (
        detail if isinstance(detail, str) and detail
        else "The settings backend could not save the requested values."
    )


def settings_sync_was_committed(settings: SettingsStore) -> bool:
    """Return whether the most recent failing save crossed its commit point."""

    return (
        isinstance(settings, PortableSettings)
        and settings.status() != QSettings.Status.NoError
        and bool(getattr(settings, "last_sync_committed", False))
    )
