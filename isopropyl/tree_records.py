"""Shared portable tree records and component validation."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
_WINDOWS_DEVICE = re.compile(r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$",re.IGNORECASE)
_FAT_FORBIDDEN = frozenset('<>:"/\\|?*')
class StagingTreeSafetyError(RuntimeError):
    """A staging tree cannot be proven stable, portable, and regular."""


@dataclass(frozen=True)
class StagedDirectory:
    parts: tuple[str, ...]
    device: int
    inode: int
    modified_ns: int
    changed_ns: int

    @property
    def path(self) -> str:
        return PurePosixPath(*self.parts).as_posix() if self.parts else "."


@dataclass(frozen=True)
class StagedFile:
    parts: tuple[str, ...]
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    link_count: int

    @property
    def path(self) -> str:
        return PurePosixPath(*self.parts).as_posix()


def validate_staged_component(component: str, rendered_path: str) -> None:
    if not component or component in {".", ".."} or "\x00" in component:
        raise StagingTreeSafetyError(f"Unsafe staged path: {rendered_path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in component):
        raise StagingTreeSafetyError(
            f"Control character in staged path: {rendered_path!r}"
        )
    if any(character in _FAT_FORBIDDEN for character in component):
        raise StagingTreeSafetyError(
            f"FAT32-incompatible character in staged path: {rendered_path!r}"
        )
    if component.endswith((" ", ".")):
        raise StagingTreeSafetyError(
            f"Trailing dot or space in staged path: {rendered_path!r}"
        )
    if _WINDOWS_DEVICE.fullmatch(unicodedata.normalize("NFC", component)):
        raise StagingTreeSafetyError(
            f"Reserved FAT32 device name in staged path: {rendered_path!r}"
        )
    try:
        utf16_units = len(component.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise StagingTreeSafetyError(
            f"Staged path is not valid Unicode: {rendered_path!r}"
        ) from error
    if utf16_units > 255:
        raise StagingTreeSafetyError(
            f"Staged path component exceeds the FAT32 name limit: {rendered_path!r}"
        )


