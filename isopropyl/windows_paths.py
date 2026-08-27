# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exact, portable Windows Setup install-image member paths."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

MAX_INSTALL_IMAGE_PATH_CHARACTERS = 1024
MAX_INSTALL_IMAGE_PATH_BYTES = 4096
MAX_INSTALL_IMAGE_COMPONENTS = 16
MAX_INSTALL_IMAGE_COMPONENT_BYTES = 255
MAX_INSTALL_IMAGE_COMPONENT_UTF16_UNITS = 255

_WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED_COMPONENT = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|"
    r"com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$",
    re.IGNORECASE,
)
_WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"\\|?*%')


@dataclass(frozen=True)
class InstallImageMemberPath:
    """A validated literal catalog member and its Windows alias key."""

    path: str
    components: tuple[str, ...]
    alias_key: tuple[str, ...]
    image_format: Literal["wim", "esd"]


def validate_install_image_member_path(path: object) -> InstallImageMemberPath:
    """Validate one exact media-relative install.wim or install.esd member.

    The canonical ``sources/install.esd`` is the only supported ESD spelling.
    WIM members may be canonical or nested at ``*/sources/install.wim``.  The
    returned path is never normalized: unsafe or non-canonical input is rejected
    so every caller binds the same literal catalog member.
    """

    if not isinstance(path, str) or not path:
        raise ValueError("The install image member path must be non-empty text")
    if len(path) > MAX_INSTALL_IMAGE_PATH_CHARACTERS:
        raise ValueError("The install image member path is too long")
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(
            "The install image member path contains invalid Unicode"
        ) from error
    if len(encoded) > MAX_INSTALL_IMAGE_PATH_BYTES:
        raise ValueError("The install image member path is too long")
    if unicodedata.normalize("NFC", path) != path:
        raise ValueError("The install image member path is not NFC-normalized")
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in path
    ):
        raise ValueError("The install image member path contains unsafe Unicode")
    if (
        path.startswith(("/", "\\"))
        or "\\" in path
        or _WINDOWS_DRIVE_PATH.match(path)
        or any(character in _WINDOWS_FORBIDDEN_CHARACTERS for character in path)
    ):
        raise ValueError("The install image member path has unsafe Windows path syntax")

    components = tuple(path.split("/"))
    if (
        not 2 <= len(components) <= MAX_INSTALL_IMAGE_COMPONENTS
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise ValueError("The install image member path has an unsafe component")
    for component in components:
        if component != component.strip() or component.endswith("."):
            raise ValueError("The install image member path has component whitespace or dots")
        if _WINDOWS_RESERVED_COMPONENT.fullmatch(component):
            raise ValueError("The install image member path contains a reserved device name")
        if (
            len(component.encode("utf-8")) > MAX_INSTALL_IMAGE_COMPONENT_BYTES
            or len(component.encode("utf-16-le")) // 2
            > MAX_INSTALL_IMAGE_COMPONENT_UTF16_UNITS
        ):
            raise ValueError("The install image member path has an overlong component")

    alias_key = tuple(component.casefold() for component in components)
    if alias_key[-2:] == ("sources", "install.esd"):
        if len(alias_key) != 2:
            raise ValueError("Only canonical sources/install.esd is supported")
        image_format: Literal["wim", "esd"] = "esd"
    elif alias_key[-2:] == ("sources", "install.wim"):
        image_format = "wim"
    else:
        raise ValueError("The member path does not name a supported install image")
    return InstallImageMemberPath(path, components, alias_key, image_format)
