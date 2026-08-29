from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Load and independently reproduce the bundled Rufus prompt MBR bootstrap."""

import hashlib
import os
import stat
import subprocess
import tempfile
from importlib import resources
from pathlib import Path


RUFUS_PROMPT_MBR_RESOURCE = "data/rufus-prompt-mbr-440.bin"
RUFUS_PROMPT_MBR_SIZE = 440
RUFUS_PROMPT_MBR_SHA256 = (
    "4fca7dcfac9f90390d00ab42c2e814952fbce41c83aa87c5c696e663efd60259"
)
RUFUS_PROMPT_MBR_FULL_SIZE = 512
RUFUS_PROMPT_MBR_FULL_SHA256 = (
    "3d92fffb6efd81da6ff44017f5b6b5696d781a1890c0c0c4834442e7bdccd632"
)
RUFUS_PROMPT_MBR_UPSTREAM_COMMIT = (
    "2368e49a82e854d3e702f824648cc723953dbb53"
)
RUFUS_PROMPT_MBR_SOURCE_SHA256 = (
    "f6a831462d1cfefa739362223f31c61f8ad8d11466c6c0cc96ab2c646f002684"
)
RUFUS_PROMPT_MBR_LINKER_SHA256 = (
    "03f3b06050e5aa4af1f2187d22fb4841a31ebbef43aaccb690e8da0263409771"
)
_MAX_TOOL_OUTPUT = 64 * 1024


class RufusPromptMbrError(ValueError):
    """The packaged asset or its corresponding-source reproduction is invalid."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_rufus_prompt_mbr() -> bytes:
    """Return the exact bootstrap bytes, excluding mutable MBR metadata."""

    value = resources.files("isopropyl").joinpath(RUFUS_PROMPT_MBR_RESOURCE).read_bytes()
    if len(value) != RUFUS_PROMPT_MBR_SIZE or _digest(value) != RUFUS_PROMPT_MBR_SHA256:
        raise RufusPromptMbrError("The packaged Rufus prompt MBR does not match its pin")
    return value


def _trusted_build_tool(path: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
        status = resolved.stat(follow_symlinks=False)
        parent = resolved.parent.stat(follow_symlinks=False)
    except OSError as error:
        raise RufusPromptMbrError(f"The required build tool is unavailable: {path}") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or not status.st_mode & 0o111
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
    ):
        raise RufusPromptMbrError(f"The required build tool is not trusted: {path}")


def _source(source_root: Path, relative: str, expected_sha256: str) -> Path:
    path = source_root / relative
    try:
        status = path.lstat()
        value = path.read_bytes()
    except OSError as error:
        raise RufusPromptMbrError(f"The Rufus build input is unavailable: {relative}") from error
    if not stat.S_ISREG(status.st_mode) or path.is_symlink() or _digest(value) != expected_sha256:
        raise RufusPromptMbrError(f"The Rufus build input does not match its pin: {relative}")
    return path


def _run(command: tuple[str, ...]) -> None:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RufusPromptMbrError("The Rufus prompt MBR reproduction could not run") from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_TOOL_OUTPUT
        or len(completed.stderr) > _MAX_TOOL_OUTPUT
    ):
        raise RufusPromptMbrError("The Rufus prompt MBR reproduction failed")


def verify_reproducible_rufus_prompt_mbr(
    source_root: Path,
    *,
    assembler: Path = Path("/usr/bin/as"),
    linker: Path = Path("/usr/bin/ld"),
    objcopy: Path = Path("/usr/bin/objcopy"),
) -> bytes:
    """Rebuild Rufus's full MBR and require its 440-byte bootstrap to match."""

    if not isinstance(source_root, Path) or not source_root.is_absolute():
        raise RufusPromptMbrError("The source root must be an absolute Path")
    for tool in (assembler, linker, objcopy):
        _trusted_build_tool(tool)
    source = _source(
        source_root,
        "third_party/rufus/res/mbr/mbr.S",
        RUFUS_PROMPT_MBR_SOURCE_SHA256,
    )
    linker_script = _source(
        source_root,
        "third_party/rufus/res/mbr/mbr.ld",
        RUFUS_PROMPT_MBR_LINKER_SHA256,
    )
    packaged = load_rufus_prompt_mbr()
    with tempfile.TemporaryDirectory(prefix="isopropyl-rufus-mbr-build-") as directory:
        build = Path(directory)
        object_path = build / "mbr.o"
        linked_path = build / "mbr.out"
        binary_path = build / "mbr.bin"
        _run((os.fspath(assembler), "--32", "-o", os.fspath(object_path), os.fspath(source)))
        _run(
            (
                os.fspath(linker), "-m", "elf_i386", "-T", os.fspath(linker_script),
                "-o", os.fspath(linked_path), os.fspath(object_path),
            )
        )
        _run(
            (
                os.fspath(objcopy), "-O", "binary", "-j", ".main",
                "--gap-fill=0x00", os.fspath(linked_path), os.fspath(binary_path),
            )
        )
        try:
            full_mbr = binary_path.read_bytes()
        except OSError as error:
            raise RufusPromptMbrError("The reproduction produced no MBR") from error
    if (
        len(full_mbr) != RUFUS_PROMPT_MBR_FULL_SIZE
        or _digest(full_mbr) != RUFUS_PROMPT_MBR_FULL_SHA256
        or full_mbr[:RUFUS_PROMPT_MBR_SIZE] != packaged
        or full_mbr[510:] != b"\x55\xaa"
    ):
        raise RufusPromptMbrError("The Rufus sources do not reproduce the packaged bootstrap")
    return packaged
