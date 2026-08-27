from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cooperative whole-disk locking for privileged destructive commands.

Linux BSD locks are advisory: they coordinate ISOpropyl with systemd-udevd and
other lock-aware storage tools, but cannot stop a privileged process that
deliberately ignores them.  This module therefore never calls the mechanism a
kernel-exclusive transaction lease.
"""

import os
import re
import shutil
from collections.abc import Callable, Sequence


TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_TOOL_DIRECTORIES = frozenset(TRUSTED_TOOL_PATH.split(":"))
LOCK_CONFLICT_EXIT_CODE = 75
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")


class CooperativeLockError(ValueError):
    pass


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=TRUSTED_TOOL_PATH)


def _validate_tool(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise CooperativeLockError(f"Refusing untrusted {name} path: {value!r}")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(value) != name
    ):
        raise CooperativeLockError(f"Refusing untrusted {name} path: {value!r}")
    return value


def resolve_flock(
    finder: Callable[[str], str | None] = _trusted_which,
) -> str:
    value = finder("flock")
    if not value:
        raise CooperativeLockError(
            "Cooperative destructive-command locking requires util-linux flock"
        )
    return _validate_tool("flock", value)


def cooperative_lock_command(
    pkexec: str,
    flock: str,
    whole_device: str,
    tool_argv: Sequence[str],
) -> list[str]:
    """Wrap one privileged command in a fail-fast whole-device BSD lock."""

    _validate_tool("pkexec", pkexec)
    _validate_tool("flock", flock)
    if not isinstance(whole_device, str) or not _BLOCK_PATH.fullmatch(whole_device):
        raise CooperativeLockError("A safe whole-device path is required for locking")
    if (
        not tool_argv
        or not isinstance(tool_argv[0], str)
        or not os.path.isabs(tool_argv[0])
        or os.path.normpath(tool_argv[0]) != tool_argv[0]
        or os.path.dirname(tool_argv[0]) not in TRUSTED_TOOL_DIRECTORIES
    ):
        raise CooperativeLockError(
            "The locked destructive tool must use a trusted absolute path"
        )
    if any(not isinstance(argument, str) or "\x00" in argument for argument in tool_argv):
        raise CooperativeLockError("A locked command contains an invalid argument")
    return [
        pkexec,
        flock,
        "--exclusive",
        "--nonblock",
        "--conflict-exit-code",
        str(LOCK_CONFLICT_EXIT_CODE),
        "--no-fork",
        whole_device,
        *tool_argv,
    ]


def is_cooperative_lock_command(command: Sequence[str]) -> bool:
    """Return whether *command* is one exact wrapper produced by this module."""

    if len(command) < 9:
        return False
    try:
        expected = cooperative_lock_command(
            command[0], command[1], command[7], command[8:],
        )
    except (CooperativeLockError, IndexError, TypeError):
        return False
    return list(command) == expected


def add_native_sfdisk_lock(command: Sequence[str], sfdisk: str) -> list[str]:
    """Add sfdisk's own nonblocking whole-device lock without nesting flock."""

    _validate_tool("sfdisk", sfdisk)
    values = list(command)
    try:
        index = values.index(sfdisk)
    except ValueError as error:
        raise CooperativeLockError("The command does not invoke the bound sfdisk") from error
    if any(argument == "--lock" or argument.startswith("--lock=") for argument in values):
        raise CooperativeLockError("The sfdisk command already has a lock mode")
    values.insert(index + 1, "--lock=nonblock")
    return values


def lock_conflict_message(returncode: int, fallback: str) -> str:
    if returncode == LOCK_CONFLICT_EXIT_CODE:
        return (
            "Another lock-aware storage operation is using the target drive; "
            "wait for it to finish and try again"
        )
    return fallback
