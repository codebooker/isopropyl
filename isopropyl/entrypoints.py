"""Select the host integration before importing platform-specific modules."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import sys

from .host_platform import validate_host


def _supported() -> bool:
    try:
        validate_host()
        return True
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return False


def gui() -> int:
    if not _supported():
        return 2
    if sys.platform == "linux":
        from .app import main
    elif sys.platform in {"darwin", "win32"}:
        from .native_app import main
    else:
        print(f"Unsupported operating system: {sys.platform}", file=sys.stderr)
        return 2
    return main()


def cli() -> int:
    if not _supported():
        return 2
    if sys.platform == "linux":
        from .cli import main
    elif sys.platform in {"darwin", "win32"}:
        from .native_cli import main
    else:
        print(f"Unsupported operating system: {sys.platform}", file=sys.stderr)
        return 2
    return main()
