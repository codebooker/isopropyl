"""Supported host CPUs, independent of the image's guest architecture."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import platform
import struct
import sys
from pathlib import Path

SUPPORTED_HOSTS = {
    "linux": {"x86_64", "arm64"},
    "win32": {"x86_64", "arm64"},
    "darwin": {"arm64"},
}


def validate_host(host=None, machine=None, pointer_bits=None) -> tuple[str, str]:
    host = host or sys.platform
    machine = (machine or platform.machine()).lower()
    cpu = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    pointer_bits = pointer_bits if pointer_bits is not None else struct.calcsize("P") * 8
    if pointer_bits != 64 or cpu not in SUPPORTED_HOSTS.get(host, set()):
        raise RuntimeError(
            f"Unsupported host: {host}/{machine} ({pointer_bits}-bit Python). "
            "Use native 64-bit Python: Linux or Windows x86-64/ARM64, or macOS Apple silicon ARM64."
        )
    return host, cpu


def x86_binutil(name: str) -> Path:
    """The bundled legacy BIOS code targets x86 even on an ARM64 Linux host."""
    if name not in {"as", "ld", "objcopy"}:
        raise ValueError("Unknown BIOS build tool")
    prefix = "x86_64-linux-gnu-" if platform.machine().lower() in {"arm64", "aarch64"} else ""
    return Path(f"/usr/bin/{prefix}{name}")
