from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Conservative persistence-profile detection and planning.

Execution is intentionally separate: changing hybrid partition layouts and
boot arguments must be validated per distribution release on real hardware.
"""

import re
from dataclasses import dataclass

from .images import ImageInspection

MIB = 1024 * 1024
MIN_PERSISTENCE_BYTES = 256 * MIB
ALIGNMENT_BYTES = MIB


class PersistenceError(ValueError):
    pass


@dataclass(frozen=True)
class PersistenceProfile:
    family: str
    filesystem: str
    label: str
    boot_parameter: str
    configuration_path: str = ""
    configuration_contents: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class PersistencePlan:
    profile: PersistenceProfile
    partition_bytes: int
    minimum_bytes: int
    blocker: str

    @property
    def executable(self) -> bool:
        return False


def _paths(inspection: ImageInspection) -> set[str]:
    return {
        member.path.replace("\\", "/").casefold().lstrip("/")
        for member in inspection.members
    }


def detect_persistence_profile(
    inspection: ImageInspection,
) -> PersistenceProfile | None:
    paths = _paths(inspection)
    label = inspection.volume_label.casefold()
    if "tails" in label:
        # Tails deliberately manages encrypted persistence inside the running
        # OS. A generic writer must not substitute an unencrypted partition.
        return None
    has_casper = any(path.startswith("casper/") for path in paths) and any(
        path.startswith("casper/vmlinuz") for path in paths
    )
    if has_casper and any(name in label for name in ("ubuntu", "mint", "pop_os", "pop-os")):
        old_release = bool(re.search(r"(?:^|[^0-9])1[468]\.\d{2}(?:[^0-9]|$)", label))
        persistent_label = "casper-rw" if old_release else "writable"
        return PersistenceProfile(
            family="casper",
            filesystem="ext4",
            label=persistent_label,
            boot_parameter="persistent",
            evidence=("casper kernel tree", f"volume label {inspection.volume_label!r}"),
        )
    has_live_boot = (
        any(path.startswith("live/vmlinuz") for path in paths)
        and any(path.startswith("live/filesystem.squashfs") for path in paths)
    )
    if has_live_boot and any(name in label for name in ("debian", "kali")):
        return PersistenceProfile(
            family="debian-live-boot",
            filesystem="ext4",
            label="persistence",
            boot_parameter="persistence",
            configuration_path="persistence.conf",
            configuration_contents="/ union\n",
            evidence=("Debian live-boot tree", f"volume label {inspection.volume_label!r}"),
        )
    return None


def build_persistence_plan(
    inspection: ImageInspection,
    partition_bytes: int,
) -> PersistencePlan:
    profile = detect_persistence_profile(inspection)
    if profile is None:
        raise PersistenceError(
            "This image is not in ISOpropyl's conservative Ubuntu/Mint/Debian/Kali persistence matrix"
        )
    if not isinstance(partition_bytes, int) or isinstance(partition_bytes, bool):
        raise PersistenceError("Persistence size must be an integer number of bytes")
    if partition_bytes < MIN_PERSISTENCE_BYTES:
        raise PersistenceError("Persistence partitions must be at least 256 MiB")
    if partition_bytes % ALIGNMENT_BYTES:
        raise PersistenceError("Persistence size must be aligned to 1 MiB")
    return PersistencePlan(
        profile,
        partition_bytes,
        MIN_PERSISTENCE_BYTES,
        "Persistence execution awaits per-release boot-config and partition-layout testing.",
    )
