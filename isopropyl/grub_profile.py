"""Device-free exact GRUB rescue profile shared by all hosts."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import hashlib,hmac,struct
from .bootloaders import BoundBootArtifact,BoundBootBundle
from .fat32_layout import SECTOR_SIZE,PARTITION_START_SECTOR
PROFILE_ID = "io.github.codebooker.isopropyl/grub-2.14-bios-rescue/v1"


RESULT_SEMANTICS = "intentional-rescue-prompt"


GRUB_FAMILY = "grub"


GRUB_VERSION = "2.14"


GRUB_PURPOSE = "blank-bios-rescue-media"


GRUB_LICENSE = "GPL-3.0-or-later"


GRUB_PROVENANCE_URL = (
    "https://github.com/pbatard/rufus/tree/"
    "6d8fbf98305ff37eb531c45cbd6ff44563c53917/res/grub2"
)


BOOT_IMAGE_SIZE = 512


BOOT_IMAGE_SHA256 = "b31c4cf688e8e16ddd177b619c20b049940bab5c675f877a1aa84a15e1e6e2e6"


BOOTSTRAP_SIZE = 432


BOOTSTRAP_SHA256 = "82d8879ed51b42cab56ad071eb3b0d28d60cd83d57f24fe788014a639940e41e"


CORE_OFFSET = SECTOR_SIZE


CORE_SIZE = 42_742


CORE_SHA256 = "9a2c946704017fa8dc4e03a8a58d754d2d1607c2d2cd74f0e2920133f1192809"


CORE_PADDED_SIZE = ((CORE_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE


CORE_BLOCKLIST_OFFSET = 0x1F4


CORE_BLOCKLIST = bytes.fromhex("020000000000000053002008")


EMBEDDING_LIMIT = PARTITION_START_SECTOR * SECTOR_SIZE


class GrubRescueError(RuntimeError):
    """An exact GRUB BIOS rescue image could not be proven safe."""


def _artifact(
    bundle: BoundBootBundle,
    name: str,
    size: int,
    digest: str,
) -> BoundBootArtifact:
    matches = tuple(item for item in bundle.artifacts if item.name == name)
    if len(matches) != 1:
        raise GrubRescueError(f"The GRUB bundle lacks one exact {name}")
    item = matches[0]
    if (
        type(item) is not BoundBootArtifact
        or type(item.data) is not bytes
        or type(item.sha256) is not str
        or item.size != size
        or item.sha256 != digest
        or not hmac.compare_digest(hashlib.sha256(item.data).hexdigest(), digest)
    ):
        raise GrubRescueError(f"The GRUB {name} payload is not the exact catalog artifact")
    return item


def _validate_bundle(bundle: BoundBootBundle) -> tuple[bytes, bytes]:
    if (
        type(bundle) is not BoundBootBundle
        or bundle.family != GRUB_FAMILY
        or bundle.version != GRUB_VERSION
        or bundle.purpose != GRUB_PURPOSE
        or bundle.license != GRUB_LICENSE
        or bundle.provenance_url != GRUB_PROVENANCE_URL
        or type(bundle.artifacts) is not tuple
        or tuple(item.name for item in bundle.artifacts) != ("boot.img", "core.img")
    ):
        raise GrubRescueError("An exact GRUB 2.14 rescue-media bundle is required")
    boot = _artifact(bundle, "boot.img", BOOT_IMAGE_SIZE, BOOT_IMAGE_SHA256).data
    core = _artifact(bundle, "core.img", CORE_SIZE, CORE_SHA256).data
    bootstrap = boot[:BOOTSTRAP_SIZE]
    if (
        len(bootstrap) != BOOTSTRAP_SIZE
        or not hmac.compare_digest(hashlib.sha256(bootstrap).hexdigest(), BOOTSTRAP_SHA256)
        or struct.unpack_from("<Q", bootstrap, 0x5C)[0] != 1
        or bootstrap[0x64] != 0xFF
        or bootstrap[0x66:0x68] != b"\x90\x90"
    ):
        raise GrubRescueError("The GRUB boot image has an unexpected first-stage layout")
    if (
        CORE_BLOCKLIST_OFFSET + len(CORE_BLOCKLIST) > len(core)
        or core[
            CORE_BLOCKLIST_OFFSET:CORE_BLOCKLIST_OFFSET + len(CORE_BLOCKLIST)
        ] != CORE_BLOCKLIST
    ):
        raise GrubRescueError("The GRUB core image has an unexpected diskboot blocklist")
    return boot, core


