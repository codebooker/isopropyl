#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Render the deterministic README screenshot without probing host devices."""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtWidgets import QApplication

import isopropyl.app as app_module
from isopropyl.app import STYLE, Window
from isopropyl.devices import Device
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState


def main() -> int:
    # Keep documentation rendering independent of a developer's real settings.
    with tempfile.TemporaryDirectory(prefix="isopropyl-screenshot-") as config_dir:
        os.environ["XDG_CONFIG_HOME"] = config_dir
        return _render()


def _render() -> int:
    application = QApplication([])
    application.setStyleSheet(STYLE)
    target = Device(
        "/dev/sdb", 64_000_000_000, "DataTraveler 3.0", "Kingston", "usb",
        "001122334455", "", "8:16", True, True, False, (), (),
    )
    app_module.list_devices = lambda _include_external=False: [target]
    window = Window()

    image_name = "Win11_25H2_English_x64_v2.iso"
    image_size = 8_471_603_200
    window.image = Path("/home/demo/Downloads") / image_name
    window.inspection = ImageInspection(
        size=image_size,
        kind="Optical ISO",
        volume_label="CCCOMA_X64FRE_EN-US_DV9",
        has_mbr=True,
        has_gpt=False,
        is_iso9660=True,
        looks_windows=True,
        boot_modes=("BIOS", "UEFI"),
        architectures=("x64",),
        bootloader="Windows Boot Manager",
        has_windows_installer=True,
        contents_scanned=True,
        members=(
            ImageMember("EFI", 0, "directory"),
            ImageMember("EFI/BOOT", 0, "directory"),
            ImageMember("EFI/BOOT/BOOTX64.EFI", 1_472_000, "file"),
            ImageMember("sources", 0, "directory"),
            ImageMember("sources/install.wim", 4_850_000_000, "file"),
            ImageMember("bootmgr", 410_000, "file"),
        ),
        uefi_payloads=(
            ImageUefiPayload(
                "EFI/BOOT/BOOTX64.EFI", "x64", "EFI application", True,
                SignatureTableState.PRESENT_UNVERIFIED, SbatState.ABSENT, (),
            ),
        ),
    )
    window.inspection_identity = (1, 2, image_size, 4)
    window.image_label.setText(f"{image_name}  ·  8.5 GB")
    window.image_label.setToolTip(str(window.image))
    window.windows_button.setEnabled(True)
    window.iso_plan_button.setEnabled(True)
    window.checksum_button.setEnabled(True)

    window.rebuild_write_recommendation(preserve_selection=False)
    window.status.setText("Ready when you are")

    window.resize(1080, 920)
    window.show()
    application.processEvents()
    destination = Path(__file__).resolve().parents[1] / "data" / "screenshot.png"
    if not window.grab().save(str(destination), "PNG"):
        raise RuntimeError(f"Could not save {destination}")
    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
