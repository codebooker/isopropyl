# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.uefi_shell import (
    UEFI_SHELL_FAMILY,
    UEFI_SHELL_LICENSE,
    UEFI_SHELL_PROVENANCE_URL,
    UEFI_SHELL_PURPOSE,
    UEFI_SHELL_VERSION,
    UefiShellArtifactProfile,
    UefiShellError,
    UefiShellSafetyError,
    prepare_uefi_shell,
    stage_uefi_shell,
    validate_uefi_shell_bundle,
    validate_uefi_shell_stage,
)


def make_pe(machine: int, *, pe32: bool = False, subsystem: int = 10) -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0 if pe32 else 0xF0
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, 0)
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    directory_count_offset = 92 if pe32 else 108
    struct.pack_into("<I", data, optional + directory_count_offset, 16)
    return bytes(data)


def fixture_bundle() -> tuple[tuple[UefiShellArtifactProfile, ...], BoundBootBundle]:
    values = (
        ("shellaa64.efi", "EFI/BOOT/BOOTAA64.EFI", "ARM64", make_pe(0xAA64)),
        ("shellia32.efi", "EFI/BOOT/BOOTIA32.EFI", "x86", make_pe(0x014C, pe32=True)),
        (
            "shellloongarch64.efi", "EFI/BOOT/BOOTLOONGARCH64.EFI",
            "LoongArch64", make_pe(0x6264),
        ),
        (
            "shellriscv64.efi", "EFI/BOOT/BOOTRISCV64.EFI",
            "RISC-V64", make_pe(0x5064),
        ),
        ("shellx64.efi", "EFI/BOOT/BOOTX64.EFI", "x64", make_pe(0x8664)),
    )
    profiles = tuple(UefiShellArtifactProfile(
        name, fallback, architecture, len(data), hashlib.sha256(data).hexdigest(),
    ) for name, fallback, architecture, data in values)
    artifacts = tuple(BoundBootArtifact(
        name, data, hashlib.sha256(data).hexdigest(),
    ) for name, _fallback, _architecture, data in values)
    return profiles, BoundBootBundle(
        UEFI_SHELL_FAMILY, UEFI_SHELL_VERSION, UEFI_SHELL_PURPOSE, artifacts,
        UEFI_SHELL_LICENSE, UEFI_SHELL_PROVENANCE_URL,
    )


class UefiShellTests(unittest.TestCase):
    def test_exact_bundle_validates_every_architecture_and_is_immutable(self):
        profiles, bundle = fixture_bundle()
        with patch("isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles):
            prepared = validate_uefi_shell_bundle(bundle)
        self.assertEqual(
            tuple(payload.architecture for payload in prepared.payloads),
            ("ARM64", "x86", "LoongArch64", "RISC-V64", "x64"),
        )
        self.assertEqual(prepared.total_size, 5 * 512)
        self.assertIsInstance(prepared.payloads[0].data, bytes)

    def test_prepare_uses_only_the_exact_catalog_bundle(self):
        profiles, bundle = fixture_bundle()
        with (
            patch("isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles),
            patch("isopropyl.uefi_shell.prepare_bundle", return_value=bundle) as acquire,
        ):
            prepared = prepare_uefi_shell(overall_timeout=42)
        acquire.assert_called_once()
        self.assertEqual(
            acquire.call_args.args,
            (UEFI_SHELL_FAMILY, UEFI_SHELL_VERSION, UEFI_SHELL_PURPOSE),
        )
        self.assertEqual(acquire.call_args.kwargs["overall_timeout"], 42)
        self.assertEqual(prepared.version, UEFI_SHELL_VERSION)

    def test_bundle_rejects_wrong_architecture_hash_or_metadata(self):
        profiles, bundle = fixture_bundle()
        first = bundle.artifacts[0]
        wrong_arch = BoundBootArtifact(
            first.name, make_pe(0x8664), hashlib.sha256(make_pe(0x8664)).hexdigest(),
        )
        wrong_profile = UefiShellArtifactProfile(
            profiles[0].source_name, profiles[0].fallback_path,
            profiles[0].architecture, len(wrong_arch.data), wrong_arch.sha256,
        )
        with patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS",
            (wrong_profile, *profiles[1:]),
        ):
            with self.assertRaisesRegex(UefiShellError, "architecture or subsystem"):
                validate_uefi_shell_bundle(BoundBootBundle(
                    bundle.family, bundle.version, bundle.purpose,
                    (wrong_arch, *bundle.artifacts[1:]), bundle.license,
                    bundle.provenance_url,
                ))

        damaged = bytearray(first.data)
        damaged[-1] ^= 1
        with patch("isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles):
            with self.assertRaisesRegex(UefiShellError, "exact release verification"):
                validate_uefi_shell_bundle(BoundBootBundle(
                    bundle.family, bundle.version, bundle.purpose,
                    (BoundBootArtifact(first.name, bytes(damaged), first.sha256),
                     *bundle.artifacts[1:]),
                    bundle.license, bundle.provenance_url,
                ))
            with self.assertRaisesRegex(UefiShellError, "metadata is not exact"):
                validate_uefi_shell_bundle(BoundBootBundle(
                    bundle.family, "future", bundle.purpose, bundle.artifacts,
                    bundle.license, bundle.provenance_url,
                ))

    def test_stages_selected_fallback_loaders_and_revalidates(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles,
        ):
            prepared = validate_uefi_shell_bundle(bundle)
            root = Path(directory) / "private-stage"
            stage = stage_uefi_shell(
                prepared, root, architectures=("x64", "ARM64"),
            )
            self.assertEqual(stage.architectures, ("ARM64", "x64"))
            self.assertEqual(
                {path.relative_to(root).as_posix() for path in root.rglob("*")},
                {
                    "EFI", "EFI/BOOT", "EFI/BOOT/BOOTAA64.EFI",
                    "EFI/BOOT/BOOTX64.EFI", "README.txt",
                },
            )
            self.assertIn("Secure Boot", (root / "README.txt").read_text("ascii"))
            self.assertIs(validate_uefi_shell_stage(stage), stage)

    def test_staging_refuses_existing_paths_links_and_unknown_architectures(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles,
        ):
            prepared = validate_uefi_shell_bundle(bundle)
            base = Path(directory)
            existing = base / "existing"
            existing.mkdir()
            with self.assertRaises(UefiShellSafetyError):
                stage_uefi_shell(prepared, existing)
            real = base / "real"
            real.mkdir()
            linked = base / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(UefiShellSafetyError):
                stage_uefi_shell(prepared, linked / "stage")
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                stage_uefi_shell(prepared, base / "never-created", architectures=("MIPS",))
            self.assertFalse((base / "never-created").exists())

    def test_cancellation_returns_no_stage_and_tampering_is_detected(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles,
        ):
            prepared = validate_uefi_shell_bundle(bundle)
            cancelled = threading.Event()
            cancelled.set()
            cancelled_root = Path(directory) / "cancelled"
            with self.assertRaisesRegex(UefiShellError, "cancelled"):
                stage_uefi_shell(prepared, cancelled_root, cancel_event=cancelled)
            self.assertFalse(cancelled_root.exists())

            root = Path(directory) / "stage"
            stage = stage_uefi_shell(prepared, root, architectures=("x64",))
            loader = root / "EFI" / "BOOT" / "BOOTX64.EFI"
            loader.chmod(0o600)
            loader.write_bytes(b"tampered")
            with self.assertRaises(UefiShellSafetyError):
                validate_uefi_shell_stage(stage)

    def test_short_os_writes_are_completed(self):
        profiles, bundle = fixture_bundle()
        real_write = os.write

        def short_write(descriptor, value):
            return real_write(descriptor, value[:7])

        with tempfile.TemporaryDirectory() as directory, patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles,
        ), patch("isopropyl.uefi_shell.os.write", side_effect=short_write):
            prepared = validate_uefi_shell_bundle(bundle)
            stage = stage_uefi_shell(
                prepared, Path(directory) / "short", architectures=("x64",),
            )
            self.assertEqual(stage.files[-1].size, 512)

    def test_parent_path_replacement_never_returns_a_stage(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch(
            "isopropyl.uefi_shell.UEFI_SHELL_ARTIFACTS", profiles,
        ):
            prepared = validate_uefi_shell_bundle(bundle)
            container = Path(directory)
            parent = container / "parent"
            parent.mkdir()
            moved = container / "moved"
            from isopropyl import uefi_shell
            inspect_tree = uefi_shell._inspect_stage_tree

            def replace_parent(root_fd, architectures):
                parent.rename(moved)
                parent.mkdir()
                return inspect_tree(root_fd, architectures)

            with patch(
                "isopropyl.uefi_shell._inspect_stage_tree", side_effect=replace_parent,
            ), self.assertRaisesRegex(UefiShellSafetyError, "parent path changed"):
                stage_uefi_shell(
                    prepared, parent / "stage", architectures=("x64",),
                )
            self.assertFalse((parent / "stage").exists())


if __name__ == "__main__":
    unittest.main()
