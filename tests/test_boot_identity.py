# SPDX-License-Identifier: AGPL-3.0-or-later

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.boot_identity import (
    BootloaderAnalysis, analyze_bootloader_blob, analyze_bootloader_members,
    analyze_iso_bootloaders, bootloader_member_paths, identify_grub_blob,
    identify_syslinux_blob,
    read_archive_member_with_7z,
)
from isopropyl.images import boot_identity_fields
from isopropyl.bootloaders import bundle_for_dependency, load_catalog


class BootIdentityTests(unittest.TestCase):
    def test_grub_package_build_is_an_exact_dependency_identity(self):
        blob = (
            b"prefix\0GNU GRUB  version %s\x002.14\0menu text\0"
            b"2.14-2ubuntu2.1\0suffix"
        )
        identity = identify_grub_blob(blob, "boot/grub/i386-pc/normal.mod")
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertEqual(identity.version, "2.14")
        self.assertEqual(identity.build, "2.14-2ubuntu2.1")
        self.assertTrue(identity.custom_build)
        self.assertTrue(identity.exact)
        self.assertEqual(identity.dependency_key, "grub:2.14-2ubuntu2.1")

    def test_bare_grub_version_does_not_claim_artifact_compatibility(self):
        identity = identify_grub_blob(b"GNU GRUB version %s\x002.06\0")
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertEqual(identity.version, "2.06")
        self.assertIsNone(identity.build)
        self.assertIsNone(identity.custom_build)
        self.assertIsNone(identity.dependency_key)
        self.assertIn("patch identity is unknown", identity.evidence[-1])

    def test_grub_custom_symbol_without_package_build_fails_closed(self):
        identity = identify_grub_blob(
            b"GNU GRUB  version %s\x002.06\0grub_debug_is_enabled\0"
        )
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertTrue(identity.custom_build)
        self.assertIsNone(identity.build)
        self.assertIsNone(identity.dependency_key)

    def test_conflicting_grub_versions_are_ambiguous(self):
        identity = identify_grub_blob(
            b"GNU GRUB version %s\x002.06\0padding\0"
            b"GNU GRUB version %s\x002.12\0"
        )
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertTrue(identity.ambiguous)
        self.assertEqual(identity.candidates, ("2.06", "2.12"))
        self.assertIsNone(identity.dependency_key)

    def test_syslinux_release_and_custom_suffix_are_parsed(self):
        release = identify_syslinux_blob(b"x" * 64 + b"ISOLINUX 6.04\0")
        self.assertIsNotNone(release)
        assert release is not None
        self.assertEqual(release.family, "Isolinux")
        self.assertEqual(release.build, "6.04")
        self.assertFalse(release.custom_build)
        self.assertEqual(release.dependency_key, "syslinux:6.04")

        custom = identify_syslinux_blob(
            b"x" * 64 + b"SYSLINUX 6.04 6.04-pre1* \0"
        )
        self.assertIsNotNone(custom)
        assert custom is not None
        self.assertEqual(custom.build, "6.04-pre1")
        self.assertTrue(custom.custom_build)
        self.assertEqual(custom.dependency_key, "syslinux:6.04-pre1")

        dated = identify_syslinux_blob(b"ISOLINUX 6.04 20251124 \0")
        self.assertIsNotNone(dated)
        assert dated is not None
        self.assertEqual(dated.build, "6.04-20251124")
        self.assertEqual(dated.dependency_key, "syslinux:6.04-20251124")

    def test_real_syslinux_markers_match_only_exact_catalog_keys(self):
        catalog = load_catalog()
        release = identify_syslinux_blob(b"ISOLINUX 6.03 2014-10-06\0")
        pre = identify_syslinux_blob(b"ISOLINUX 6.04 6.04-pre1* \0")
        assert release is not None and pre is not None
        self.assertEqual(release.dependency_key, "syslinux:6.03-2014-10-06")
        self.assertIsNotNone(
            bundle_for_dependency(release.dependency_key or "", catalog=catalog)
        )
        self.assertIsNotNone(
            bundle_for_dependency(pre.dependency_key or "", catalog=catalog)
        )
        self.assertIsNone(bundle_for_dependency("syslinux:6.03", catalog=catalog))

    def test_conflicting_syslinux_markers_fail_closed(self):
        identity = identify_syslinux_blob(
            b"ISOLINUX 4.07\0" + b"x" * 70 + b"ISOLINUX 6.04\0"
        )
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertTrue(identity.ambiguous)
        self.assertIsNone(identity.dependency_key)

    def test_invalid_syslinux_build_metadata_fails_closed(self):
        identity = identify_syslinux_blob(b"ISOLINUX 6.04 bad/build\0")
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertTrue(identity.ambiguous)
        self.assertIsNone(identity.dependency_key)

    def test_blob_analysis_does_not_guess_from_filename(self):
        result = analyze_bootloader_blob(b"not a boot payload", "grub.efi")
        self.assertEqual(result.identities, ())

    def test_payload_reader_never_uses_an_untrusted_path_7z(self):
        with patch(
            "isopropyl.boot_identity.shutil.which",
            return_value="/home/example/bin/7z",
        ) as which:
            with self.assertRaisesRegex(OSError, "not installed"):
                read_archive_member_with_7z(Path("fixture.iso"), "isolinux.bin")
        which.assert_called_once_with("7z", path="/usr/bin:/bin")

    def test_member_selection_rejects_traversal_and_is_bounded_to_payloads(self):
        selected = bootloader_member_paths([
            "../isolinux.bin", "/absolute/isolinux.bin", "C:\\isolinux.bin",
            "README", "isolinux/isolinux.bin",
            "boot/grub/i386-pc/normal.mod", "EFI/BOOT/BOOTX64.EFI",
        ])
        self.assertEqual(selected, (
            "isolinux/isolinux.bin", "boot/grub/i386-pc/normal.mod",
            "EFI/BOOT/BOOTX64.EFI",
        ))

    def test_conflicting_member_versions_do_not_resolve(self):
        result = analyze_bootloader_members({
            "isolinux/isolinux.bin": b"ISOLINUX 4.07\0",
            "legacy/isolinux.bin": b"ISOLINUX 6.04\0",
        })
        self.assertIsNone(result.resolved("Isolinux"))
        self.assertEqual(result.dependency_keys, ())
        self.assertTrue(any("Conflicting Syslinux/Isolinux" in issue for issue in result.issues))

    def test_syslinux_and_isolinux_members_share_one_dependency_lineage(self):
        result = analyze_bootloader_members({
            "isolinux/isolinux.bin": b"ISOLINUX 6.04\0",
            "syslinux/ldlinux.sys": b"SYSLINUX 4.07\0",
        })
        self.assertIsNone(result.resolved("Syslinux/Isolinux"))
        self.assertEqual(result.dependency_keys, ())

    def test_iso_reader_is_injected_and_only_receives_candidates(self):
        calls: list[str] = []

        def reader(_image: Path, member: str) -> bytes:
            calls.append(member)
            return b"ISOLINUX 6.04\0"

        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"test")
            result = analyze_iso_bootloaders(
                image, ["README", "isolinux/isolinux.bin"], reader=reader
            )
        self.assertEqual(calls, ["isolinux/isolinux.bin"])
        self.assertEqual(result.dependency_keys, ("syslinux:6.04",))

    def test_overall_iso_analysis_time_limit_fails_closed(self):
        calls = 0

        def reader(_image: Path, _member: str) -> bytes:
            nonlocal calls
            calls += 1
            return b"ISOLINUX 6.04\0"

        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"test")
            result = analyze_iso_bootloaders(
                image, ["one/isolinux.bin", "two/isolinux.bin"],
                reader=reader, timeout=-1,
            )
        self.assertEqual(calls, 0)
        self.assertTrue(any("time limit" in issue for issue in result.issues))
        self.assertFalse(result.complete)
        self.assertEqual(result.dependency_keys, ())

    def test_excess_candidates_disable_exact_dependency_matching(self):
        consumed = 0

        def candidates():
            nonlocal consumed
            for index in range(1_000_000):
                consumed += 1
                yield f"candidate-{index}/isolinux.bin"

        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"test")
            result = analyze_iso_bootloaders(
                image, candidates(), reader=lambda _image, _member: b"ISOLINUX 6.04\0",
            )

        self.assertEqual(consumed, 65)
        self.assertEqual(len(result.identities), 64)
        self.assertFalse(result.complete)
        self.assertIsNone(result.resolved("Syslinux/Isolinux"))
        self.assertEqual(result.dependency_keys, ())
        self.assertTrue(any("more than 64" in issue for issue in result.issues))

    def test_failed_candidate_read_disables_resolution(self):
        def reader(_image: Path, member: str) -> bytes:
            if member.startswith("broken/"):
                raise OSError("fixture read failure")
            return b"ISOLINUX 6.04\0"

        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"test")
            result = analyze_iso_bootloaders(
                image, ["good/isolinux.bin", "broken/isolinux.bin"], reader=reader,
            )

        self.assertFalse(result.complete)
        self.assertEqual(result.dependency_keys, ())

    def test_incomplete_boot_scan_does_not_label_windows_identity_ambiguous(self):
        analysis = BootloaderAnalysis((), ("fixture read failed",), False)
        fields = boot_identity_fields(analysis, "Windows Boot Manager")
        self.assertFalse(fields[3])
        self.assertTrue(boot_identity_fields(analysis, "GRUB")[3])


if __name__ == "__main__":
    unittest.main()
