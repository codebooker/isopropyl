from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.distro_policies import (
    DistroIsoPolicy,
    DistroPolicyCatalogError,
    DistroPolicyEvidenceError,
    load_distro_iso_policies,
    match_distro_iso_exclusion,
    match_distro_member_exclusion,
)
from isopropyl.images import ImageInspection, ImageMember


def inspection(
    *members: ImageMember,
    contents_scanned: object = True,
    is_iso9660: object = True,
) -> ImageInspection:
    return ImageInspection(
        size=1024,
        kind="Optical ISO" if is_iso9660 is True else "Raw image",
        volume_label="TEST",
        has_mbr=True,
        has_gpt=False,
        is_iso9660=is_iso9660,  # type: ignore[arg-type]
        looks_windows=False,
        boot_modes=("UEFI",),
        architectures=("x64",),
        bootloader="GRUB",
        has_windows_installer=False,
        contents_scanned=contents_scanned,  # type: ignore[arg-type]
        members=tuple(members),
    )


def catalog_policy(
    *,
    policy_id: str = "fixture-policy",
    match: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": policy_id,
        "distribution": "Fixture Linux",
        "reason": "The fixture layout must retain its native disk structure.",
        "source_url": "https://example.org/project/compatibility",
        "source_description": "Distribution-owned fixture documentation.",
        "match": match or {"kind": "exact_file", "path": "marker"},
    }


class DistroPolicyCatalogTests(unittest.TestCase):
    def _load(self, value: object) -> tuple[DistroIsoPolicy, ...]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policies.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_distro_iso_policies(path)

    def _assert_rejected(self, value: object, message: str = "") -> None:
        with self.assertRaises(DistroPolicyCatalogError) as raised:
            self._load(value)
        if message:
            self.assertIn(message.casefold(), str(raised.exception).casefold())

    def test_bundled_catalog_has_only_the_three_audited_exclusions(self):
        policies = load_distro_iso_policies()

        self.assertEqual(
            tuple(policy.policy_id for policy in policies),
            (
                "manjaro-miso-layout",
                "proxmox-native-layout",
                "pop-os-casper-layout",
            ),
        )
        self.assertEqual(
            {policy.match_kind for policy in policies},
            {
                "exact_file",
                "direct_child_file",
                "direct_named_file_in_root_fragment",
            },
        )
        for policy in policies:
            self.assertTrue(policy.source_url.startswith("https://github.com/"))
            self.assertIn("2368e49a", policy.source_url)
            self.assertTrue(policy.source_description)
        with self.assertRaises(FrozenInstanceError):
            policies[0].reason = "changed"  # type: ignore[misc]

    def test_catalog_schema_types_and_match_shapes_are_exact(self):
        valid = {"catalog_version": 1, "policies": [catalog_policy()]}
        self.assertEqual(len(self._load(valid)), 1)

        cases = []
        for version in (True, 1.0, 2):
            value = json.loads(json.dumps(valid))
            value["catalog_version"] = version
            cases.append((value, "version"))
        value = json.loads(json.dumps(valid))
        value["extra"] = False
        cases.append((value, "fields"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["unknown"] = "value"
        cases.append((value, "fields"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["match"] = {
            "kind": "exact_file", "path": "marker", "fragment": "extra",
        }
        cases.append((value, "fields"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["match"] = {"kind": "regex", "path": ".*"}
        cases.append((value, "unsupported"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["match"] = {
            "kind": "direct_named_file_in_root_fragment",
            "root_prefix": "a/b", "fragment": "x", "filename": "file",
        }
        cases.append((value, "component"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["match"] = {
            "kind": "exact_file", "path": "UPPER",
        }
        cases.append((value, "lowercase"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["source_url"] = "http://example.org/source"
        cases.append((value, "HTTPS"))
        value = json.loads(json.dumps(valid))
        value["policies"][0]["source_url"] = "https://example.org/source?mutable=1"
        cases.append((value, "HTTPS"))

        for value, message in cases:
            with self.subTest(message=message):
                self._assert_rejected(value, message)

    def test_catalog_rejects_duplicate_fields_ids_and_predicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"catalog_version":1,"catalog_version":1,"policies":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DistroPolicyCatalogError, "repeats"):
                load_distro_iso_policies(path)

        first = catalog_policy()
        duplicate_id = catalog_policy(
            policy_id="fixture-policy",
            match={"kind": "exact_file", "path": "another"},
        )
        self._assert_rejected(
            {"catalog_version": 1, "policies": [first, duplicate_id]},
            "IDs",
        )
        duplicate_match = catalog_policy(policy_id="another-policy")
        self._assert_rejected(
            {"catalog_version": 1, "policies": [first, duplicate_match]},
            "predicates",
        )

    def test_catalog_count_and_bytes_are_bounded(self):
        policies = [
            catalog_policy(
                policy_id=f"fixture-{index}",
                match={"kind": "exact_file", "path": f"marker-{index}"},
            )
            for index in range(33)
        ]
        self._assert_rejected(
            {"catalog_version": 1, "policies": policies}, "count",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (64 * 1024 + 1))
            with self.assertRaisesRegex(DistroPolicyCatalogError, "size limit"):
                load_distro_iso_policies(path)


class DistroPolicyMatchTests(unittest.TestCase):
    def test_member_matcher_and_complete_iso_wrapper_return_same_matches(self):
        examples = (
            (ImageMember(".MISO", 1, "file"),),
            (ImageMember("PROXMOX/pve-base.squashfs", 1, "file"),),
            (
                ImageMember(
                    "CASPER_POP-OS_24.04_AMD64/filesystem.squashfs",
                    1,
                    "file",
                ),
            ),
        )
        for members in examples:
            with self.subTest(members=members):
                self.assertEqual(
                    match_distro_member_exclusion(members),
                    match_distro_iso_exclusion(inspection(*members)),
                )

    def test_member_matcher_requires_exact_immutable_member_types(self):
        marker = ImageMember(".miso", 1, "file")
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "immutable"):
            match_distro_member_exclusion([marker])  # type: ignore[arg-type]
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "invalid type"):
            match_distro_member_exclusion((object(),))  # type: ignore[arg-type]
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "invalid type"):
            match_distro_member_exclusion((
                ImageMember(".miso", 1, "file", modified_ns=True),
            ))

    def test_member_matcher_does_not_implicitly_include_separate_overlay_entries(self):
        base_members = (ImageMember("EFI/BOOT/BOOTX64.EFI", 1, "file"),)
        overlay_members = (ImageMember(".miso", 1, "file"),)

        self.assertIsNone(match_distro_member_exclusion(base_members))
        overlay_match = match_distro_member_exclusion(overlay_members)
        self.assertIsNotNone(overlay_match)
        assert overlay_match is not None
        self.assertEqual(overlay_match.policy_id, "manjaro-miso-layout")
        self.assertIsNone(match_distro_member_exclusion(base_members))

    def test_manjaro_requires_the_root_regular_miso_marker(self):
        match = match_distro_iso_exclusion(inspection(
            ImageMember(".MISO", 1, "file"),
        ))
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.policy_id, "manjaro-miso-layout")
        self.assertEqual(match.distribution, "Manjaro")
        self.assertFalse(hasattr(match, "write_mode"))

        for member in (
            ImageMember("boot/.miso", 1, "file"),
            ImageMember(".miso", 1, "directory"),
            ImageMember(".miso", 1, "symlink", "elsewhere"),
            ImageMember("miso", 1, "file"),
        ):
            with self.subTest(member=member):
                self.assertIsNone(match_distro_iso_exclusion(inspection(member)))

    def test_proxmox_requires_a_regular_direct_child_of_the_root_directory(self):
        member = ImageMember("PROXMOX/pve-base.squashfs", 1, "file")
        match = match_distro_iso_exclusion(inspection(member))
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.policy_id, "proxmox-native-layout")

        for member in (
            ImageMember("ProxMox", 0, "directory"),
            ImageMember("proxmox/boot/linux26", 1, "file"),
            ImageMember("proxmox/pve-base.squashfs", 0, "directory"),
            ImageMember("myproxmox/file", 1, "file"),
            ImageMember("images/proxmox/file", 1, "file"),
            ImageMember("proxmox", 1, "file"),
        ):
            with self.subTest(member=member):
                self.assertIsNone(match_distro_iso_exclusion(inspection(member)))

    def test_pop_os_requires_pop_os_inside_the_same_casper_root_component(self):
        match = match_distro_iso_exclusion(inspection(
            ImageMember(
                "CASPER_POP-OS_24.04_AMD64/filesystem.squashfs", 1, "file",
            ),
        ))
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.policy_id, "pop-os-casper-layout")

        near_misses = (
            (
                ImageMember("casper/filesystem.squashfs", 1, "file"),
                ImageMember("docs/pop-os/readme", 1, "file"),
            ),
            (ImageMember("images/casper-pop-os/file", 1, "file"),),
            (ImageMember("pop-os-casper/file", 1, "file"),),
            (ImageMember("casper-pop-os", 0, "directory"),),
            (ImageMember("casper-pop-os/readme", 1, "file"),),
            (
                ImageMember(
                    "casper-pop-os/nested/filesystem.squashfs", 1, "file",
                ),
            ),
            (ImageMember("casper-pop-os", 1, "symlink", "casper"),),
        )
        for members in near_misses:
            with self.subTest(members=members):
                self.assertIsNone(match_distro_iso_exclusion(inspection(*members)))

    def test_only_complete_iso_catalogs_can_produce_an_exclusion(self):
        marker = ImageMember(".miso", 1, "file")
        for candidate in (
            inspection(marker, contents_scanned=False),
            inspection(marker, contents_scanned=1),
            inspection(marker, is_iso9660=False),
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(match_distro_iso_exclusion(candidate))

        udf_optical = replace(
            inspection(marker), is_iso9660=False, kind="Optical ISO",
        )
        self.assertIsNotNone(match_distro_iso_exclusion(udf_optical))

    def test_ascii_case_matching_does_not_fold_compatibility_characters(self):
        for member in (
            ImageMember(".miſo", 1, "file"),
            ImageMember(
                "caſper-pop-os/filesystem.squashfs", 1, "file",
            ),
        ):
            with self.subTest(member=member):
                self.assertIsNone(match_distro_iso_exclusion(inspection(member)))

    def test_member_normalization_is_nfc_and_case_insensitive(self):
        catalog = {
            "catalog_version": 1,
            "policies": [catalog_policy(
                match={"kind": "exact_file", "path": "caf\u00e9.marker"},
            )],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policies.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            policies = load_distro_iso_policies(path)

        match = match_distro_iso_exclusion(
            inspection(ImageMember("CAFE\u0301.MARKER", 1, "file")), policies,
        )
        self.assertIsNotNone(match)

    def test_unsafe_or_ambiguous_complete_evidence_raises(self):
        for member in (
            ImageMember("../.miso", 1, "file"),
            ImageMember("/.miso", 1, "file"),
            ImageMember("dir\\.miso", 1, "file"),
            ImageMember("dir//.miso", 1, "file"),
        ):
            with self.subTest(member=member):
                with self.assertRaises(DistroPolicyEvidenceError):
                    match_distro_iso_exclusion(inspection(member))

        collision = inspection(
            ImageMember("Proxmox/file", 1, "file"),
            ImageMember("PROXMOX/FILE", 1, "file"),
        )
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "collision"):
            match_distro_iso_exclusion(collision)

        malformed_size = inspection(ImageMember(".miso", True, "file"))
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "invalid type"):
            match_distro_iso_exclusion(malformed_size)

        inconsistent_links = (
            ImageMember(".miso", 1, "file", "target"),
            ImageMember(".miso", 1, "directory", "target"),
            ImageMember(".miso", 1, "symlink"),
        )
        for member in inconsistent_links:
            with self.subTest(member=member):
                with self.assertRaisesRegex(
                    DistroPolicyEvidenceError, "inconsistent",
                ):
                    match_distro_member_exclusion((member,))

        with patch("isopropyl.distro_policies.MAX_IMAGE_MEMBERS", 1):
            with self.assertRaisesRegex(DistroPolicyEvidenceError, "bound"):
                match_distro_iso_exclusion(inspection(
                    ImageMember("one", 1, "file"),
                    ImageMember("two", 1, "file"),
                ))

    def test_policy_inputs_are_immutable_and_bounded(self):
        candidate = inspection(ImageMember("marker", 1, "file"))
        policies = load_distro_iso_policies()
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "immutable"):
            match_distro_iso_exclusion(candidate, list(policies))  # type: ignore[arg-type]
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "ImageInspection"):
            match_distro_iso_exclusion(object())  # type: ignore[arg-type]
        malformed = replace(policies[0], path=True)  # type: ignore[arg-type]
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "policy data"):
            match_distro_iso_exclusion(candidate, (malformed,))
        duplicated = (policies[0], policies[0])
        with self.assertRaisesRegex(DistroPolicyEvidenceError, "duplicated"):
            match_distro_iso_exclusion(candidate, duplicated)
