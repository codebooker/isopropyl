# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.runtime_validation as runtime_validation
from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle, load_catalog
from isopropyl.runtime_validation import (
    RUNTIME_VALIDATION_FAMILY,
    RUNTIME_VALIDATION_LICENSE,
    RUNTIME_VALIDATION_PROVENANCE_URL,
    RUNTIME_VALIDATION_PURPOSE,
    RUNTIME_VALIDATION_VERSION,
    RuntimeValidationArtifactProfile,
    RuntimeValidationCancelled,
    RuntimeValidationError,
    RuntimeValidationSafetyError,
    analyze_runtime_validation_compatibility,
    apply_runtime_validation,
    prepare_runtime_validation,
    validate_prepared_runtime_validation,
    validate_runtime_validation_bundle,
    validate_runtime_validation_stage,
)
from isopropyl.uefi import SignatureTableState


MACHINES = {
    "ARM64": (0xAA64, False),
    "Thumb": (0x01C2, True),
    "x86": (0x014C, True),
    "LoongArch64": (0x6264, False),
    "RISC-V64": (0x5064, False),
    "x64": (0x8664, False),
}


def make_pe(
    architecture: str,
    *,
    signed: bool = False,
    subsystem: int = 10,
    marker: bytes = b"",
) -> bytes:
    machine, pe32 = MACHINES[architecture]
    pe_offset = 0x80
    optional_size = 0xE0 if pe32 else 0xF0
    size = 0x208 if signed else 0x200
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, 0)
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    count_offset = 92 if pe32 else 108
    directory_offset = 96 if pe32 else 112
    struct.pack_into("<I", data, optional + count_offset, 16)
    if signed:
        struct.pack_into("<II", data, optional + directory_offset + 32, 0x200, 8)
        struct.pack_into("<IHH", data, 0x200, 8, 0x0200, 0x0002)
    return bytes(data) + marker


def fixture_bundle() -> tuple[
    tuple[RuntimeValidationArtifactProfile, ...], BoundBootBundle
]:
    values = (
        ("bootaa64_signed.efi", "EFI/BOOT/BOOTAA64.EFI", "bootaa64_original.efi", "ARM64", True),
        ("bootarm.efi", "EFI/BOOT/BOOTARM.EFI", "bootarm_original.efi", "Thumb", False),
        ("bootia32_signed.efi", "EFI/BOOT/BOOTIA32.EFI", "bootia32_original.efi", "x86", True),
        (
            "bootloongarch64.efi", "EFI/BOOT/BOOTLOONGARCH64.EFI",
            "bootloongarch64_original.efi", "LoongArch64", False,
        ),
        (
            "bootriscv64.efi", "EFI/BOOT/BOOTRISCV64.EFI",
            "bootriscv64_original.efi", "RISC-V64", False,
        ),
        ("bootx64_signed.efi", "EFI/BOOT/BOOTX64.EFI", "bootx64_original.efi", "x64", True),
    )
    profiles: list[RuntimeValidationArtifactProfile] = []
    artifacts: list[BoundBootArtifact] = []
    for name, fallback, original_name, architecture, signed in values:
        data = make_pe(architecture, signed=signed, marker=(b"wrapper-" + name.encode()))
        digest = hashlib.sha256(data).hexdigest()
        profiles.append(RuntimeValidationArtifactProfile(
            name,
            fallback,
            "EFI/BOOT/" + original_name,
            architecture,
            len(data),
            digest,
            (
                SignatureTableState.PRESENT_UNVERIFIED
                if signed else SignatureTableState.ABSENT
            ),
        ))
        artifacts.append(BoundBootArtifact(name, data, digest))
    return tuple(profiles), BoundBootBundle(
        RUNTIME_VALIDATION_FAMILY,
        RUNTIME_VALIDATION_VERSION,
        RUNTIME_VALIDATION_PURPOSE,
        tuple(artifacts),
        RUNTIME_VALIDATION_LICENSE,
        RUNTIME_VALIDATION_PROVENANCE_URL,
    )


def make_tree(root: Path, architectures: tuple[str, ...] = ("x64",)) -> dict[str, bytes]:
    boot = root / "EFI" / "BOOT"
    boot.mkdir(parents=True)
    originals: dict[str, bytes] = {}
    for architecture in architectures:
        profile = next(
            item for item in runtime_validation.RUNTIME_VALIDATION_ARTIFACTS
            if item.architecture == architecture
        )
        data = make_pe(architecture, marker=(b"original-" + architecture.encode()))
        (root / profile.fallback_path).write_bytes(data)
        originals[architecture] = data
    return originals


def expected_manifest(root: Path, wrapper_paths: set[str]) -> bytes:
    rows: list[tuple[bytes, str, int]] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if (
            path.is_file()
            and relative != "md5sum.txt"
            and relative not in wrapper_paths
        ):
            data = path.read_bytes()
            rows.append((relative.encode("utf-8"), hashlib.md5(
                data, usedforsecurity=False,
            ).hexdigest(), len(data)))
    rows.sort(key=lambda item: item[0])
    total = sum(row[2] for row in rows)
    return (
        f"# md5sum_totalbytes = 0x{total:x}\n".encode("ascii")
        + b"".join(
            digest.encode("ascii") + b"  ./" + path + b"\n"
            for path, digest, _size in rows
        )
    )


class RuntimeValidationTests(unittest.TestCase):
    def test_bundled_catalog_matches_the_independent_release_profile(self):
        catalog = load_catalog()
        bundle = catalog.find_bundle(
            RUNTIME_VALIDATION_FAMILY,
            RUNTIME_VALIDATION_VERSION,
            RUNTIME_VALIDATION_PURPOSE,
        )
        self.assertIsNotNone(bundle)
        assert bundle is not None
        self.assertEqual(
            (
                bundle.license,
                bundle.provenance_url,
                bundle.artifact_names,
            ),
            (
                RUNTIME_VALIDATION_LICENSE,
                RUNTIME_VALIDATION_PROVENANCE_URL,
                tuple(
                    profile.source_name
                    for profile in runtime_validation.RUNTIME_VALIDATION_ARTIFACTS
                ),
            ),
        )
        for profile in runtime_validation.RUNTIME_VALIDATION_ARTIFACTS:
            resource = catalog.find(
                RUNTIME_VALIDATION_FAMILY,
                RUNTIME_VALIDATION_VERSION,
                profile.source_name,
            )
            self.assertIsNotNone(resource)
            assert resource is not None
            self.assertEqual((resource.size, resource.sha256), (profile.size, profile.sha256))

    def test_exact_bundle_and_prepare_validate_all_profiles(self):
        profiles, bundle = fixture_bundle()
        with patch.object(runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles):
            prepared = validate_runtime_validation_bundle(bundle)
            self.assertIs(
                validate_prepared_runtime_validation(prepared), prepared,
            )
            self.assertEqual(
                tuple(payload.architecture for payload in prepared.payloads),
                ("ARM64", "Thumb", "x86", "LoongArch64", "RISC-V64", "x64"),
            )
            self.assertTrue(all(type(payload.data) is bytes for payload in prepared.payloads))
            with patch.object(runtime_validation, "prepare_bundle", return_value=bundle) as acquire:
                again = prepare_runtime_validation(overall_timeout=27)
        acquire.assert_called_once()
        self.assertEqual(
            acquire.call_args.args,
            (RUNTIME_VALIDATION_FAMILY, RUNTIME_VALIDATION_VERSION, RUNTIME_VALIDATION_PURPOSE),
        )
        self.assertEqual(acquire.call_args.kwargs["overall_timeout"], 27)
        self.assertEqual(again, prepared)
        with self.assertRaisesRegex(RuntimeValidationError, "not exact"):
            validate_prepared_runtime_validation(replace(prepared, payloads=()))

    def test_bundle_rejects_order_content_metadata_architecture_and_type_spoof(self):
        profiles, bundle = fixture_bundle()
        class SpoofedBundle(BoundBootBundle):
            pass

        with patch.object(runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles):
            with self.assertRaisesRegex(RuntimeValidationError, "invalid type"):
                validate_runtime_validation_bundle(SpoofedBundle(
                    bundle.family, bundle.version, bundle.purpose, bundle.artifacts,
                    bundle.license, bundle.provenance_url,
                ))
            with self.assertRaisesRegex(RuntimeValidationError, "set or order"):
                validate_runtime_validation_bundle(replace(
                    bundle,
                    artifacts=(bundle.artifacts[1], bundle.artifacts[0], *bundle.artifacts[2:]),
                ))
            damaged = bytearray(bundle.artifacts[0].data)
            damaged[-1] ^= 1
            with self.assertRaisesRegex(RuntimeValidationError, "release verification"):
                validate_runtime_validation_bundle(replace(
                    bundle,
                    artifacts=(replace(bundle.artifacts[0], data=bytes(damaged)), *bundle.artifacts[1:]),
                ))
            with self.assertRaisesRegex(RuntimeValidationError, "metadata"):
                validate_runtime_validation_bundle(replace(bundle, purpose="different"))

            wrong = make_pe("x64", signed=True, marker=b"wrong-arch")
            wrong_digest = hashlib.sha256(wrong).hexdigest()
            wrong_profile = replace(profiles[0], size=len(wrong), sha256=wrong_digest)
            wrong_artifact = BoundBootArtifact(profiles[0].source_name, wrong, wrong_digest)
            with (
                patch.object(
                    runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS",
                    (wrong_profile, *profiles[1:]),
                ),
                self.assertRaisesRegex(RuntimeValidationError, "architecture"),
            ):
                validate_runtime_validation_bundle(replace(
                    bundle, artifacts=(wrong_artifact, *bundle.artifacts[1:]),
                ))

    def test_apply_generates_exact_manifest_and_revalidates(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            originals = make_tree(root)
            (root / "z.txt").write_bytes(b"z")
            (root / "a.txt").write_bytes(b"alpha")
            (root / "MD5SUMS").write_bytes(b"preserve-me")
            (root / "md5sum.txt").write_text("untrusted old manifest\n", "utf-8")
            prepared = validate_runtime_validation_bundle(bundle)
            compatibility = analyze_runtime_validation_compatibility(root)
            stage = apply_runtime_validation(
                prepared, root, compatibility=compatibility,
            )
            self.assertEqual(stage.architectures, ("x64",))
            self.assertEqual(
                (root / "EFI/BOOT/BOOTX64.EFI").read_bytes(),
                next(item.data for item in prepared.payloads if item.architecture == "x64"),
            )
            self.assertEqual(
                (root / "EFI/BOOT/bootx64_original.efi").read_bytes(), originals["x64"],
            )
            wanted = expected_manifest(root, {"EFI/BOOT/BOOTX64.EFI"})
            self.assertEqual((root / "md5sum.txt").read_bytes(), wanted)
            self.assertIn(b"  ./MD5SUMS\n", wanted)
            self.assertIs(validate_runtime_validation_stage(stage), stage)

    def test_multiarchitecture_is_canonical_and_unsigned_profiles_remain_explicit(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root, ("Thumb", "x64", "ARM64"))
            prepared = validate_runtime_validation_bundle(bundle)
            stage = apply_runtime_validation(prepared, root)
            self.assertEqual(stage.architectures, ("ARM64", "Thumb", "x64"))
            self.assertEqual(
                tuple(loader.architecture for loader in stage.loaders), stage.architectures,
            )
            self.assertEqual(
                next(
                    profile.signature_state for profile in profiles
                    if profile.architecture == "Thumb"
                ),
                SignatureTableState.ABSENT,
            )
            self.assertEqual(stage.unsigned_wrapper_architectures, ("Thumb",))
            self.assertIs(validate_runtime_validation_stage(stage), stage)

    def test_analysis_rejects_unsafe_trees_and_ambiguous_reserved_paths(self):
        profiles, _bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            base = Path(directory).resolve()
            empty = base / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "no recognized"):
                analyze_runtime_validation_compatibility(empty)

            original = base / "original"
            make_tree(original)
            (original / "EFI/BOOT/bootx64_original.efi").write_bytes(b"occupied")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "original"):
                analyze_runtime_validation_compatibility(original)

            alias = base / "alias"
            make_tree(alias)
            (alias / "MD5SUM.TXT").write_bytes(b"alias")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "case alias"):
                analyze_runtime_validation_compatibility(alias)

            symlink = base / "symlink"
            make_tree(symlink)
            (symlink / "link").symlink_to("a")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "Symlink"):
                analyze_runtime_validation_compatibility(symlink)

            special = base / "special"
            make_tree(special)
            os.mkfifo(special / "fifo")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "special"):
                analyze_runtime_validation_compatibility(special)

            hardlink = base / "hardlink"
            make_tree(hardlink)
            (hardlink / "one").write_bytes(b"same inode")
            os.link(hardlink / "one", hardlink / "two")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "Hard-linked"):
                analyze_runtime_validation_compatibility(hardlink)

            collision = base / "collision"
            make_tree(collision)
            (collision / "Readme").write_bytes(b"one")
            (collision / "README").write_bytes(b"two")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "alias"):
                analyze_runtime_validation_compatibility(collision)

    def test_manifest_path_line_and_utf16_limits_fail_closed(self):
        profiles, _bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            base = Path(directory).resolve()
            root = base / "long"
            make_tree(root)
            first = "a" * 255
            second = "b" * 255
            nested = root / first
            nested.mkdir()
            (nested / second).write_bytes(b"too long")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "parser limit"):
                analyze_runtime_validation_compatibility(root)

            emoji = base / "emoji"
            make_tree(emoji)
            (emoji / "non-ascii-\U0001f642-file.txt").write_bytes(b"valid UTF-8")
            with (
                patch.object(runtime_validation, "MAX_MANIFEST_PATH_UTF16_UNITS", 10),
                self.assertRaisesRegex(RuntimeValidationSafetyError, "parser limit"),
            ):
                analyze_runtime_validation_compatibility(emoji)

            lines = base / "lines"
            make_tree(lines)
            (lines / "extra").write_bytes(b"one")
            with (
                patch.object(runtime_validation, "MAX_MANIFEST_LINES", 3),
                self.assertRaisesRegex(RuntimeValidationSafetyError, "line limit"),
            ):
                analyze_runtime_validation_compatibility(lines)

    def test_cancellation_before_mutation_returns_no_witness(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            original = make_tree(root)["x64"]
            prepared = validate_runtime_validation_bundle(bundle)
            cancelled = threading.Event()
            cancelled.set()
            with self.assertRaises(RuntimeValidationCancelled):
                apply_runtime_validation(prepared, root, cancel_event=cancelled)
            self.assertEqual((root / "EFI/BOOT/BOOTX64.EFI").read_bytes(), original)
            self.assertFalse((root / "EFI/BOOT/bootx64_original.efi").exists())
            self.assertFalse((root / "md5sum.txt").exists())

    def test_incompatible_member_of_multiarch_tree_aborts_before_any_mutation(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            originals = make_tree(root, ("ARM64", "x64"))
            (root / "EFI/BOOT/BOOTAA64.EFI").write_bytes(make_pe(
                "x64", marker=b"wrong architecture",
            ))
            prepared = validate_runtime_validation_bundle(bundle)
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "does not match"):
                apply_runtime_validation(prepared, root)
            self.assertEqual(
                (root / "EFI/BOOT/BOOTX64.EFI").read_bytes(), originals["x64"],
            )
            self.assertFalse((root / "EFI/BOOT/bootx64_original.efi").exists())
            self.assertFalse((root / "md5sum.txt").exists())

    def test_cancellation_during_hashing_never_returns_or_installs_a_manifest(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root)
            (root / "one").write_bytes(b"1")
            (root / "two").write_bytes(b"2")
            prepared = validate_runtime_validation_bundle(bundle)
            cancelled = threading.Event()
            real_hash = runtime_validation._hash_manifest_file
            calls = 0

            def cancel_after_first(*args, **kwargs):
                nonlocal calls
                result = real_hash(*args, **kwargs)
                calls += 1
                if calls == 1:
                    cancelled.set()
                return result

            with (
                patch.object(
                    runtime_validation, "_hash_manifest_file",
                    side_effect=cancel_after_first,
                ),
                self.assertRaises(RuntimeValidationCancelled),
            ):
                apply_runtime_validation(prepared, root, cancel_event=cancelled)
            self.assertFalse((root / "md5sum.txt").exists())

    def test_forged_compatibility_is_freshly_rederived_before_mutation(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            original = make_tree(root)["x64"]
            (root / "victim.efi").write_bytes(original)
            prepared = validate_runtime_validation_bundle(bundle)
            compatibility = analyze_runtime_validation_compatibility(root)
            forged_loader = replace(
                compatibility.loaders[0],
                fallback_path="victim.efi",
                original_path="victim_original.efi",
            )
            forged = replace(compatibility, loaders=(forged_loader,))
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "fresh analysis"):
                apply_runtime_validation(prepared, root, compatibility=forged)
            self.assertEqual((root / "EFI/BOOT/BOOTX64.EFI").read_bytes(), original)
            self.assertFalse((root / "EFI/BOOT/bootx64_original.efi").exists())

    def test_forged_stage_with_current_but_wrong_manifest_is_rejected(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root)
            (root / "payload").write_bytes(b"payload")
            prepared = validate_runtime_validation_bundle(bundle)
            stage = apply_runtime_validation(prepared, root)
            manifest_path = root / "md5sum.txt"
            malformed = bytearray(manifest_path.read_bytes())
            digest_start = malformed.index(b"\n") + 1
            malformed[digest_start] = ord("0") if malformed[digest_start] != ord("0") else ord("1")
            manifest_path.chmod(0o600)
            manifest_path.write_bytes(bytes(malformed))
            changed = manifest_path.stat()
            identity = (
                changed.st_dev, changed.st_ino, changed.st_size,
                changed.st_mtime_ns, changed.st_ctime_ns,
            )
            tree = tuple(
                replace(entry, identity=identity)
                if entry.path == "md5sum.txt" else entry
                for entry in stage.tree
            )
            forged = replace(
                stage,
                manifest_sha256=hashlib.sha256(malformed).hexdigest(),
                manifest_identity=identity,
                tree=tree,
            )
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "digest changed"):
                validate_runtime_validation_stage(forged)

    def test_consistent_forged_stage_cannot_omit_an_unwrapped_architecture(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root, ("ARM64", "x64"))
            prepared = validate_runtime_validation_bundle(bundle)
            stage = apply_runtime_validation(prepared, root)
            arm64 = next(
                loader for loader in stage.loaders if loader.architecture == "ARM64"
            )
            x64 = next(
                loader for loader in stage.loaders if loader.architecture == "x64"
            )

            # Make the tree and witness internally consistent while undoing only
            # the ARM64 wrapper. A validator must derive that fallback itself,
            # rather than trusting the forged one-entry loader tuple.
            (root / arm64.fallback_path).unlink()
            (root / arm64.original_path).replace(root / arm64.fallback_path)
            root_fd = runtime_validation._open_absolute_directory(root)
            try:
                changed_tree = runtime_validation._scan_tree(root_fd)
                manifest = runtime_validation._build_manifest(
                    root_fd,
                    changed_tree,
                    frozenset({x64.fallback_path}),
                    None,
                )
                old_manifest = runtime_validation._tree_map(changed_tree).get(
                    runtime_validation.RUNTIME_VALIDATION_MANIFEST
                )
                runtime_validation._write_manifest(
                    root_fd, manifest, old_manifest, None,
                )
                final_tree = runtime_validation._scan_tree(root_fd)
            finally:
                os.close(root_fd)
            manifest_entry = runtime_validation._tree_map(final_tree)[
                runtime_validation.RUNTIME_VALIDATION_MANIFEST
            ]
            forged = replace(
                stage,
                architectures=("x64",),
                loaders=(x64,),
                manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                manifest_identity=manifest_entry.identity,
                tree=final_tree,
            )
            with self.assertRaisesRegex(
                RuntimeValidationSafetyError, "not the exact validation wrapper",
            ):
                validate_runtime_validation_stage(forged)

    def test_stage_validation_honors_precancel_before_opening_the_tree(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root)
            stage = apply_runtime_validation(
                validate_runtime_validation_bundle(bundle), root,
            )
            cancelled = threading.Event()
            cancelled.set()
            with (
                patch.object(
                    runtime_validation, "_open_absolute_directory",
                    wraps=runtime_validation._open_absolute_directory,
                ) as opener,
                self.assertRaises(RuntimeValidationCancelled),
            ):
                validate_runtime_validation_stage(
                    stage, cancel_event=cancelled,
                )
            opener.assert_not_called()

    def test_stage_validation_cancels_during_traversal_and_manifest_rehash(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root)
            (root / "payload-one").write_bytes(b"one")
            (root / "payload-two").write_bytes(b"two")
            stage = apply_runtime_validation(
                validate_runtime_validation_bundle(bundle), root,
            )

            traversal_cancelled = threading.Event()
            real_validate_name = runtime_validation._validate_name
            names_seen = 0

            def cancel_after_first_name(*args, **kwargs):
                nonlocal names_seen
                result = real_validate_name(*args, **kwargs)
                names_seen += 1
                if names_seen == 1:
                    traversal_cancelled.set()
                return result

            with (
                patch.object(
                    runtime_validation, "_validate_name",
                    side_effect=cancel_after_first_name,
                ),
                self.assertRaises(RuntimeValidationCancelled),
            ):
                validate_runtime_validation_stage(
                    stage, cancel_event=traversal_cancelled,
                )

            hashing_cancelled = threading.Event()
            real_hash = runtime_validation._hash_manifest_file
            hashes_completed = 0

            def cancel_after_first_hash(*args, **kwargs):
                nonlocal hashes_completed
                result = real_hash(*args, **kwargs)
                hashes_completed += 1
                if hashes_completed == 1:
                    hashing_cancelled.set()
                return result

            with (
                patch.object(
                    runtime_validation, "_hash_manifest_file",
                    side_effect=cancel_after_first_hash,
                ),
                self.assertRaises(RuntimeValidationCancelled),
            ):
                validate_runtime_validation_stage(
                    stage, cancel_event=hashing_cancelled,
                )
            self.assertEqual(hashes_completed, 1)
            self.assertIs(validate_runtime_validation_stage(stage), stage)

    def test_stage_detects_added_removed_and_replaced_content(self):
        profiles, bundle = fixture_bundle()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runtime_validation, "RUNTIME_VALIDATION_ARTIFACTS", profiles,
        ):
            root = Path(directory).resolve() / "private"
            make_tree(root)
            prepared = validate_runtime_validation_bundle(bundle)
            stage = apply_runtime_validation(prepared, root)
            (root / "added").write_bytes(b"new")
            with self.assertRaisesRegex(RuntimeValidationSafetyError, "tree changed"):
                validate_runtime_validation_stage(stage)


if __name__ == "__main__":
    unittest.main()
