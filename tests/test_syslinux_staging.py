from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import unittest
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import patch

import isopropyl.syslinux_staging as staging
import isopropyl.syslinux as syslinux
from isopropyl.boot_identity import BootloaderAnalysis, BootloaderIdentity
from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle, load_catalog
from isopropyl.iso import ArchiveEntry, EntryKind
from isopropyl.syslinux_staging import (
    StageDisposition,
    SyslinuxStagingError,
    bind_syslinux_c32_bundle,
    syslinux_staging_analysis_paths,
    syslinux_staging_read_paths,
)


PRODUCTION_PINS = staging.PINNED_SYSLINUX_C32
PRODUCTION_ROOT_PINS = staging.PINNED_SYSLINUX_ROOTS
VERSIONS = {
    "6.03-2014-10-06": ("6.03", b"fixture c32 for 6.03", "fixture://6.03"),
    "6.04-pre1": ("6.04", b"fixture c32 for 6.04-pre1", "fixture://6.04"),
}
TEST_PINS = MappingProxyType({
    version: (len(data), hashlib.sha256(data).hexdigest(), provenance)
    for version, (_base, data, provenance) in VERSIONS.items()
})
CONFIG_DATA = b"DEFAULT linux\n\nLABEL linux\n  LINUX /vmlinuz\n"
BIOS_PAYLOADS = {
    version: {
        "ldlinux.bss": f"fixture bss for {version}".encode(),
        "ldlinux.sys": f"fixture sys for {version}".encode(),
    }
    for version in VERSIONS
}
BIOS_TEST_PINS = MappingProxyType({
    version: MappingProxyType({
        name: (len(data), hashlib.sha256(data).hexdigest())
        for name, data in payloads.items()
    })
    for version, payloads in BIOS_PAYLOADS.items()
})
BIOS_TEST_PROVENANCE = MappingProxyType({
    version: f"fixture://bios/{version}" for version in VERSIONS
})
BIOS_TEST_ROOTS = MappingProxyType({
    version: (
        len(payloads["ldlinux.sys"] + syslinux.make_empty_adv()),
        hashlib.sha256(
            payloads["ldlinux.sys"] + syslinux.make_empty_adv(),
        ).hexdigest(),
    )
    for version, payloads in BIOS_PAYLOADS.items()
})


def bootloader_blob(version: str) -> bytes:
    if version == "6.03-2014-10-06":
        return b"ISOLINUX 6.03 2014-10-06"
    if version == "6.04-pre1":
        return b"ISOLINUX 6.04 6.04-pre1"
    raise AssertionError(f"unsupported fixture version: {version}")


def identity(version: str, path: str = "isolinux/isolinux.bin") -> BootloaderIdentity:
    base = VERSIONS[version][0]
    return BootloaderIdentity(
        "Isolinux", base, version, path, True, False, (version,),
        ("embedded ISOLINUX version marker",),
    )


def analysis(
    version: str = "6.03-2014-10-06",
    *paths: str,
) -> BootloaderAnalysis:
    sources = paths or ("isolinux/isolinux.bin",)
    return BootloaderAnalysis(tuple(identity(version, path) for path in sources))


def module_bundle(version: str = "6.03-2014-10-06") -> BoundBootBundle:
    data = VERSIONS[version][1]
    digest = hashlib.sha256(data).hexdigest()
    return BoundBootBundle(
        "syslinux", version, "blank-bios-module",
        (BoundBootArtifact("ldlinux.c32", data, digest),),
        "GPL-2.0-or-later", VERSIONS[version][2],
    )


def payload_bundle(version: str = "6.03-2014-10-06") -> BoundBootBundle:
    payloads = BIOS_PAYLOADS[version]
    artifacts = tuple(
        BoundBootArtifact(name, data, hashlib.sha256(data).hexdigest())
        for name, data in payloads.items()
    )
    return BoundBootBundle(
        "syslinux", version, "matched-bios-payloads", artifacts,
        "GPL-2.0-or-later", BIOS_TEST_PROVENANCE[version],
    )


def _payload_for_module(module: object) -> BoundBootBundle:
    version = getattr(module, "version", "6.03-2014-10-06")
    if type(version) is not str or version not in BIOS_PAYLOADS:
        version = "6.03-2014-10-06"
    return payload_bundle(version)


def plan_syslinux_staging(entries, boot_analysis, module, **kwargs):
    payload = kwargs.pop("payload_bundle", _payload_for_module(module))
    return staging.plan_syslinux_staging(
        entries, boot_analysis, module, payload, **kwargs,
    )


def validate_syslinux_staging_plan(plan, entries, boot_analysis, module, **kwargs):
    payload = kwargs.pop("payload_bundle", _payload_for_module(module))
    return staging.validate_syslinux_staging_plan(
        plan, entries, boot_analysis, module, payload, **kwargs,
    )


def source_member_bytes(
    version: str = "6.03-2014-10-06",
    *bootloader_paths: str,
    config: str = "isolinux/isolinux.cfg",
    config_data: bytes = CONFIG_DATA,
) -> dict[str, bytes]:
    paths = bootloader_paths or ("isolinux/isolinux.bin",)
    return {
        **{path: bootloader_blob(version) for path in paths},
        config: config_data,
    }


def entries(
    config: str = "isolinux/isolinux.cfg",
    *,
    version: str = "6.03-2014-10-06",
    bootloader: str = "isolinux/isolinux.bin",
    config_data: bytes = CONFIG_DATA,
) -> tuple[ArchiveEntry, ...]:
    parent = config.rsplit("/", 1)[0] if "/" in config else ""
    boot_parent = bootloader.rsplit("/", 1)[0] if "/" in bootloader else ""
    directories = tuple(dict.fromkeys(filter(None, (parent, boot_parent))))
    return tuple(ArchiveEntry(path, kind=EntryKind.DIRECTORY) for path in directories) + (
        ArchiveEntry(bootloader, len(bootloader_blob(version))),
        ArchiveEntry(config, len(config_data)),
    )


class SyslinuxStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin_patch = patch.object(staging, "PINNED_SYSLINUX_C32", TEST_PINS)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.payload_pin_patch = patch.object(
            syslinux, "PINNED_SYSLINUX_PAYLOADS", BIOS_TEST_PINS,
        )
        self.payload_pin_patch.start()
        self.addCleanup(self.payload_pin_patch.stop)
        self.payload_provenance_patch = patch.object(
            syslinux, "PINNED_SYSLINUX_PROVENANCE", BIOS_TEST_PROVENANCE,
        )
        self.payload_provenance_patch.start()
        self.addCleanup(self.payload_provenance_patch.stop)
        self.root_pin_patch = patch.object(
            staging, "PINNED_SYSLINUX_ROOTS", BIOS_TEST_ROOTS,
        )
        self.root_pin_patch.start()
        self.addCleanup(self.root_pin_patch.stop)

    def test_nested_603_config_creates_canonical_redirect_and_module(self):
        catalog = entries()
        sources = source_member_bytes()
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(), source_files=sources,
        )

        self.assertEqual(result.version, "6.03-2014-10-06")
        self.assertEqual(result.dependency_key, "syslinux:6.03-2014-10-06")
        self.assertEqual(result.bootloader_path, "isolinux/isolinux.bin")
        self.assertEqual(result.config_path, "isolinux/isolinux.cfg")
        self.assertEqual(result.config_directory, "/isolinux")
        self.assertIsNotNone(result.root_redirect)
        assert result.root_redirect is not None
        self.assertEqual(
            result.root_redirect.data,
            b"DEFAULT loadconfig\n\nLABEL loadconfig\n"
            b"  CONFIG /isolinux/isolinux.cfg\n"
            b"  APPEND /isolinux/\n",
        )
        self.assertEqual(result.root_redirect.path, "syslinux.cfg")
        self.assertIs(result.root_redirect.disposition, StageDisposition.CREATE)
        self.assertEqual(result.ldlinux_c32.path, "isolinux/ldlinux.c32")
        self.assertIs(result.ldlinux_c32.disposition, StageDisposition.CREATE)
        self.assertEqual(
            result.additions,
            (result.root_redirect, result.ldlinux_c32, result.root_ldlinux_sys),
        )
        self.assertEqual(result.root_ldlinux_sys.path, "ldlinux.sys")
        self.assertEqual(
            result.root_ldlinux_sys.data,
            BIOS_PAYLOADS[result.version]["ldlinux.sys"] + syslinux.make_empty_adv(),
        )
        validate_syslinux_staging_plan(
            result, catalog, analysis(), module_bundle(), source_files=sources,
        )

    def test_production_root_and_adv_pins_are_frozen_independently(self):
        self.assertEqual(
            hashlib.sha256(syslinux.make_empty_adv()).hexdigest(),
            "32a7611ef0a2a3ecb19b45aea0d85b5da493874e42a671ad6283658ba383527e",
        )

    def test_generated_root_must_match_its_second_consumer_pin(self):
        size, digest = BIOS_TEST_ROOTS["6.03-2014-10-06"]
        for pin in ((size, "0" * 64), (size + 1, digest)):
            with (
                self.subTest(pin=pin),
                patch.object(
                    staging,
                    "PINNED_SYSLINUX_ROOTS",
                    {"6.03-2014-10-06": pin},
                ),
                self.assertRaisesRegex(SyslinuxStagingError, "independent pin"),
            ):
                plan_syslinux_staging(
                    entries(),
                    analysis(),
                    module_bundle(),
                    source_files=source_member_bytes(),
                )
        self.assertEqual(
            PRODUCTION_ROOT_PINS,
            {
                "6.03-2014-10-06": (
                    69_623,
                    "b073e94a47a2eedc93367d75956c83a82b05d4c778eb78685af3f484917f484c",
                ),
                "6.04-pre1": (
                    69_145,
                    "7d50190c5f9c7f3e7f4f3ca98da03ec294cf10aa2b45adbdddee53f422b283a5",
                ),
            },
        )

    def test_bios_payload_bundle_must_match_image_and_c32_build(self):
        with self.assertRaisesRegex(SyslinuxStagingError, "BIOS payload bundle"):
            plan_syslinux_staging(
                entries(),
                analysis(),
                module_bundle(),
                payload_bundle=payload_bundle("6.04-pre1"),
                source_files=source_member_bytes(),
            )

        bundle = payload_bundle()
        for forged in (
            replace(bundle, purpose="blank-bios-module"),
            replace(bundle, license="MIT"),
            replace(bundle, provenance_url="fixture://wrong"),
            replace(bundle, artifacts=tuple(reversed(bundle.artifacts))),
            replace(
                bundle,
                artifacts=(
                    bundle.artifacts[0],
                    replace(bundle.artifacts[1], data=b"changed"),
                ),
            ),
        ):
            with self.subTest(forged=forged), self.assertRaises(
                SyslinuxStagingError,
            ):
                plan_syslinux_staging(
                    entries(),
                    analysis(),
                    module_bundle(),
                    payload_bundle=forged,
                    source_files=source_member_bytes(),
                )
    def test_read_paths_return_exact_required_iso_members(self):
        catalog = entries()
        self.assertEqual(
            syslinux_staging_read_paths(catalog, analysis()),
            ("isolinux/isolinux.bin", "isolinux/isolinux.cfg"),
        )

        data = VERSIONS["6.03-2014-10-06"][1]
        with_c32 = catalog + (
            ArchiveEntry("isolinux/ldlinux.c32", len(data)),
        )
        self.assertEqual(
            syslinux_staging_read_paths(with_c32, analysis()),
            (
                "isolinux/isolinux.bin",
                "isolinux/isolinux.cfg",
                "isolinux/ldlinux.c32",
            ),
        )

        root_catalog = entries("syslinux.cfg") + (
            ArchiveEntry("ldlinux.c32", len(data)),
        )
        self.assertEqual(
            syslinux_staging_read_paths(root_catalog, analysis()),
            ("isolinux/isolinux.bin", "syslinux.cfg", "ldlinux.c32"),
        )

    def test_analysis_paths_enforce_profile_specific_count_and_byte_caps(self):
        self.assertEqual(
            syslinux_staging_analysis_paths(entries()),
            ("isolinux/isolinux.bin",),
        )
        too_many = tuple(
            ArchiveEntry(f"boot-{index}/isolinux.bin", 1)
            for index in range(staging.MAX_SYSLINUX_IDENTITY_COUNT + 1)
        )
        oversized = (
            ArchiveEntry(
                "isolinux.bin",
                staging.MAX_SYSLINUX_LOADER_BYTES + 1,
            ),
        )
        for catalog in (too_many, oversized):
            with self.subTest(catalog=catalog), self.assertRaisesRegex(
                SyslinuxStagingError,
                "bounded staging profile",
            ):
                syslinux_staging_analysis_paths(catalog)

    def test_read_paths_include_every_validated_identity_source(self):
        blob_size = len(bootloader_blob("6.03-2014-10-06"))
        catalog = (
            ArchiveEntry("one", kind=EntryKind.DIRECTORY),
            ArchiveEntry("one/isolinux.bin", blob_size),
            ArchiveEntry("one/isolinux.cfg", len(CONFIG_DATA)),
            ArchiveEntry("two", kind=EntryKind.DIRECTORY),
            ArchiveEntry("two/isolinux.bin", blob_size),
        )
        boot_analysis = analysis(
            "6.03-2014-10-06", "one/isolinux.bin", "two/isolinux.bin",
        )
        self.assertEqual(
            syslinux_staging_read_paths(catalog, boot_analysis),
            (
                "one/isolinux.bin",
                "two/isolinux.bin",
                "one/isolinux.cfg",
            ),
        )

        unbound = catalog + (
            ArchiveEntry("three", kind=EntryKind.DIRECTORY),
            ArchiveEntry("three/isolinux.bin", blob_size),
        )
        with self.assertRaisesRegex(
            SyslinuxStagingError,
            "every cataloged Isolinux payload",
        ):
            syslinux_staging_read_paths(unbound, boot_analysis)

    def test_read_paths_fail_closed_on_invalid_selection_or_c32_layout(self):
        invalid_cases = (
            (entries() + (ArchiveEntry("isolinux/syslinux.cfg", 10),), analysis()),
            (entries() + (ArchiveEntry("other/menu.c32", 10),), analysis()),
            (
                entries() + (
                    ArchiveEntry(
                        "isolinux/ldlinux.c32",
                        staging.MAX_SYSLINUX_C32_BYTES + 1,
                    ),
                ),
                analysis(),
            ),
            (
                entries() + (
                    ArchiveEntry(
                        "isolinux/ldlinux.c32", kind=EntryKind.DIRECTORY,
                    ),
                ),
                analysis(),
            ),
        )
        for catalog, boot_analysis in invalid_cases:
            with self.subTest(catalog=catalog):
                with self.assertRaises(SyslinuxStagingError):
                    syslinux_staging_read_paths(catalog, boot_analysis)

        with self.assertRaises(SyslinuxStagingError):
            syslinux_staging_read_paths(entries(), object())  # type: ignore[arg-type]

    def test_exact_604_pre1_uses_its_own_module(self):
        version = "6.04-pre1"
        catalog = entries(version=version)
        result = plan_syslinux_staging(
            catalog, analysis(version), module_bundle(version),
            source_files=source_member_bytes(version),
        )
        self.assertEqual(result.version, version)
        self.assertEqual(result.ldlinux_c32.data, VERSIONS[version][1])
        self.assertEqual(result.ldlinux_c32.sha256, TEST_PINS[version][1])

    def test_descriptor_bound_source_members_are_mandatory_and_exact(self):
        catalog = entries()
        good = source_member_bytes()
        bad_inputs = (
            None,
            {"isolinux/isolinux.bin": good["isolinux/isolinux.bin"]},
            {**good, "extra": b"x"},
            {
                **good,
                "ISOLINUX/ISOLINUX.BIN": good["isolinux/isolinux.bin"],
            },
            {
                **good,
                "isolinux/isolinux.bin": bytearray(
                    good["isolinux/isolinux.bin"],
                ),
            },
        )
        for supplied in bad_inputs:
            with self.subTest(supplied=supplied):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        catalog, analysis(), module_bundle(),
                        source_files=supplied,  # type: ignore[arg-type]
                    )

    def test_identity_is_rederived_from_exact_size_bound_source_bytes(self):
        catalog = entries()
        good = source_member_bytes()
        forged = dict(good)
        forged["isolinux/isolinux.bin"] = b"X" * len(bootloader_blob("6.03-2014-10-06"))
        with self.assertRaisesRegex(SyslinuxStagingError, "exact source bytes"):
            plan_syslinux_staging(
                catalog, analysis(), module_bundle(), source_files=forged,
            )

        wrong_size_catalog = tuple(
            replace(item, size=item.size + 1)
            if item.path == "isolinux/isolinux.bin" else item
            for item in catalog
        )
        with self.assertRaisesRegex(SyslinuxStagingError, "catalog size"):
            plan_syslinux_staging(
                wrong_size_catalog, analysis(), module_bundle(), source_files=good,
            )

    def test_every_isolinux_identity_source_requires_exact_bytes(self):
        blob_size = len(bootloader_blob("6.03-2014-10-06"))
        catalog = (
            ArchiveEntry("one", kind=EntryKind.DIRECTORY),
            ArchiveEntry("one/isolinux.bin", blob_size),
            ArchiveEntry("one/isolinux.cfg", len(CONFIG_DATA)),
            ArchiveEntry("two", kind=EntryKind.DIRECTORY),
            ArchiveEntry("two/isolinux.bin", blob_size),
        )
        boot_analysis = analysis(
            "6.03-2014-10-06", "one/isolinux.bin", "two/isolinux.bin",
        )
        complete = source_member_bytes(
            "6.03-2014-10-06", "one/isolinux.bin", "two/isolinux.bin",
            config="one/isolinux.cfg",
        )
        missing = dict(complete)
        del missing["two/isolinux.bin"]
        with self.assertRaisesRegex(SyslinuxStagingError, "incomplete"):
            plan_syslinux_staging(
                catalog, boot_analysis, module_bundle(), source_files=missing,
            )
        plan_syslinux_staging(
            catalog, boot_analysis, module_bundle(), source_files=complete,
        )

    def test_config_bytes_are_size_bound_ascii_and_control_safe(self):
        bad_configs = (
            b"DEFAULT linux\n\xff",
            b"DEFAULT linux\n\x00",
            b"DEFAULT linux\n\x1b",
            b"DEFAULT linux\n\x7f",
        )
        for config_data in bad_configs:
            catalog = entries(config_data=config_data)
            sources = source_member_bytes(config_data=config_data)
            with self.subTest(config_data=config_data):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        catalog, analysis(), module_bundle(), source_files=sources,
                    )

        sources = source_member_bytes()
        sources["isolinux/isolinux.cfg"] += b"x"
        with self.assertRaisesRegex(SyslinuxStagingError, "catalog size"):
            plan_syslinux_staging(
                entries(), analysis(), module_bundle(), source_files=sources,
            )

    def test_config_module_and_transitive_directives_fail_closed(self):
        forbidden_configs = (
            b"UI menu.bin\n",
            b"\tCoM32 evil.bin\n",
            b"CONFIG next.cfg /next\n",
            b"include other.cfg\n",
            b"MENU INCLUDE submenu.cfg\n",
            b"LABEL boot\n  LINUX kernel\n  APPEND helper.C32\n",
        )
        for config_data in forbidden_configs:
            catalog = entries(config_data=config_data)
            sources = source_member_bytes(config_data=config_data)
            with self.subTest(config_data=config_data):
                with self.assertRaisesRegex(SyslinuxStagingError, "module dependencies"):
                    plan_syslinux_staging(
                        catalog, analysis(), module_bundle(), source_files=sources,
                    )

        allowed = b"# UI ignored.c32\n" + CONFIG_DATA
        result = plan_syslinux_staging(
            entries(config_data=allowed), analysis(), module_bundle(),
            source_files=source_member_bytes(config_data=allowed),
        )
        self.assertEqual(result.config_sha256, hashlib.sha256(allowed).hexdigest())

    def test_plan_digests_bind_same_size_source_and_config_bytes(self):
        first_loader = bootloader_blob("6.03-2014-10-06") + b"\0A"
        second_loader = bootloader_blob("6.03-2014-10-06") + b"\0B"
        first_config = CONFIG_DATA.replace(b"vmlinuz", b"bzImage")
        second_config = CONFIG_DATA.replace(b"vmlinuz", b"kernelx")
        self.assertEqual(len(first_loader), len(second_loader))
        self.assertEqual(len(first_config), len(second_config))
        catalog = tuple(
            replace(item, size=len(first_loader))
            if item.path == "isolinux/isolinux.bin"
            else replace(item, size=len(first_config))
            if item.path == "isolinux/isolinux.cfg"
            else item
            for item in entries()
        )
        first_sources = {
            "isolinux/isolinux.bin": first_loader,
            "isolinux/isolinux.cfg": first_config,
        }
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(), source_files=first_sources,
        )
        self.assertRegex(result.source_members_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(
            result.config_sha256,
            hashlib.sha256(first_config).hexdigest(),
        )

        for changed_sources in (
            {**first_sources, "isolinux/isolinux.bin": second_loader},
            {**first_sources, "isolinux/isolinux.cfg": second_config},
        ):
            with self.subTest(changed_sources=changed_sources):
                with self.assertRaisesRegex(
                    SyslinuxStagingError, "forged or stale",
                ):
                    validate_syslinux_staging_plan(
                        result, catalog, analysis(), module_bundle(),
                        source_files=changed_sources,
                    )

    def test_existing_root_syslinux_config_is_preserved(self):
        catalog = entries("syslinux.cfg")
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(),
            source_files=source_member_bytes(config="syslinux.cfg"),
        )
        self.assertEqual(result.config_path, "syslinux.cfg")
        self.assertEqual(result.config_directory, "")
        self.assertIsNone(result.root_redirect)
        self.assertEqual(result.ldlinux_c32.path, "ldlinux.c32")
        self.assertEqual(
            result.additions,
            (result.ldlinux_c32, result.root_ldlinux_sys),
        )

    def test_root_isolinux_config_redirect_has_no_append(self):
        catalog = entries("isolinux.cfg", bootloader="isolinux.bin")
        result = plan_syslinux_staging(
            catalog, analysis("6.03-2014-10-06", "isolinux.bin"), module_bundle(),
            source_files=source_member_bytes(
                "6.03-2014-10-06", "isolinux.bin", config="isolinux.cfg",
            ),
        )
        assert result.root_redirect is not None
        self.assertEqual(
            result.root_redirect.data,
            b"DEFAULT loadconfig\n\nLABEL loadconfig\n  CONFIG /isolinux.cfg\n",
        )
        self.assertNotIn(b"APPEND", result.root_redirect.data)
        self.assertEqual(result.config_directory, "")

    def test_extlinux_conf_is_an_exact_sibling_candidate(self):
        catalog = entries("isolinux/extlinux.conf")
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(),
            source_files=source_member_bytes(config="isolinux/extlinux.conf"),
        )
        self.assertEqual(result.config_path, "isolinux/extlinux.conf")

    def test_root_config_is_authoritative_over_nested_candidates(self):
        catalog = entries("syslinux.cfg") + (
            ArchiveEntry("isolinux/isolinux.cfg", 20),
        )
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(),
            source_files=source_member_bytes(config="syslinux.cfg"),
        )
        self.assertEqual(result.config_path, "syslinux.cfg")
        self.assertIsNone(result.root_redirect)

    def test_exact_existing_c32_is_reused_without_an_addition(self):
        data = VERSIONS["6.03-2014-10-06"][1]
        catalog = entries() + (ArchiveEntry("isolinux/ldlinux.c32", len(data)),)
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(),
            source_files=source_member_bytes(),
            existing_files={"isolinux/ldlinux.c32": data},
        )
        self.assertIs(result.ldlinux_c32.disposition, StageDisposition.REUSE)
        self.assertEqual(
            result.additions,
            (result.root_redirect, result.root_ldlinux_sys),
        )
        validate_syslinux_staging_plan(
            result, catalog, analysis(), module_bundle(),
            source_files=source_member_bytes(),
            existing_files={"isolinux/ldlinux.c32": data},
        )

    def test_c32_bundle_consumer_rechecks_every_pin_and_field(self):
        bundle = module_bundle()
        bound = bind_syslinux_c32_bundle(bundle)
        self.assertEqual(bound.data, VERSIONS[bound.version][1])

        mutations = (
            replace(bundle, family="Syslinux"),
            replace(bundle, purpose="matched-bios-payloads"),
            replace(bundle, license="MIT"),
            replace(bundle, provenance_url="fixture://wrong"),
            replace(bundle, version="6.03"),
            replace(bundle, artifacts=()),
            replace(bundle, artifacts=(replace(bundle.artifacts[0], name="menu.c32"),)),
            replace(bundle, artifacts=(replace(bundle.artifacts[0], sha256="0" * 64),)),
            replace(bundle, artifacts=(replace(bundle.artifacts[0], data=b"changed"),)),
        )
        for forged in mutations:
            with self.subTest(forged=forged):
                with self.assertRaises(SyslinuxStagingError):
                    bind_syslinux_c32_bundle(forged)

    def test_independent_c32_pins_match_the_reviewed_acquisition_catalog(self):
        catalog = load_catalog()
        with patch.object(staging, "PINNED_SYSLINUX_C32", PRODUCTION_PINS):
            for version, (size, digest, provenance) in PRODUCTION_PINS.items():
                with self.subTest(version=version):
                    resource = catalog.find("syslinux", version, "ldlinux.c32")
                    bundle = catalog.find_bundle("syslinux", version, "blank-bios-module")
                    self.assertIsNotNone(resource)
                    self.assertIsNotNone(bundle)
                    assert resource is not None and bundle is not None
                    self.assertEqual((resource.size, resource.sha256), (size, digest))
                    self.assertEqual(bundle.artifact_names, ("ldlinux.c32",))
                    self.assertEqual(bundle.provenance_url, provenance)

    def test_malformed_frozen_dataclass_fields_fail_with_policy_errors(self):
        bad_bundle = module_bundle()
        object.__setattr__(bad_bundle, "version", [])
        with self.assertRaises(SyslinuxStagingError):
            bind_syslinux_c32_bundle(bad_bundle)

        bad_identity = identity("6.03-2014-10-06")
        object.__setattr__(bad_identity, "source", None)
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(
                entries(), BootloaderAnalysis((bad_identity,)), module_bundle(),
            )

        bad_entry = ArchiveEntry("isolinux/isolinux.cfg", 10)
        object.__setattr__(bad_entry, "kind", "file")
        malformed_catalog = entries()[:-1] + (bad_entry,)
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(malformed_catalog, analysis(), module_bundle())

    def test_module_build_must_match_image_build(self):
        with self.assertRaisesRegex(SyslinuxStagingError, "does not match"):
            plan_syslinux_staging(entries(), analysis(), module_bundle("6.04-pre1"))

    def test_analysis_must_be_complete_issue_free_and_exact(self):
        base = analysis()
        mutations = (
            replace(base, complete=False),
            replace(base, issues=("reader failed",)),
            replace(base, identities=()),
            replace(base, identities=(replace(base.identities[0], family="Syslinux"),)),
            replace(base, identities=(replace(base.identities[0], version="6.04"),)),
            replace(base, identities=(replace(base.identities[0], build="6.03"),)),
            replace(base, identities=(replace(base.identities[0], custom_build=False),)),
            replace(base, identities=(replace(base.identities[0], ambiguous=True),)),
            replace(base, identities=(replace(base.identities[0], candidates=()),)),
            replace(base, identities=(replace(base.identities[0], evidence=()),)),
            replace(base, identities=(replace(base.identities[0], source="other/isolinux.bin"),)),
        )
        for forged in mutations:
            with self.subTest(forged=forged):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(entries(), forged, module_bundle())

    def test_conflicting_builds_and_unsupported_releases_fail_closed(self):
        conflicting = BootloaderAnalysis((
            identity("6.03-2014-10-06", "one/isolinux.bin"),
            identity("6.04-pre1", "two/isolinux.bin"),
        ))
        catalog = (
            ArchiveEntry("one", kind=EntryKind.DIRECTORY),
            ArchiveEntry("one/isolinux.bin", 10),
            ArchiveEntry("one/isolinux.cfg", 10),
            ArchiveEntry("two", kind=EntryKind.DIRECTORY),
            ArchiveEntry("two/isolinux.bin", 10),
        )
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(catalog, conflicting, module_bundle())

        unsupported = BootloaderAnalysis((BootloaderIdentity(
            "Isolinux", "6.04", "6.04", "isolinux/isolinux.bin", False,
            False, ("6.04",), ("embedded ISOLINUX version marker",),
        ),))
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(entries(), unsupported, module_bundle())

    def test_identity_source_must_be_a_nonempty_catalog_file(self):
        for source_entry in (
            ArchiveEntry("isolinux/isolinux.bin", 0),
            ArchiveEntry("isolinux/isolinux.bin", kind=EntryKind.DIRECTORY),
        ):
            catalog = (
                ArchiveEntry("isolinux", kind=EntryKind.DIRECTORY),
                source_entry,
                ArchiveEntry("isolinux/isolinux.cfg", 10),
            )
            with self.subTest(kind=source_entry.kind, size=source_entry.size):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(catalog, analysis(), module_bundle())

    def test_config_selection_rejects_missing_empty_nonfile_and_oversized(self):
        base = (
            ArchiveEntry("isolinux", kind=EntryKind.DIRECTORY),
            ArchiveEntry("isolinux/isolinux.bin", 32),
        )
        configs = (
            (),
            (ArchiveEntry("isolinux/isolinux.cfg", 0),),
            (ArchiveEntry("isolinux/isolinux.cfg", kind=EntryKind.DIRECTORY),),
            (ArchiveEntry(
                "isolinux/isolinux.cfg", staging.MAX_SYSLINUX_CONFIG_BYTES + 1,
            ),),
        )
        for extra in configs:
            with self.subTest(extra=extra):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(base + extra, analysis(), module_bundle())

    def test_multiple_sibling_configs_are_not_resolved_heuristically(self):
        catalog = entries() + (ArchiveEntry("isolinux/syslinux.cfg", 10),)
        with self.assertRaisesRegex(SyslinuxStagingError, "multiple"):
            plan_syslinux_staging(catalog, analysis(), module_bundle())

    def test_two_qualifying_payload_directories_are_ambiguous(self):
        catalog = (
            ArchiveEntry("one", kind=EntryKind.DIRECTORY),
            ArchiveEntry("one/isolinux.bin", 10),
            ArchiveEntry("one/isolinux.cfg", 10),
            ArchiveEntry("two", kind=EntryKind.DIRECTORY),
            ArchiveEntry("two/isolinux.bin", 10),
            ArchiveEntry("two/isolinux.cfg", 10),
        )
        boot_analysis = analysis(
            "6.03-2014-10-06", "one/isolinux.bin", "two/isolinux.bin",
        )
        with self.assertRaisesRegex(SyslinuxStagingError, "exactly one"):
            plan_syslinux_staging(catalog, boot_analysis, module_bundle())

    def test_root_config_with_multiple_payloads_is_ambiguous(self):
        catalog = (
            ArchiveEntry("one", kind=EntryKind.DIRECTORY),
            ArchiveEntry("one/isolinux.bin", 10),
            ArchiveEntry("two", kind=EntryKind.DIRECTORY),
            ArchiveEntry("two/isolinux.bin", 10),
            ArchiveEntry("syslinux.cfg", 10),
        )
        boot_analysis = analysis(
            "6.03-2014-10-06", "one/isolinux.bin", "two/isolinux.bin",
        )
        with self.assertRaisesRegex(SyslinuxStagingError, "exactly one"):
            plan_syslinux_staging(catalog, boot_analysis, module_bundle())

    def test_non_ascii_and_overlong_configuration_directories_are_rejected(self):
        for directory in ("isolínux", "a" * staging.MAX_SYSLINUX_DIRECTORY_BYTES):
            config = f"{directory}/isolinux.cfg"
            loader = f"{directory}/isolinux.bin"
            catalog = entries(config, bootloader=loader)
            boot_analysis = analysis("6.03-2014-10-06", loader)
            with self.subTest(directory=directory):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(catalog, boot_analysis, module_bundle())

    def test_root_ldlinux_collision_is_always_rejected_case_insensitively(self):
        for collision in (
            ArchiveEntry("ldlinux.sys", 1),
            ArchiveEntry("LDLINUX.SYS", 1),
            ArchiveEntry("LdLinux.Sys", kind=EntryKind.DIRECTORY),
        ):
            with self.subTest(path=collision.path):
                with self.assertRaisesRegex(SyslinuxStagingError, "root ldlinux"):
                    plan_syslinux_staging(
                        entries() + (collision,), analysis(), module_bundle(),
                        source_files=source_member_bytes(),
                    )

    def test_planned_files_cannot_be_reserved_as_implied_directories(self):
        for collision in (
            ArchiveEntry("syslinux.cfg/child", 1),
            ArchiveEntry("isolinux/ldlinux.c32/child", 1),
            ArchiveEntry("LDLINUX.SYS/child", 1),
        ):
            with self.subTest(path=collision.path):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        entries() + (collision,), analysis(), module_bundle(),
                        source_files=source_member_bytes(),
                    )

    def test_catalog_casefold_collisions_and_links_are_rejected(self):
        colliding = entries() + (ArchiveEntry("ISOLINUX/ISOLINUX.CFG", 10),)
        prefix_alias = entries() + (ArchiveEntry("ISOLINUX/readme.txt", 10),)
        linked = entries() + (
            ArchiveEntry(
                "linked", kind=EntryKind.SYMLINK,
                link_target="isolinux/isolinux.cfg",
            ),
        )
        for catalog in (colliding, prefix_alias, linked):
            with self.subTest(catalog=catalog[-1]):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(catalog, analysis(), module_bundle())

    def test_non_pinned_misplaced_and_case_aliased_c32_files_are_rejected(self):
        cases = (
            ArchiveEntry("isolinux/menu.c32", 1),
            ArchiveEntry("other/ldlinux.c32", 1),
            ArchiveEntry("isolinux/LDLINUX.C32", len(VERSIONS["6.03-2014-10-06"][1])),
            ArchiveEntry("isolinux/module.C32", kind=EntryKind.DIRECTORY),
        )
        for item in cases:
            prefix = (
                (ArchiveEntry("other", kind=EntryKind.DIRECTORY),)
                if item.path.startswith("other/") else ()
            )
            with self.subTest(path=item.path):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        entries() + prefix + (item,), analysis(), module_bundle(),
                        source_files=source_member_bytes(),
                    )

    def test_existing_c32_requires_exact_catalog_size_path_and_bytes(self):
        data = VERSIONS["6.03-2014-10-06"][1]
        good_catalog = entries() + (ArchiveEntry("isolinux/ldlinux.c32", len(data)),)
        bad_inputs = (
            (good_catalog, None),
            (good_catalog, {"isolinux/ldlinux.c32": b"wrong"}),
            (good_catalog, {"ISOLINUX/LDLINUX.C32": data}),
            (entries() + (ArchiveEntry("isolinux/ldlinux.c32", len(data) - 1),),
             {"isolinux/ldlinux.c32": data}),
            (entries(), {"isolinux/ldlinux.c32": data}),
        )
        for catalog, supplied in bad_inputs:
            with self.subTest(supplied=supplied):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        catalog, analysis(), module_bundle(),
                        source_files=source_member_bytes(),
                        existing_files=supplied,
                    )

    def test_existing_byte_mapping_rejects_extra_and_casefold_keys(self):
        data = VERSIONS["6.03-2014-10-06"][1]
        catalog = entries() + (ArchiveEntry("isolinux/ldlinux.c32", len(data)),)
        for supplied in (
            {
                "isolinux/ldlinux.c32": data,
                "extra": b"x",
            },
            {
                "isolinux/ldlinux.c32": data,
                "ISOLINUX/LDLINUX.C32": data,
            },
        ):
            with self.subTest(supplied=supplied):
                with self.assertRaises(SyslinuxStagingError):
                    plan_syslinux_staging(
                        catalog, analysis(), module_bundle(),
                        source_files=source_member_bytes(),
                        existing_files=supplied,
                    )

    def test_plan_validation_rejects_forged_and_stale_plans(self):
        catalog = entries()
        sources = source_member_bytes()
        result = plan_syslinux_staging(
            catalog, analysis(), module_bundle(), source_files=sources,
        )
        for forged in (
            replace(result, config_path="other.cfg"),
            replace(result, config_directory="/other"),
            replace(result, dependency_key="syslinux:6.04-pre1"),
            replace(result, source_members_sha256="0" * 64),
            replace(result, config_sha256="0" * 64),
            replace(
                result,
                ldlinux_c32=replace(result.ldlinux_c32, disposition=StageDisposition.REUSE),
            ),
            replace(
                result,
                root_ldlinux_sys=replace(result.root_ldlinux_sys, path="other.sys"),
            ),
            replace(
                result,
                root_ldlinux_sys=replace(
                    result.root_ldlinux_sys,
                    disposition=StageDisposition.REUSE,
                ),
            ),
            replace(
                result,
                root_ldlinux_sys=replace(
                    result.root_ldlinux_sys,
                    data=b"changed",
                    sha256=hashlib.sha256(b"changed").hexdigest(),
                ),
            ),
        ):
            with self.subTest(forged=forged):
                with self.assertRaisesRegex(SyslinuxStagingError, "forged or stale"):
                    validate_syslinux_staging_plan(
                        forged, catalog, analysis(), module_bundle(),
                        source_files=sources,
                    )

        for field in ("source_members_sha256", "config_sha256"):
            with self.subTest(field=field):
                malformed = replace(result, **{field: "not-a-digest"})
                with self.assertRaisesRegex(SyslinuxStagingError, "digests are invalid"):
                    validate_syslinux_staging_plan(
                        malformed, catalog, analysis(), module_bundle(),
                        source_files=sources,
                    )

        with self.assertRaises(SyslinuxStagingError):
            validate_syslinux_staging_plan(
                result,
                catalog + (ArchiveEntry("README", 1),),
                analysis(),
                module_bundle(),
                source_files=sources,
            )

        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool:
                return True

        poisoned = plan_syslinux_staging(
            catalog, analysis(), module_bundle(), source_files=sources,
        )
        object.__setattr__(poisoned, "ldlinux_c32", AlwaysEqual())
        with self.assertRaisesRegex(SyslinuxStagingError, "fields are invalid"):
            validate_syslinux_staging_plan(
                poisoned, catalog, analysis(), module_bundle(),
                source_files=sources,
            )

    def test_input_types_and_manual_plan_are_rejected(self):
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(  # type: ignore[arg-type]
                "not a catalog", analysis(), module_bundle(),
            )
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(entries(), object(), module_bundle())  # type: ignore[arg-type]
        with self.assertRaises(SyslinuxStagingError):
            plan_syslinux_staging(entries(), analysis(), object())  # type: ignore[arg-type]

        sources = source_member_bytes()
        authentic = plan_syslinux_staging(
            entries(), analysis(), module_bundle(), source_files=sources,
        )
        manual = replace(authentic, _witness=None)
        with self.assertRaisesRegex(SyslinuxStagingError, "authentic"):
            validate_syslinux_staging_plan(
                manual, entries(), analysis(), module_bundle(),
                source_files=sources,
            )


if __name__ == "__main__":
    unittest.main()
