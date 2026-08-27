from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import math
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import Mock

from isopropyl.casper_media import (
    CasperLayoutExecutor,
    CasperMediaCancelled,
    CasperMediaError,
    CasperMediaExecutor,
    CasperMediaSafetyError,
    CasperStagingExecutor,
    _atomic_replace_config,
    build_casper_media_plan,
    build_casper_staging_plan,
    probe_casper_logical_sector_size,
    supported_casper_profile,
    validate_casper_media_plan,
)
from isopropyl.constructed import (
    ConstructedMediaCancelled,
    ConstructedMediaResult,
    ConstructedMediaSafetyError,
)
from isopropyl.devices import Device
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.formatting import (
    DeviceChangedError,
    FormattingError,
    MissingFormatToolError,
    PartitionRole,
    PartitionTable,
)
from isopropyl.persistence import MIB, ubuntu_casper_profile


DATA_GUID = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
LINUX_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


def device(**changes) -> Device:
    values = dict(
        path="/dev/sdz",
        size=8 * 1024 * MIB,
        model="Flash",
        vendor="Acme",
        transport="usb",
        serial="SERIAL",
        wwn="",
        major_minor="65:144",
        removable=True,
        hotplug=True,
        read_only=False,
        mountpoints=(),
        partitions=(),
    )
    values.update(changes)
    return Device(**values)


def finder(name: str) -> str:
    directory = "/usr/sbin" if name in {
        "sfdisk", "partprobe", "mkfs.vfat", "mkfs.ext4",
    } else "/usr/bin"
    return f"{directory}/{name}"


def create_staging(root: Path, *, release: str = "24.04") -> None:
    (root / ".disk").mkdir(parents=True)
    (root / ".disk/info").write_text(
        f'Ubuntu {release}.1 LTS "Fixture" - Release amd64 (test)\n',
        encoding="utf-8",
    )
    (root / "casper").mkdir()
    (root / "casper/vmlinuz").write_bytes(b"kernel")
    (root / "casper/initrd").write_bytes(b"initrd")
    (root / "casper/filesystem.squashfs").write_bytes(b"squashfs")
    (root / "EFI/BOOT").mkdir(parents=True)
    (root / "EFI/BOOT/BOOTX64.EFI").write_bytes(b"uefi")
    (root / "boot/grub").mkdir(parents=True)
    (root / "boot/grub/grub.cfg").write_bytes(
        b"menuentry live {\n  linux /casper/vmlinuz boot=casper quiet ---\n}\n"
    )
    (root / "isolinux").mkdir()
    (root / "isolinux/txt.cfg").write_bytes(
        b"LABEL live\n KERNEL /casper/vmlinuz\n"
        b" APPEND initrd=/casper/initrd boot=casper quiet ---\n"
    )


def staged(root: Path, *, release: str = "24.04"):
    create_staging(root, release=release)
    profile = ubuntu_casper_profile(release)
    plan = build_casper_staging_plan(root, profile)
    result = CasperStagingExecutor().execute(plan)
    return profile, plan, result


def media_plan(root: Path, *, sector=512, persistence=1024 * MIB, target=None):
    profile, _stage_plan, result = staged(root)
    plan = build_casper_media_plan(
        root,
        result,
        target or device(),
        persistence,
        sector,
        finder=finder,
        source_on_device=lambda _path, _device: False,
    )
    return profile, result, plan


def partition_metadata(plan, *, wrong=False) -> str:
    entries = []
    for index, spec in enumerate(plan.layout.partitions, 1):
        entries.append({
            "node": f"/dev/sdz{index}",
            "start": spec.start_sector,
            "size": (spec.sector_count + 1 if wrong and index == 2 else spec.sector_count),
            "type": DATA_GUID if index == 1 else LINUX_GUID,
            "name": "ISOpropyl data" if index == 1 else "ISOpropyl persistence",
        })
    return json.dumps({"partitiontable": {
        "label": "gpt",
        "device": "/dev/sdz",
        "unit": "sectors",
        "sectorsize": plan.layout.logical_sector_size,
        "partitions": entries,
    }})


def block_metadata(*, wrong_parent=False, mounted=False, wrong_label=False) -> str:
    return json.dumps({"blockdevices": [{
        "path": "/dev/sdz",
        "type": "disk",
        "children": [
            {
                "path": "/dev/sdz1", "type": "part",
                "pkname": "/dev/sdy" if wrong_parent else "/dev/sdz",
                "fstype": "vfat", "label": "OTHER" if wrong_label else "ISOPROPYL",
                "maj:min": "65:145", "mountpoints": ["/media/data"] if mounted else [],
                "ro": False,
            },
            {
                "path": "/dev/sdz2", "type": "part", "pkname": "/dev/sdz",
                "fstype": "ext4", "label": "writable", "maj:min": "65:146",
                "mountpoints": [], "ro": False,
            },
        ],
    }]})


class BlockStat:
    def __init__(self, major: int, minor: int):
        self.st_mode = stat.S_IFBLK | 0o660
        self.st_rdev = os.makedev(major, minor)


def block_stat(path: str):
    mapping = {
        "/dev/sdz": (65, 144),
        "/dev/sdz1": (65, 145),
        "/dev/sdz2": (65, 146),
    }
    return BlockStat(*mapping[path])


class StagingTests(unittest.TestCase):
    def test_private_transform_is_exact_idempotent_and_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile, plan, result = staged(root)
            self.assertEqual(result.profile, profile)
            self.assertEqual(len(result.boot_configs), 2)
            self.assertIn(
                b"quiet persistent ---", (root / "boot/grub/grub.cfg").read_bytes(),
            )
            self.assertIn(
                b"quiet persistent ---", (root / "isolinux/txt.cfg").read_bytes(),
            )
            self.assertTrue(all(item.eligible_lines == 1 for item in result.boot_configs))
            with self.assertRaises(FrozenInstanceError):
                plan.root = Path("/tmp")  # type: ignore[misc]

            repeated = build_casper_staging_plan(root, profile)
            repeated_result = CasperStagingExecutor().execute(repeated)
            self.assertEqual(
                tuple(item.sha256 for item in repeated_result.boot_configs),
                tuple(item.sha256 for item in result.boot_configs),
            )

            published = root.parent / f"{root.name}-published"
            os.rename(root, published)
            try:
                built = build_casper_media_plan(
                    published, result, device(), 1024 * MIB, 512,
                    finder=finder, source_on_device=lambda _path, _device: False,
                )
                self.assertEqual(built.staging.root_identity, result.root_identity)
            finally:
                os.rename(published, root)

    def test_rejects_release_architecture_evidence_and_link_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            create_staging(root, release="22.04")
            with self.assertRaisesRegex(CasperMediaSafetyError, "release"):
                build_casper_staging_plan(root, ubuntu_casper_profile("24.04"))

        for mutation in ("extra_initrd", "symlink_config", "unknown_syntax"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                create_staging(root)
                if mutation == "extra_initrd":
                    (root / "casper/initrd.lz").write_bytes(b"other")
                elif mutation == "symlink_config":
                    config = root / "boot/grub/grub.cfg"
                    config.unlink()
                    config.symlink_to(root / "isolinux/txt.cfg")
                else:
                    (root / "boot/grub/grub.cfg").write_bytes(
                        b"linux /casper/${kernel} quiet ---\n"
                    )
                with self.assertRaises(CasperMediaSafetyError):
                    build_casper_staging_plan(root, ubuntu_casper_profile("24.04"))

    def test_cancel_before_or_between_replacements_never_returns_a_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            create_staging(root)
            plan = build_casper_staging_plan(root, ubuntu_casper_profile("24.04"))
            executor = CasperStagingExecutor()
            executor.cancel()
            with self.assertRaises(CasperMediaCancelled):
                executor.execute(plan)
            self.assertNotIn(b"persistent", (root / "boot/grub/grub.cfg").read_bytes())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            create_staging(root)
            plan = build_casper_staging_plan(root, ubuntu_casper_profile("24.04"))
            holder = {}
            replacements = []

            def replace_then_cancel(*args):
                _atomic_replace_config(*args)
                replacements.append(args[1].relative_path)
                holder["executor"].cancel()

            executor = CasperStagingExecutor(replacer=replace_then_cancel)
            holder["executor"] = executor
            with self.assertRaisesRegex(CasperMediaCancelled, "discard"):
                executor.execute(plan)
            self.assertEqual(len(replacements), 1)
            self.assertIn(b"persistent", (root / replacements[0]).read_bytes())
            untouched = next(
                item.relative_path for item in plan.boot_configs
                if item.relative_path != replacements[0]
            )
            self.assertNotIn(b"persistent", (root / untouched).read_bytes())


class PlanTests(unittest.TestCase):
    def test_ui_candidate_requires_an_exposed_uefi_grub_configuration(self):
        members = tuple(
            ImageMember(path, 1, "file") for path in (
                ".disk/info", "casper/vmlinuz", "casper/filesystem.squashfs",
                "casper/initrd", "EFI/BOOT/BOOTX64.EFI",
                "boot/grub/grub.cfg",
            )
        )
        candidate = ImageInspection(
            1024, "Optical ISO", "Ubuntu 24.04.3 LTS amd64", True, False,
            True, False, ("BIOS", "UEFI"), ("x64",), "GRUB", False, True,
            members=members,
        )
        profile = supported_casper_profile(candidate)
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile.ubuntu_release, "24.04")
        for forged in (
            replace(candidate, volume_label="Linux 24.04 amd64"),
            replace(candidate, architectures=("ARM64",)),
            replace(candidate, contents_scanned=False),
            replace(candidate, members=members[:-1]),
            replace(candidate, has_windows_installer=True),
        ):
            with self.subTest(forged=forged):
                self.assertIsNone(supported_casper_profile(forged))

    def test_current_official_ubuntu_catalog_shapes_are_not_false_positives(self):
        common = (
            ".disk/info", "casper/vmlinuz", "casper/initrd",
            "EFI/BOOT/BOOTX64.EFI",
        )
        # Derived from Ubuntu's published 20.04.6, 22.04.5, and 24.04.3
        # desktop ISO .list files.  The current images do not expose a UEFI
        # GRUB config that the immutable staging transform can safely bind.
        catalogs = (
            (
                "Ubuntu 20.04.6 LTS amd64",
                common + ("casper/filesystem.squashfs", "isolinux/txt.cfg"),
            ),
            (
                "Ubuntu 22.04.5 LTS amd64",
                common + ("casper/filesystem.squashfs",),
            ),
            (
                "Ubuntu 24.04.3 LTS amd64",
                common + ("casper/minimal.squashfs",),
            ),
        )
        for label, paths in catalogs:
            inspection = ImageInspection(
                1024, "Optical ISO", label, True, False, True, False,
                ("BIOS", "UEFI"), ("x64",), "GRUB", False, True,
                members=tuple(ImageMember(path, 1, "file") for path in paths),
            )
            with self.subTest(label=label):
                self.assertIsNone(supported_casper_profile(inspection))

    def test_staging_rejects_syslinux_only_media_for_uefi_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            create_staging(root)
            (root / "boot/grub/grub.cfg").unlink()
            with self.assertRaisesRegex(CasperMediaSafetyError, "UEFI-only"):
                build_casper_staging_plan(
                    root, ubuntu_casper_profile("24.04"),
                )

    def test_preconsent_sector_probe_binds_device_and_supports_512_or_4096(self):
        for sector in (512, 4096):
            with self.subTest(sector=sector):
                target = device()
                payload = json.dumps({"blockdevices": [{
                    "path": target.path, "size": target.size, "type": "disk",
                    "rm": True, "hotplug": True, "tran": "usb",
                    "model": target.model, "vendor": target.vendor,
                    "serial": target.serial, "wwn": target.wwn,
                    "maj:min": target.major_minor, "mountpoints": [], "ro": False,
                    "log-sec": sector,
                }]})
                calls = []

                def runner(argv, **kwargs):
                    calls.append((argv, kwargs))
                    return subprocess.CompletedProcess(argv, 0, payload, "")

                self.assertEqual(
                    probe_casper_logical_sector_size(
                        target, finder=finder, runner=runner,
                    ),
                    sector,
                )
                self.assertIn("--nodeps", calls[0][0])
                self.assertFalse(calls[0][1]["shell"])

        changed = device(serial="REPLACEMENT")
        payload = json.dumps({"blockdevices": [{
            "path": changed.path, "size": changed.size, "type": "disk",
            "rm": True, "hotplug": True, "tran": "usb", "model": changed.model,
            "vendor": changed.vendor, "serial": changed.serial, "wwn": changed.wwn,
            "maj:min": changed.major_minor, "mountpoints": [], "ro": False,
            "log-sec": 512,
        }]})
        with self.assertRaisesRegex(CasperMediaSafetyError, "changed"):
            probe_casper_logical_sector_size(
                device(), finder=finder,
                runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, payload, "",
                ),
            )

    def test_exact_gpt_geometry_for_512_and_4096_sector_media(self):
        for sector in (512, 4096):
            with self.subTest(sector=sector), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                _profile, _staging, plan = media_plan(root, sector=sector)
                alignment = MIB // sector
                tail = math.ceil((128 * 128) / sector) + 1
                aligned_end = ((device().size // sector - tail) // alignment) * alignment
                data, persistence = plan.layout.partitions
                self.assertEqual(data.start_sector, alignment)
                self.assertEqual(persistence.sector_count, 1024 * MIB // sector)
                self.assertEqual(persistence.start_sector, aligned_end - persistence.sector_count)
                self.assertEqual(data.sector_count, persistence.start_sector - alignment)
                self.assertEqual(data.role, PartitionRole.DATA)
                self.assertEqual(persistence.role, PartitionRole.PERSISTENCE)
                self.assertEqual(plan.data_capacity, data.sector_count * sector)
                validate_casper_media_plan(plan)

    def test_rejects_small_unaligned_unsupported_and_capacity_exhaustion(self):
        failures = (
            (255 * MIB, 512, device()),
            (256 * MIB + 1, 512, device()),
            (256 * MIB, 2048, device()),
            (256 * MIB, 512, device(size=300 * MIB)),
        )
        for persistence, sector, target in failures:
            with self.subTest(persistence=persistence, sector=sector), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                profile, _plan, result = staged(root)
                self.assertEqual(profile.architecture, "amd64")
                with self.assertRaises(CasperMediaSafetyError):
                    build_casper_media_plan(
                        root, result, target, persistence, sector,
                        finder=finder,
                        source_on_device=lambda _path, _device: False,
                    )

    def test_rejects_source_overlap_changed_staging_and_forged_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, result, plan = media_plan(root)
            with self.assertRaisesRegex(CasperMediaSafetyError, "stored on the target"):
                build_casper_media_plan(
                    root, result, device(), 1024 * MIB, 512,
                    finder=finder, source_on_device=lambda _path, _device: True,
                )
            (root / "boot/grub/grub.cfg").write_bytes(b"changed")
            with self.assertRaises(CasperMediaSafetyError):
                validate_casper_media_plan(plan)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _result, plan = media_plan(root)
            for forged in (
                replace(plan, persistence_bytes=256 * MIB),
                replace(plan, data_capacity=1),
                replace(plan, profile=replace(plan.profile, partition_label="evil")),
                replace(plan, tools=replace(plan.tools, sfdisk="/tmp/sfdisk")),
            ):
                with self.subTest(forged=forged), self.assertRaises(CasperMediaSafetyError):
                    validate_casper_media_plan(forged)


class FakeProcess:
    def __init__(self, argv, calls, **kwargs):
        self.argv = list(argv)
        self.calls = calls
        self.kwargs = kwargs
        self.returncode = 0

    def communicate(self, input=None, timeout=None):
        self.calls.append((self.argv, input))
        return b"", b""

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class LayoutExecutorTests(unittest.TestCase):
    def test_missing_flock_preflight_touches_no_device_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            runner = Mock()
            popen = Mock()
            boundary = Mock()
            executor = CasperLayoutExecutor(
                boundary_validator=boundary,
                device_lookup=lambda _path: device(),
                which=lambda name: None if name == "flock" else finder(name),
                runner=runner,
                popen=popen,
            )
            with self.assertRaisesRegex(MissingFormatToolError, "flock"):
                executor.execute_multi(device(), plan.layout)
            runner.assert_not_called()
            popen.assert_not_called()
            boundary.assert_not_called()

    def test_revalidates_exact_geometry_and_nodes_before_each_mkfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            process_calls = []
            boundaries = []

            def runner(argv, **_kwargs):
                if argv[0] == "/usr/bin/lsblk" and "--nodeps" in argv:
                    return subprocess.CompletedProcess(argv, 0, json.dumps({
                        "blockdevices": [{
                            "path": "/dev/sdz", "type": "disk", "log-sec": 512,
                        }],
                    }), "")
                if argv[0] == "/usr/bin/lsblk":
                    return subprocess.CompletedProcess(argv, 0, json.dumps({
                        "blockdevices": [{
                            "path": "/dev/sdz", "type": "disk", "children": [
                                {
                                    "path": "/dev/sdz1", "type": "part",
                                    "pkname": "/dev/sdz", "maj:min": "65:145",
                                },
                                {
                                    "path": "/dev/sdz2", "type": "part",
                                    "pkname": "/dev/sdz", "maj:min": "65:146",
                                },
                            ],
                        }],
                    }), "")
                if len(argv) > 2 and argv[1] == "/usr/sbin/sfdisk" and "--json" in argv:
                    return subprocess.CompletedProcess(argv, 0, partition_metadata(plan), "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            def boundary(_partitions):
                completed_mkfs = sum(
                    any("mkfs." in item for item in command)
                    for command, _input in process_calls
                )
                boundaries.append(completed_mkfs)

            executor = CasperLayoutExecutor(
                boundary_validator=boundary,
                device_lookup=lambda _path: device(),
                which=finder,
                runner=runner,
                lstat_func=block_stat,
                popen=lambda argv, **kwargs: FakeProcess(argv, process_calls, **kwargs),
                sleep=lambda _seconds: None,
            )
            partitions = executor.execute_multi(device(), plan.layout)
            self.assertEqual(partitions, ("/dev/sdz1", "/dev/sdz2"))
            self.assertEqual(boundaries, [0, 1])
            mkfs = [
                command for command, _input in process_calls
                if any("mkfs." in item for item in command)
            ]
            self.assertEqual(len(mkfs), 2)
            self.assertTrue(any("mkfs.vfat" in item for item in mkfs[0]))
            self.assertTrue(any("mkfs.ext4" in item for item in mkfs[1]))
            self.assertTrue(all(command[1] == "/usr/bin/flock" for command in mkfs))
            self.assertTrue(all(command[7] == "/dev/sdz" for command in mkfs))

    def test_partition_device_identity_swap_stops_before_first_mkfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            process_calls = []
            identity_reads = 0

            def runner(argv, **_kwargs):
                nonlocal identity_reads
                if argv[0] == "/usr/bin/lsblk" and "--nodeps" in argv:
                    return subprocess.CompletedProcess(argv, 0, json.dumps({
                        "blockdevices": [{
                            "path": "/dev/sdz", "type": "disk", "log-sec": 512,
                        }],
                    }), "")
                if len(argv) > 2 and argv[1] == "/usr/sbin/sfdisk" and "--json" in argv:
                    return subprocess.CompletedProcess(
                        argv, 0, partition_metadata(plan), "",
                    )
                if argv[0] == "/usr/bin/lsblk":
                    identity_query = "PATH,TYPE,PKNAME,MAJ:MIN" in argv
                    if identity_query:
                        identity_reads += 1
                    offset = 10 if identity_reads >= 2 else 0
                    return subprocess.CompletedProcess(argv, 0, json.dumps({
                        "blockdevices": [{
                            "path": "/dev/sdz", "type": "disk", "children": [
                                {
                                    "path": "/dev/sdz1", "type": "part",
                                    "pkname": "/dev/sdz",
                                    "maj:min": f"65:{145 + offset}",
                                },
                                {
                                    "path": "/dev/sdz2", "type": "part",
                                    "pkname": "/dev/sdz",
                                    "maj:min": f"65:{146 + offset}",
                                },
                            ],
                        }],
                    }), "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            def changing_stat(path: str):
                if path == "/dev/sdz":
                    return block_stat(path)
                offset = 10 if identity_reads >= 2 else 0
                minor = 145 if path.endswith("1") else 146
                return BlockStat(65, minor + offset)

            executor = CasperLayoutExecutor(
                boundary_validator=lambda _partitions: None,
                device_lookup=lambda _path: device(),
                which=finder,
                runner=runner,
                lstat_func=changing_stat,
                popen=lambda argv, **kwargs: FakeProcess(
                    argv, process_calls, **kwargs,
                ),
                sleep=lambda _seconds: None,
            )
            with self.assertRaisesRegex(DeviceChangedError, "identity changed"):
                executor.execute_multi(device(), plan.layout)
            self.assertEqual(identity_reads, 2)
            self.assertFalse(any(
                any("mkfs." in item for item in command)
                for command, _input in process_calls
            ))


class FakeLayout:
    def __init__(self, events, error=None, preflight_error=None):
        self.events = events
        self.error = error
        self.preflight_error = preflight_error
        self.cancelled = False

    def execute_multi(self, _device, _layout, stage=None):
        if self.preflight_error:
            raise self.preflight_error
        if stage is not None:
            stage("Creating partition table")
        self.events.extend(("mkfs-fat32", "mkfs-ext4"))
        if self.error:
            raise self.error
        return "/dev/sdz1", "/dev/sdz2"

    def cancel(self):
        self.cancelled = True


class FakeContent:
    def __init__(
        self, events, *, unmounted=True, hook=None, error=None,
        preflight_error=None,
    ):
        self.events = events
        self.unmounted = unmounted
        self.hook = hook
        self.error = error
        self.preflight_error = preflight_error
        self.cancelled = False
        self.calls = []

    def verify_pre_destructive(self, _plan):
        self.events.append("preflight")
        if self.preflight_error:
            raise self.preflight_error

    def populate_existing_partition(self, plan, partition, progress, *, power_off):
        self.events.append("copy")
        self.calls.append((plan, partition, power_off))
        if self.hook:
            self.hook()
        if self.error:
            raise self.error
        progress(type("Update", (), {
            "stage": "Copying", "relative_path": "casper/vmlinuz",
            "bytes_done": plan.total_bytes, "total_bytes": plan.total_bytes,
        })())
        return ConstructedMediaResult(
            plan.device.identity, partition, "/media/data",
            len(plan.files), plan.total_bytes, self.unmounted, False,
        )

    def cancel(self):
        self.cancelled = True


class ExecutorTests(unittest.TestCase):
    def make_executor(
        self,
        plan,
        *,
        events=None,
        wrong_geometry=False,
        wrong_parent=False,
        wrong_label=False,
        content_unmounted=True,
        content_hook=None,
        layout_error=None,
        layout_preflight_error=None,
        content_error=None,
        content_preflight_error=None,
        current=None,
    ):
        events = events if events is not None else []
        layout = FakeLayout(events, layout_error, layout_preflight_error)
        content = FakeContent(
            events,
            unmounted=content_unmounted,
            hook=content_hook,
            error=content_error,
            preflight_error=content_preflight_error,
        )
        commands = []
        state = current or {"device": device()}

        def run(argv, **kwargs):
            commands.append((list(argv), kwargs))
            if len(argv) > 2 and argv[1] == "/usr/sbin/sfdisk" and "--json" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, partition_metadata(plan, wrong=wrong_geometry), "",
                )
            if argv[0] == "/usr/bin/lsblk":
                return subprocess.CompletedProcess(
                    argv, 0, block_metadata(
                        wrong_parent=wrong_parent, wrong_label=wrong_label,
                    ), "",
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

        executor = CasperMediaExecutor(
            layout_executor=layout,  # type: ignore[arg-type]
            content_executor=content,  # type: ignore[arg-type]
            run_command=run,
            device_lister=lambda: [state["device"]],
            stat_func=block_stat,
        )
        return executor, layout, content, commands, events, state

    def test_formats_both_before_copy_verifies_unmounts_and_powers_off(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, content, commands, events, _state = self.make_executor(plan)
            updates = []
            result = executor.execute(plan, updates.append)
            self.assertEqual(
                events, ["preflight", "mkfs-fat32", "mkfs-ext4", "copy"],
            )
            self.assertEqual(content.calls[0][1:], ("/dev/sdz1", False))
            self.assertEqual(result.persistence_partition, "/dev/sdz2")
            self.assertEqual(result.persistence_label, "writable")
            self.assertTrue(result.powered_off)
            flat = [item for command, _kwargs in commands for item in command]
            self.assertNotIn("--append", flat)
            self.assertNotIn("--delete", flat)
            self.assertNotIn("--resize", flat)
            self.assertEqual(
                sum(command[1] == "unmount" for command, _kwargs in commands), 2,
            )
            self.assertTrue(any(command[1] == "power-off" for command, _ in commands))
            self.assertEqual(updates[-1].stage, "Complete")

    def test_wrong_geometry_node_parent_or_label_stops_before_copy(self):
        for option in ("geometry", "parent", "label"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                _profile, _staging, plan = media_plan(root)
                executor, _layout, content, _commands, _events, _state = self.make_executor(
                    plan,
                    wrong_geometry=option == "geometry",
                    wrong_parent=option == "parent",
                    wrong_label=option == "label",
                )
                with self.assertRaises(CasperMediaSafetyError):
                    executor.execute(plan)
                self.assertEqual(content.calls, [])

    def test_complete_source_preflight_failure_prevents_any_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, content, _commands, events, _state = self.make_executor(
                plan,
                content_preflight_error=ConstructedMediaSafetyError(
                    "staged tree changed"
                ),
            )
            with self.assertRaisesRegex(
                CasperMediaSafetyError, "^staged tree changed$",
            ):
                executor.execute(plan)
            self.assertEqual(events, ["preflight"])
            self.assertEqual(content.calls, [])

    def test_preflight_cancellation_does_not_claim_media_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, content, commands, events, _state = self.make_executor(
                plan,
                content_preflight_error=ConstructedMediaCancelled("cancelled"),
            )
            with self.assertRaises(CasperMediaCancelled) as raised:
                executor.execute(plan)
            self.assertNotIn("incomplete", str(raised.exception).casefold())
            self.assertEqual(events, ["preflight"])
            self.assertEqual(commands, [])
            self.assertEqual(content.calls, [])

    def test_layout_preflight_failure_does_not_claim_media_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, content, commands, events, _state = self.make_executor(
                plan,
                layout_preflight_error=FormattingError("unmount refused"),
            )
            with self.assertRaises(CasperMediaError) as raised:
                executor.execute(plan)
            self.assertNotIn("incomplete", str(raised.exception).casefold())
            self.assertEqual(events, ["preflight"])
            self.assertEqual(content.calls, [])
            self.assertEqual(commands, [])

    def test_cancellation_failure_and_unclean_unmount_surface_incomplete_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, layout, content, commands, _events, _state = self.make_executor(
                plan,
                content_hook=lambda: executor.cancel(),
                content_error=ConstructedMediaCancelled("cancelled"),
            )
            with self.assertRaisesRegex(CasperMediaCancelled, "incomplete"):
                executor.execute(plan)
            self.assertTrue(layout.cancelled)
            self.assertTrue(content.cancelled)
            self.assertFalse(any(command[1] == "power-off" for command, _ in commands))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, _content, _commands, _events, _state = self.make_executor(
                plan, layout_error=FormattingError("mkfs failed"),
            )
            with self.assertRaisesRegex(CasperMediaError, "incomplete"):
                executor.execute(plan)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, _layout, _content, _commands, _events, _state = self.make_executor(
                plan, content_unmounted=False,
            )
            with self.assertRaisesRegex(CasperMediaError, "cleanly unmounted"):
                executor.execute(plan)
            self.assertFalse(any(
                command[1] == "power-off" for command, _ in _commands
            ))

    def test_device_replacement_after_copy_is_not_powered_off(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            state = {"device": device()}

            def replace_device():
                state["device"] = device(serial="REPLACEMENT")

            executor, _layout, _content, commands, _events, _state = self.make_executor(
                plan, content_hook=replace_device, current=state,
            )
            with self.assertRaisesRegex(CasperMediaSafetyError, "changed identity"):
                executor.execute(plan)
            self.assertFalse(any(command[1] == "power-off" for command, _ in commands))

    def test_cancel_before_start_touches_nothing_and_executor_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _profile, _staging, plan = media_plan(root)
            executor, layout, content, commands, events, _state = self.make_executor(plan)
            executor.cancel()
            with self.assertRaises(CasperMediaCancelled):
                executor.execute(plan)
            self.assertTrue(layout.cancelled)
            self.assertTrue(content.cancelled)
            self.assertEqual(commands, [])
            self.assertEqual(events, [])
            with self.assertRaisesRegex(CasperMediaSafetyError, "only be used once"):
                executor.execute(plan)


if __name__ == "__main__":
    unittest.main()
