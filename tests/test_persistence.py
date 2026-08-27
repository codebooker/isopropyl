from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import json
import stat
import subprocess
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.formatting import PartitionTable
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.persistence import (
    LINUX_FILESYSTEM_GUID,
    MICROSOFT_BASIC_DATA_GUID,
    MIB,
    SECTOR_BYTES,
    BootConfigTransform,
    CasperPersistenceExecutor,
    MediaLayout,
    PartitionLayout,
    PersistenceBackendCancelled,
    PersistenceBackendError,
    PersistenceBackendSafetyError,
    PersistenceError,
    build_casper_persistence_backend_plan,
    build_persistence_plan,
    detect_persistence_profile,
    persistence_format_command,
    persistence_partition_command,
    persistence_partition_script,
    read_media_layout,
    resolve_persistence_tools,
    transform_grub_config,
    transform_syslinux_config,
    ubuntu_casper_profile,
    validate_casper_persistence_backend_plan,
)


def image(label, paths):
    return ImageInspection(
        100, "Optical ISO", label, True, False, True, False,
        ("BIOS", "UEFI"), ("x64",), "GRUB", False, True,
        members=tuple(ImageMember(path, 1, "file") for path in paths),
    )


class PersistenceTests(unittest.TestCase):
    def test_modern_and_legacy_casper_labels_are_not_confused(self):
        modern = detect_persistence_profile(image(
            "Ubuntu 24.04 LTS", ("casper/vmlinuz", "casper/filesystem.squashfs"),
        ))
        legacy = detect_persistence_profile(image(
            "Ubuntu 18.04 LTS", ("casper/vmlinuz", "casper/filesystem.squashfs"),
        ))
        self.assertEqual(modern.label, "writable")
        self.assertEqual(legacy.label, "casper-rw")
        self.assertEqual(modern.boot_parameter, "persistent")

    def test_debian_live_boot_profile_has_exact_config(self):
        profile = detect_persistence_profile(image(
            "Debian Live 13", ("live/vmlinuz", "live/filesystem.squashfs"),
        ))
        self.assertEqual(profile.label, "persistence")
        self.assertEqual(profile.configuration_path, "persistence.conf")
        self.assertEqual(profile.configuration_contents, "/ union\n")

    def test_tails_and_unknown_images_fail_closed(self):
        self.assertIsNone(detect_persistence_profile(image(
            "Tails 7", ("live/vmlinuz", "live/filesystem.squashfs"),
        )))
        self.assertIsNone(detect_persistence_profile(image("CUSTOM", ("boot/kernel",))))

    def test_plan_validates_minimum_and_alignment_but_stays_nonexecutable(self):
        inspection = image(
            "Kali Live", ("live/vmlinuz", "live/filesystem.squashfs"),
        )
        plan = build_persistence_plan(inspection, 1024 * MIB)
        self.assertFalse(plan.executable)
        self.assertIn("per-release", plan.blocker)
        for size in (255 * MIB, 300 * MIB + 1):
            with self.subTest(size=size), self.assertRaises(PersistenceError):
                build_persistence_plan(inspection, size)


PROGRAMS = {
    "pkexec": "/usr/bin/pkexec",
    "sfdisk": "/usr/sbin/sfdisk",
    "partprobe": "/usr/sbin/partprobe",
    "udevadm": "/usr/bin/udevadm",
    "lsblk": "/usr/bin/lsblk",
    "mkfs.ext4": "/usr/sbin/mkfs.ext4",
}


def find_program(name):
    return PROGRAMS.get(name)


def persistence_device(**changes):
    values = {
        "path": "/dev/sdz",
        "size": 8 * 1024 * MIB,
        "model": "Persistence Test",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "PERSIST-001",
        "wwn": "",
        "major_minor": "65:144",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": (),
        "partitions": ("/dev/sdz1",),
    }
    values.update(changes)
    return Device(**values)


def create_media(root: Path, *, release="24.04", persistent=False):
    (root / ".disk").mkdir(parents=True)
    (root / ".disk/info").write_text(
        f'Ubuntu {release}.1 LTS "Test" - Release amd64 (test)\n',
    )
    (root / "casper").mkdir()
    (root / "casper/vmlinuz").write_bytes(b"kernel")
    (root / "casper/initrd").write_bytes(b"initrd")
    (root / "casper/filesystem.squashfs").write_bytes(b"squashfs")
    (root / "EFI/BOOT").mkdir(parents=True)
    (root / "EFI/BOOT/BOOTX64.EFI").write_bytes(b"efi-loader")
    token = " persistent" if persistent else ""
    (root / "boot/grub").mkdir(parents=True)
    (root / "boot/grub/grub.cfg").write_text(
        "menuentry 'Try Ubuntu' {\n"
        f"  linux /casper/vmlinuz boot=casper quiet{token} ---\n"
        "  initrd /casper/initrd\n"
        "}\n"
    )
    (root / "isolinux").mkdir()
    (root / "isolinux/txt.cfg").write_text(
        "LABEL live\n"
        "  KERNEL /casper/vmlinuz\n"
        f"  APPEND initrd=/casper/initrd boot=casper quiet{token} ---\n"
    )


def initial_layout(root: Path):
    first = PartitionLayout(
        number=1,
        path="/dev/sdz1",
        start_sector=2048,
        sector_count=5 * 1024 * MIB // SECTOR_BYTES,
        partition_type=MICROSOFT_BASIC_DATA_GUID,
        filesystem="vfat",
        label="ISOPROPYL",
        mountpoints=(str(root),),
        major_minor="65:145",
    )
    return MediaLayout(PartitionTable.GPT, SECTOR_BYTES, (first,))


class BlockStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(65, 146)


class FakeProcess:
    def __init__(self, argv, *, code=0, stderr_data=b"", hook=None, **kwargs):
        self.argv = list(argv)
        self.kwargs = kwargs
        self.returncode = code
        self.stderr = stderr_data
        self.inputs = []
        self.terminated = False
        self.killed = False
        self._hook = hook
        self._hooked = False

    def poll(self):
        return self.returncode

    def communicate(self, input=None, timeout=None):
        self.inputs.append(input)
        if self._hook and not self._hooked:
            self._hooked = True
            self._hook()
        return b"", self.stderr

    def terminate(self):
        self.terminated = True
        if self.returncode is None:
            self.returncode = -15

    def kill(self):
        self.killed = True
        if self.returncode is None:
            self.returncode = -9


class BackendHarness:
    def __init__(self, root: Path, *, fail_command=None, wrong_geometry=False):
        self.root = root
        self.device = persistence_device()
        self.initial = initial_layout(root)
        self.state = "initial"
        self.fail_command = fail_command
        self.wrong_geometry = wrong_geometry
        self.processes = []

    def current_device(self, _path):
        partitions = (
            ("/dev/sdz1",)
            if self.state == "initial"
            else ("/dev/sdz1", "/dev/sdz2")
        )
        return replace(self.device, partitions=partitions)

    def _second(self, formatted=False):
        plan = self.plan
        return PartitionLayout(
            number=2,
            path="/dev/sdz2",
            start_sector=plan.partition_start_sector + (2048 if self.wrong_geometry else 0),
            sector_count=plan.partition_sector_count,
            partition_type=LINUX_FILESYSTEM_GUID,
            filesystem="ext4" if formatted else "",
            label="writable" if formatted else "",
            mountpoints=(),
            major_minor="65:146",
        )

    def layout_reader(self, _device, _root, _tools):
        if self.state == "initial":
            return self.initial
        return MediaLayout(
            PartitionTable.GPT,
            SECTOR_BYTES,
            (self.initial.partitions[0], self._second(self.state == "formatted")),
        )

    def popen(self, argv, **kwargs):
        command = list(argv)
        code = 1 if self.fail_command and any(
            item == self.fail_command or item.endswith("/" + self.fail_command)
            for item in command
        ) else 0
        hook = None
        if "--append" in command:
            hook = lambda: setattr(self, "state", "created")
        elif any(item.endswith("/mkfs.ext4") for item in command):
            hook = lambda: setattr(self, "state", "formatted")
        elif "--delete" in command:
            hook = lambda: setattr(self, "state", "initial")
        process = FakeProcess(
            command,
            code=code,
            stderr_data=b"intentional failure" if code else b"",
            hook=hook,
            **kwargs,
        )
        self.processes.append(process)
        return process

    def build(self, *, size=1024 * MIB, profile=None):
        self.plan = build_casper_persistence_backend_plan(
            self.root,
            self.device,
            size,
            profile or ubuntu_casper_profile("24.04"),
            finder=find_program,
            device_lookup=self.current_device,
            layout_reader=self.layout_reader,
        )
        return self.plan

    def executor(self):
        return CasperPersistenceExecutor(
            device_lookup=self.current_device,
            layout_reader=self.layout_reader,
            popen=self.popen,
            block_stat=lambda _path: BlockStat(),
        )


class BootConfigTransformTests(unittest.TestCase):
    def test_grub_inserts_exact_token_before_separator_and_is_idempotent(self):
        source = (
            b"menuentry live {\n"
            b"  linux /casper/vmlinuz boot=casper quiet ---\n"
            b"}\n"
        )
        transformed = transform_grub_config(source)
        self.assertIsInstance(transformed, BootConfigTransform)
        self.assertEqual((transformed.eligible_lines, transformed.changed_lines), (1, 1))
        self.assertIn(b"quiet persistent ---", transformed.contents)
        repeated = transform_grub_config(transformed.contents)
        self.assertEqual(repeated.changed_lines, 0)
        self.assertEqual(repeated.contents, transformed.contents)

    def test_grub_rejects_conflicts_duplicates_and_unknown_syntax(self):
        failures = (
            b"linux /casper/vmlinuz nopersistent ---\n",
            b"linux /casper/vmlinuz persistent persistent ---\n",
            b"linux /casper/$kernel quiet ---\n",
            b"LINUX /casper/vmlinuz quiet ---\n",
            b"linux '/casper/vmlinuz' quiet ---\n",
        )
        for payload in failures:
            with self.subTest(payload=payload), self.assertRaises(PersistenceBackendSafetyError):
                transform_grub_config(payload)

    def test_syslinux_mutates_only_casper_label_and_rejects_ambiguous_blocks(self):
        source = (
            b"LABEL live\n"
            b" KERNEL /casper/vmlinuz\n"
            b" APPEND boot=casper quiet ---\n"
            b"LABEL memtest\n"
            b" KERNEL /install/mt86plus\n"
            b" APPEND -\n"
        )
        transformed = transform_syslinux_config(source)
        self.assertEqual((transformed.eligible_lines, transformed.changed_lines), (1, 1))
        self.assertIn(b"APPEND boot=casper quiet persistent ---", transformed.contents)
        self.assertIn(b" APPEND -\n", transformed.contents)
        with self.assertRaises(PersistenceBackendSafetyError):
            transform_syslinux_config(
                b"LABEL live\n KERNEL /casper/vmlinuz\n APPEND quiet\n APPEND debug\n"
            )
        with self.assertRaisesRegex(PersistenceBackendSafetyError, "outside a LABEL"):
            transform_syslinux_config(
                b"KERNEL /casper/vmlinuz\nAPPEND boot=casper quiet ---\n"
            )


class PersistenceBackendPlanTests(unittest.TestCase):
    def test_profile_is_explicit_release_limited_and_immutable(self):
        profile = ubuntu_casper_profile("24.04")
        self.assertEqual(profile.partition_label, "writable")
        self.assertEqual(profile.boot_parameter, "persistent")
        with self.assertRaises(FrozenInstanceError):
            profile.partition_label = "wrong"  # type: ignore[misc]
        for release in ("18.04", "26.04", "rolling"):
            with self.subTest(release=release), self.assertRaises(
                PersistenceBackendSafetyError,
            ):
                ubuntu_casper_profile(release)

    def test_plan_binds_media_device_layout_geometry_tools_and_boot_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            validate_casper_persistence_backend_plan(plan)
            self.assertTrue(plan.executable)
            self.assertEqual(plan.device.identity, harness.device.identity)
            self.assertEqual(plan.layout, harness.initial)
            self.assertEqual(plan.partition_path, "/dev/sdz2")
            self.assertEqual(plan.partition_sector_count, 1024 * MIB // SECTOR_BYTES)
            self.assertEqual(
                {item.relative_path for item in plan.boot_configs},
                {"boot/grub/grub.cfg", "isolinux/txt.cfg"},
            )
            self.assertTrue(plan.evidence)
            self.assertEqual(
                persistence_partition_command(plan),
                [
                    "/usr/bin/pkexec", "/usr/sbin/sfdisk", "--lock=yes",
                    "--no-reread", "--append", "/dev/sdz",
                ],
            )
            self.assertIn(
                f"start={plan.partition_start_sector}".encode(),
                persistence_partition_script(plan),
            )
            self.assertEqual(persistence_format_command(plan)[-3:], ["-L", "writable", "/dev/sdz2"])

    def test_plan_rejects_release_mismatch_full_disk_wrong_label_and_extra_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root, release="22.04")
            harness = BackendHarness(root)
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "release"):
                harness.build(profile=ubuntu_casper_profile("24.04"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            first = replace(
                harness.initial.partitions[0],
                sector_count=harness.device.size // SECTOR_BYTES - 2048 - 34,
            )
            harness.initial = replace(harness.initial, partitions=(first,))
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "will not shrink"):
                harness.build()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            first = replace(harness.initial.partitions[0], label="OTHER")
            harness.initial = replace(harness.initial, partitions=(first,))
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "label"):
                harness.build()

    def test_plan_rejects_symlinked_config_unknown_boot_syntax_and_forged_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            config = root / "boot/grub/grub.cfg"
            config.unlink()
            config.symlink_to(root / "isolinux/txt.cfg")
            with self.assertRaises(PersistenceBackendSafetyError):
                BackendHarness(root).build()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            (root / "boot/grub/grub.cfg").write_text(
                "linux /casper/${kernel} quiet ---\n"
            )
            with self.assertRaises(PersistenceBackendSafetyError):
                BackendHarness(root).build()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            profile = replace(ubuntu_casper_profile("24.04"), partition_label="evil")
            with self.assertRaises(PersistenceBackendSafetyError):
                BackendHarness(root).build(profile=profile)

    def test_default_layout_reader_merges_sfdisk_and_lsblk_without_a_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            device = persistence_device()
            tools = resolve_persistence_tools(find_program)
            calls = []
            table = json.dumps({"partitiontable": {
                "label": "gpt",
                "device": "/dev/sdz",
                "unit": "sectors",
                "sectorsize": 512,
                "partitions": [{
                    "node": "/dev/sdz1",
                    "start": 2048,
                    "size": 5 * 1024 * MIB // SECTOR_BYTES,
                    "type": MICROSOFT_BASIC_DATA_GUID,
                }],
            }})
            blocks = json.dumps({"blockdevices": [{
                "path": "/dev/sdz",
                "type": "disk",
                "children": [{
                    "path": "/dev/sdz1",
                    "type": "part",
                    "fstype": "vfat",
                    "label": "ISOPROPYL",
                    "maj:min": "65:145",
                    "mountpoints": [str(root)],
                    "ro": False,
                }],
            }]})

            def runner(argv, **kwargs):
                calls.append((list(argv), kwargs))
                payload = table if "sfdisk" in argv[1] else blocks
                return subprocess.CompletedProcess(argv, 0, payload, "")

            layout = read_media_layout(device, root, tools, runner=runner)
            self.assertEqual(layout, initial_layout(root))
            self.assertEqual(calls[0][0][:3], ["/usr/bin/pkexec", "/usr/sbin/sfdisk", "--json"])
            self.assertTrue(all(call[1]["shell"] is False for call in calls))


class PersistenceBackendExecutorTests(unittest.TestCase):
    def test_success_creates_exact_partition_formats_and_atomically_updates_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            updates = []
            result = harness.executor().execute(plan, updates.append)
            self.assertEqual(harness.state, "formatted")
            self.assertEqual(result.partition_path, "/dev/sdz2")
            self.assertEqual(
                set(result.boot_configs_updated),
                {"boot/grub/grub.cfg", "isolinux/txt.cfg"},
            )
            self.assertEqual(result.persistence_token, "persistent")
            self.assertIn("persistent ---", (root / "boot/grub/grub.cfg").read_text())
            self.assertIn("persistent ---", (root / "isolinux/txt.cfg").read_text())
            self.assertEqual(updates[-1].stage, "Complete")
            self.assertEqual(updates[-1].fraction, 1.0)
            self.assertEqual(harness.processes[0].argv, persistence_partition_command(plan))
            self.assertEqual(harness.processes[0].inputs[0], persistence_partition_script(plan))
            self.assertEqual(
                next(
                    process.argv for process in harness.processes
                    if any(item.endswith("/mkfs.ext4") for item in process.argv)
                ),
                persistence_format_command(plan),
            )
            self.assertTrue(all(process.kwargs["shell"] is False for process in harness.processes))

    def test_existing_exact_tokens_create_partition_without_rewriting_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root, persistent=True)
            harness = BackendHarness(root)
            plan = harness.build()
            identities = {
                path: os.stat(root / path).st_ino
                for path in ("boot/grub/grub.cfg", "isolinux/txt.cfg")
            }
            result = harness.executor().execute(plan)
            self.assertEqual(result.boot_configs_updated, ())
            self.assertEqual(
                identities,
                {path: os.stat(root / path).st_ino for path in identities},
            )

    def test_changed_source_or_layout_fails_before_any_device_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            (root / "casper/vmlinuz").write_bytes(b"changed")
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "changed"):
                harness.executor().execute(plan)
            self.assertEqual(harness.processes, [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            harness.initial = replace(
                harness.initial,
                partitions=(replace(harness.initial.partitions[0], sector_count=123456),),
            )
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "layout changed"):
                harness.executor().execute(plan)
            self.assertEqual(harness.processes, [])

    def test_cancel_before_start_runs_no_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            executor.cancel()
            with self.assertRaises(PersistenceBackendCancelled):
                executor.execute(plan)
            self.assertEqual(harness.processes, [])

    def test_cancel_terminates_partition_command_and_removes_created_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            original_popen = harness.popen
            first = True

            class CancellingProcess(FakeProcess):
                def __init__(self, argv, **kwargs):
                    super().__init__(argv, **kwargs)
                    self.returncode = None
                    self.waited = False

                def communicate(self, input=None, timeout=None):
                    self.inputs.append(input)
                    if not self.waited:
                        self.waited = True
                        harness.state = "created"
                        executor.cancel()
                        raise subprocess.TimeoutExpired(self.argv, timeout)
                    return b"", b""

            def popen(argv, **kwargs):
                nonlocal first
                if first:
                    first = False
                    process = CancellingProcess(argv, **kwargs)
                    harness.processes.append(process)
                    return process
                return original_popen(argv, **kwargs)

            executor._popen = popen
            with self.assertRaises(PersistenceBackendCancelled):
                executor.execute(plan)
            self.assertEqual(harness.state, "initial")
            self.assertTrue(harness.processes[0].terminated)
            self.assertTrue(any("--delete" in process.argv for process in harness.processes))

    def test_cancel_escalates_to_kill_and_reaps_before_partition_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            original_popen = harness.popen
            first = True
            events = []

            class StubbornProcess(FakeProcess):
                def __init__(self, argv, **kwargs):
                    super().__init__(argv, **kwargs)
                    self.returncode = None
                    self.calls = 0
                    self.timeouts = []

                def communicate(self, input=None, timeout=None):
                    self.inputs.append(input)
                    self.timeouts.append(timeout)
                    self.calls += 1
                    if self.calls == 1:
                        harness.state = "created"
                        executor.cancel()
                        raise subprocess.TimeoutExpired(self.argv, timeout)
                    if not self.killed:
                        raise subprocess.TimeoutExpired(self.argv, timeout)
                    events.append("reaped")
                    return b"", b""

                def terminate(self):
                    self.terminated = True

            def popen(argv, **kwargs):
                nonlocal first
                if first:
                    first = False
                    process = StubbornProcess(argv, **kwargs)
                    harness.processes.append(process)
                    return process
                if "--delete" in argv:
                    events.append("cleanup")
                return original_popen(argv, **kwargs)

            executor._popen = popen
            with self.assertRaises(PersistenceBackendCancelled):
                executor.execute(plan)
            stubborn = harness.processes[0]
            self.assertTrue(stubborn.terminated)
            self.assertTrue(stubborn.killed)
            self.assertEqual(events[:2], ["reaped", "cleanup"])
            self.assertTrue(all(timeout is not None for timeout in stubborn.timeouts))
            self.assertEqual(harness.state, "initial")

    def test_cancel_surfaces_a_child_that_cannot_be_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            original_popen = harness.popen
            first = True

            class UnreapableProcess(FakeProcess):
                def __init__(self, argv, **kwargs):
                    super().__init__(argv, **kwargs)
                    self.returncode = None
                    self.calls = 0

                def communicate(self, input=None, timeout=None):
                    self.inputs.append(input)
                    self.calls += 1
                    if self.calls == 1:
                        harness.state = "created"
                        executor.cancel()
                    raise subprocess.TimeoutExpired(self.argv, timeout)

                def terminate(self):
                    self.terminated = True

                def kill(self):
                    self.killed = True

            def popen(argv, **kwargs):
                nonlocal first
                if first:
                    first = False
                    process = UnreapableProcess(argv, **kwargs)
                    harness.processes.append(process)
                    return process
                return original_popen(argv, **kwargs)

            executor._popen = popen
            with self.assertRaisesRegex(
                PersistenceBackendError, "could not be stopped and reaped",
            ):
                executor.execute(plan)
            unreapable = harness.processes[0]
            self.assertTrue(unreapable.terminated)
            self.assertTrue(unreapable.killed)
            self.assertEqual(unreapable.calls, 3)
            self.assertEqual(harness.state, "initial")

    def test_geometry_change_immediately_before_mkfs_is_not_formatted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()

            def change_geometry(update):
                if update.stage == "Creating ext4 persistence filesystem":
                    harness.wrong_geometry = True

            with self.assertRaisesRegex(PersistenceBackendError, "cleanup was incomplete"):
                harness.executor().execute(plan, change_geometry)
            self.assertFalse(any(
                any(item.endswith("/mkfs.ext4") for item in process.argv)
                for process in harness.processes
            ))

    def test_partition_node_change_immediately_before_mkfs_is_not_formatted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root)
            plan = harness.build()
            changed = False

            class ChangedBlockStat(BlockStat):
                st_rdev = os.makedev(65, 147)

            executor = harness.executor()
            executor._block_stat = lambda _path: ChangedBlockStat() if changed else BlockStat()

            def change_node(update):
                nonlocal changed
                if update.stage == "Creating ext4 persistence filesystem":
                    changed = True

            with self.assertRaisesRegex(PersistenceBackendSafetyError, "node identity changed"):
                executor.execute(plan, change_node)
            self.assertEqual(harness.state, "initial")
            self.assertFalse(any(
                any(item.endswith("/mkfs.ext4") for item in process.argv)
                for process in harness.processes
            ))

    def test_cancel_during_last_config_replace_rolls_back_before_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            (root / "isolinux/txt.cfg").unlink()
            original = (root / "boot/grub/grub.cfg").read_bytes()
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            atomic_replace = executor._atomic_replace
            cancelled = False

            def cancel_once(*args, **kwargs):
                nonlocal cancelled
                if not cancelled:
                    cancelled = True
                    executor.cancel()
                return atomic_replace(*args, **kwargs)

            executor._atomic_replace = cancel_once
            with self.assertRaises(PersistenceBackendCancelled):
                executor.execute(plan)
            self.assertEqual(harness.state, "initial")
            self.assertEqual((root / "boot/grub/grub.cfg").read_bytes(), original)
            self.assertTrue(any("--delete" in process.argv for process in harness.processes))

    def test_device_change_during_last_config_replace_prevents_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            (root / "isolinux/txt.cfg").unlink()
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            atomic_replace = executor._atomic_replace
            changed_once = False
            injected = False

            def lookup(path):
                nonlocal changed_once
                current = harness.current_device(path)
                if changed_once:
                    changed_once = False
                    return replace(current, serial="REPLACEMENT")
                return current

            def change_device_once(*args, **kwargs):
                nonlocal changed_once, injected
                result = atomic_replace(*args, **kwargs)
                if not injected:
                    injected = True
                    changed_once = True
                return result

            executor._device_lookup = lookup
            executor._atomic_replace = change_device_once
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "device changed"):
                executor.execute(plan)
            self.assertEqual(harness.state, "initial")

    def test_layout_change_during_last_config_replace_prevents_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            (root / "isolinux/txt.cfg").unlink()
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            atomic_replace = executor._atomic_replace
            changed_once = False
            injected = False

            def read_layout(device, media_root, tools):
                nonlocal changed_once
                layout = harness.layout_reader(device, media_root, tools)
                if changed_once:
                    changed_once = False
                    second = replace(
                        layout.partitions[1],
                        start_sector=layout.partitions[1].start_sector + 2048,
                    )
                    return replace(layout, partitions=(layout.partitions[0], second))
                return layout

            def change_layout_once(*args, **kwargs):
                nonlocal changed_once, injected
                result = atomic_replace(*args, **kwargs)
                if not injected:
                    injected = True
                    changed_once = True
                return result

            executor._layout_reader = read_layout
            executor._atomic_replace = change_layout_once
            with self.assertRaisesRegex(
                PersistenceBackendSafetyError, "filesystem identity could not be verified",
            ):
                executor.execute(plan)
            self.assertEqual(harness.state, "initial")

    def test_failed_final_config_verification_retains_partition_when_rollback_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            (root / "isolinux/txt.cfg").unlink()
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            atomic_replace = executor._atomic_replace
            corrupted = False

            def corrupt_once(*args, **kwargs):
                nonlocal corrupted
                result = atomic_replace(*args, **kwargs)
                if not corrupted:
                    corrupted = True
                    (root / "boot/grub/grub.cfg").write_bytes(b"external change\n")
                return result

            executor._atomic_replace = corrupt_once
            with self.assertRaisesRegex(
                PersistenceBackendError,
                "partition retained because boot-config rollback was incomplete",
            ):
                executor.execute(plan)
            self.assertEqual(harness.state, "formatted")
            self.assertEqual(
                (root / "boot/grub/grub.cfg").read_bytes(), b"external change\n",
            )
            self.assertFalse(any("--delete" in process.argv for process in harness.processes))

    def test_mkfs_failure_removes_only_the_exact_new_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root, fail_command="mkfs.ext4")
            plan = harness.build()
            with self.assertRaisesRegex(PersistenceBackendError, "intentional failure"):
                harness.executor().execute(plan)
            self.assertEqual(harness.state, "initial")
            self.assertTrue(any("--delete" in process.argv for process in harness.processes))
            self.assertNotIn("persistent", (root / "boot/grub/grub.cfg").read_text())

    def test_cancel_between_config_updates_rolls_back_first_and_deletes_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            original_grub = (root / "boot/grub/grub.cfg").read_bytes()
            original_syslinux = (root / "isolinux/txt.cfg").read_bytes()
            harness = BackendHarness(root)
            plan = harness.build()
            executor = harness.executor()
            config_updates = 0

            def cancel_on_second(update):
                nonlocal config_updates
                if update.stage.startswith("Updating"):
                    config_updates += 1
                    if config_updates == 2:
                        executor.cancel()

            with self.assertRaises(PersistenceBackendCancelled):
                executor.execute(plan, cancel_on_second)
            self.assertEqual(harness.state, "initial")
            self.assertEqual((root / "boot/grub/grub.cfg").read_bytes(), original_grub)
            self.assertEqual((root / "isolinux/txt.cfg").read_bytes(), original_syslinux)
            self.assertTrue(any("--delete" in process.argv for process in harness.processes))

    def test_wrong_created_geometry_is_never_formatted_or_guessed_for_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root, wrong_geometry=True)
            plan = harness.build()
            with self.assertRaisesRegex(PersistenceBackendError, "cleanup was incomplete"):
                harness.executor().execute(plan)
            self.assertFalse(any(
                any(item.endswith("/mkfs.ext4") for item in process.argv)
                for process in harness.processes
            ))
            self.assertFalse(any("--delete" in process.argv for process in harness.processes))

    def test_failure_after_atomic_replace_rolls_config_back_before_partition_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            original = (root / "boot/grub/grub.cfg").read_bytes()
            harness = BackendHarness(root)
            plan = harness.build()
            # First fsync persists the temporary replacement; the second is
            # the containing-directory durability barrier after os.replace.
            effects = [None, OSError("directory fsync failed"), None, None]
            with patch("isopropyl.persistence.os.fsync", side_effect=effects):
                with self.assertRaises(PersistenceBackendError):
                    harness.executor().execute(plan)
            self.assertEqual((root / "boot/grub/grub.cfg").read_bytes(), original)
            self.assertEqual(harness.state, "initial")
            self.assertTrue(any("--delete" in process.argv for process in harness.processes))

    def test_executor_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_media(root)
            harness = BackendHarness(root, fail_command="mkfs.ext4")
            plan = harness.build()
            executor = harness.executor()
            with self.assertRaises(PersistenceBackendError):
                executor.execute(plan)
            with self.assertRaisesRegex(PersistenceBackendSafetyError, "only be used once"):
                executor.execute(plan)


if __name__ == "__main__":
    unittest.main()
