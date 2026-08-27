from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.constructed import (
    COPY_BLOCK_BYTES,
    FAT32_MAX_FILE_BYTES,
    ConstructedMediaCancelled,
    ConstructedMediaError,
    ConstructedMediaExecutor,
    ConstructedMediaSafetyError,
    ConstructedMediaUnavailable,
    ConstructedTools,
    StagedFile,
    build_constructed_media_plan,
    resolve_constructed_tools,
    scan_staging_tree,
    validate_constructed_media_plan,
)
from isopropyl.devices import Device
from isopropyl.formatting import (
    Filesystem,
    FormatCancelled,
    FormattingError,
    PartitionTable,
)


def removable_device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": 2_000_000_000,
        "model": "Flash",
        "vendor": "Acme",
        "transport": "usb",
        "serial": "MEDIA-123",
        "wwn": "",
        "major_minor": "65:144",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": (),
        "partitions": (),
    }
    values.update(changes)
    return Device(**values)  # type: ignore[arg-type]


PROGRAMS = {
    "pkexec": "/usr/bin/pkexec",
    "udisksctl": "/usr/bin/udisksctl",
    "sfdisk": "/usr/sbin/sfdisk",
    "partprobe": "/usr/sbin/partprobe",
    "udevadm": "/usr/bin/udevadm",
    "lsblk": "/usr/bin/lsblk",
    "mkfs.vfat": "/usr/sbin/mkfs.vfat",
    "mkfs.ntfs": "/usr/sbin/mkfs.ntfs",
    "findmnt": "/usr/bin/findmnt",
}


def find_program(name: str) -> str | None:
    return PROGRAMS.get(name)


def make_staging(parent: Path, *, payload: bytes = b"payload") -> Path:
    staging = parent / "staging"
    (staging / "EFI" / "BOOT").mkdir(parents=True)
    (staging / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(b"uefi-loader")
    (staging / "images").mkdir()
    (staging / "images" / "payload.bin").write_bytes(payload)
    (staging / "README.txt").write_text("constructed media\n")
    return staging


def build_plan(staging: Path, **kwargs):
    return build_constructed_media_plan(
        staging,
        kwargs.pop("device", removable_device()),
        kwargs.pop("partition_table", PartitionTable.GPT),
        finder=kwargs.pop("finder", find_program),
        source_on_device=kwargs.pop("source_on_device", lambda _path, _device: False),
        **kwargs,
    )


def completed(code: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class FakeFormatExecutor:
    def __init__(self, *, result: str = "/dev/sdz1", error: BaseException | None = None, hook=None):
        self.result = result
        self.error = error
        self.hook = hook
        self.calls = []
        self.cancelled = False

    def execute(self, device, plan, stage):
        self.calls.append((device, plan))
        stage("Creating filesystem")
        if self.hook:
            self.hook()
        if self.error:
            raise self.error
        return self.result

    def cancel(self):
        self.cancelled = True


class WholeBlockStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(65, 144)


class PartitionBlockStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(65, 145)


def device_and_real_stat(path: str):
    if os.fspath(path) == "/dev/sdz":
        return WholeBlockStat()
    if os.fspath(path) == "/dev/sdz1":
        return PartitionBlockStat()
    return os.stat(path)


class PlanTests(unittest.TestCase):
    def test_plan_binds_tree_target_fat32_capacity_and_fallback_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            plan = build_plan(staging, partition_table=PartitionTable.MBR)
        self.assertTrue(plan.uefi_only)
        self.assertEqual(plan.device.identity, removable_device().identity)
        self.assertEqual(plan.format_plan.filesystem, Filesystem.FAT32)
        self.assertEqual(plan.format_plan.partition_table, PartitionTable.MBR)
        self.assertEqual(plan.fallback_loaders, ("EFI/BOOT/BOOTX64.EFI",))
        self.assertEqual(plan.total_bytes, sum(item.size for item in plan.files))
        self.assertGreater(plan.required_capacity, plan.total_bytes)
        self.assertTrue(plan.directories)
        self.assertEqual(plan.directories[0].parts, ())
        self.assertTrue(all(item.inode > 0 and item.device > 0 for item in plan.files))
        with self.assertRaises(FrozenInstanceError):
            plan.total_bytes = 1  # type: ignore[misc]

    def test_accepts_multiple_architecture_fallback_loaders_case_insensitively(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            (staging / "EFI" / "BOOT" / "bootaa64.efi").write_bytes(b"arm64")
            plan = build_plan(staging)
        self.assertEqual(plan.fallback_loaders, (
            "EFI/BOOT/bootaa64.efi", "EFI/BOOT/BOOTX64.EFI",
        ))

    def test_requires_nonempty_uefi_fallback_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            (staging / "EFI" / "BOOT" / "BOOTX64.EFI").unlink()
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "fallback loader"):
                build_plan(staging)
            (staging / "EFI" / "BOOT" / "BOOTX64.EFI").touch()
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "fallback loader"):
                build_plan(staging)

    def test_rejects_symlinks_hardlinks_fifo_and_case_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for kind in ("symlink", "hardlink", "fifo", "collision"):
                staging = make_staging(base / kind)
                if kind == "symlink":
                    (staging / "link").symlink_to("README.txt")
                elif kind == "hardlink":
                    os.link(staging / "README.txt", staging / "linked.txt")
                elif kind == "fifo":
                    os.mkfifo(staging / "pipe")
                else:
                    (staging / "readme.TXT").write_text("collision")
                with self.subTest(kind=kind):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        build_plan(staging)

    def test_rejects_fat32_incompatible_names(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("bad:name", "trailing.", "CON"):
                staging = make_staging(base / str(len(name)))
                (staging / name).write_text("bad")
                with self.subTest(name=name):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        build_plan(staging)

    def test_rejects_non_enum_table_target_source_overlap_and_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            with self.assertRaises(ConstructedMediaSafetyError):
                build_plan(staging, partition_table="gpt")  # type: ignore[arg-type]
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "stored on the target"):
                build_plan(staging, source_on_device=lambda _path, _device: True)
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "requires"):
                build_plan(staging, device=removable_device(size=20_000_000))

    def test_rejects_file_larger_than_fat32_limit_without_allocating_it(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            huge = staging / "huge.bin"
            with huge.open("wb") as stream:
                stream.truncate(FAT32_MAX_FILE_BYTES + 1)
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "single-file limit"):
                build_plan(staging)

    def test_ntfs_plan_accepts_large_files_and_binds_ntfs_formatter(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            huge = staging / "install.wim"
            with huge.open("wb") as stream:
                stream.truncate(FAT32_MAX_FILE_BYTES + 1)
            plan = build_plan(
                staging,
                filesystem=Filesystem.NTFS,
                device=removable_device(size=8_000_000_000),
            )
            self.assertEqual(plan.filesystem, Filesystem.NTFS)
            self.assertEqual(plan.format_plan.filesystem, Filesystem.NTFS)
            self.assertEqual(
                next(item for item in plan.files if item.path == "install.wim").size,
                FAT32_MAX_FILE_BYTES + 1,
            )

    def test_constructed_plan_rejects_unsupported_filesystem(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "FAT32 or NTFS"):
                build_plan(staging, filesystem=Filesystem.EXFAT)

    def test_tool_preflight_uses_fixed_system_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            with self.assertRaises(ConstructedMediaUnavailable):
                build_plan(
                    staging,
                    finder=lambda name: None if name == "findmnt" else PROGRAMS.get(name),
                )
            with self.assertRaises(ConstructedMediaUnavailable):
                build_plan(
                    staging,
                    finder=lambda name: "/tmp/findmnt" if name == "findmnt" else PROGRAMS.get(name),
                )

    @patch("isopropyl.constructed.shutil.which")
    def test_default_constructed_tool_search_ignores_user_path(self, which):
        which.side_effect = lambda name, **_kwargs: PROGRAMS[name]
        self.assertEqual(
            resolve_constructed_tools(),
            ConstructedTools(
                "/usr/bin/udisksctl", "/usr/bin/findmnt", "/usr/bin/lsblk",
            ),
        )
        self.assertTrue(all(
            call.kwargs["path"] == "/usr/sbin:/usr/bin:/sbin:/bin"
            for call in which.call_args_list
        ))

    def test_forged_plans_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            plan = build_plan(staging)
            file = plan.files[0]
            forged_file = replace(file, parts=("..", "escape"))
            forged = (
                replace(plan, files=(forged_file,) + plan.files[1:]),
                replace(plan, total_bytes=1),
                replace(plan, fallback_loaders=("EFI/BOOT/NOTEFI",)),
                replace(plan, format_plan=replace(plan.format_plan, filesystem=Filesystem.NTFS)),
                replace(plan, tools=replace(plan.tools, findmnt="/tmp/findmnt")),
            )
            for item in forged:
                with self.subTest(plan=item):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        validate_constructed_media_plan(item)

    def test_scan_returns_canonical_depth_and_case_order(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = make_staging(Path(directory))
            _root, directories, files = scan_staging_tree(staging)
        self.assertEqual(directories[0].parts, ())
        self.assertEqual(
            [len(item.parts) for item in directories],
            sorted(len(item.parts) for item in directories),
        )
        self.assertEqual(
            [item.path.casefold() for item in files],
            sorted(item.path.casefold() for item in files),
        )


class ExecutorTests(unittest.TestCase):
    def make_executor(
        self,
        mountpoint: Path,
        formatter: FakeFormatExecutor,
        calls: list[tuple],
        *,
        device_lister=None,
        stat_func=device_and_real_stat,
        command_hook=None,
        access_func=lambda _path, _mode: True,
    ) -> ConstructedMediaExecutor:
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if command_hook is not None:
                override = command_hook(argv, kwargs)
                if override is not None:
                    return override
            if argv[0] == "/usr/bin/lsblk":
                return completed(stdout=json.dumps({"blockdevices": [{
                    "path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz",
                    "fstype": "vfat",
                }]}))
            if argv[0] == "/usr/bin/findmnt":
                return completed(stdout=json.dumps({"filesystems": [{
                    "source": "/dev/sdz1", "target": str(mountpoint),
                    "fstype": "vfat", "options": "rw,nosuid,nodev",
                }]}))
            return completed()

        return ConstructedMediaExecutor(
            format_executor=formatter,  # type: ignore[arg-type]
            run_command=run,
            device_lister=device_lister or (lambda: [removable_device()]),
            stat_func=stat_func,
            access_func=access_func,
        )

    def test_complete_flow_formats_mounts_copies_verifies_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            formatter = FakeFormatExecutor()
            calls: list[tuple] = []
            updates = []
            result = self.make_executor(
                mountpoint, formatter, calls,
            ).execute(plan, updates.append)

            for source in staging.rglob("*"):
                if source.is_file():
                    self.assertEqual(
                        (mountpoint / source.relative_to(staging)).read_bytes(),
                        source.read_bytes(),
                    )
            self.assertEqual(result.partition, "/dev/sdz1")
            self.assertEqual(result.files_copied, len(plan.files))
            self.assertEqual(result.bytes_copied, plan.total_bytes)
            self.assertTrue(result.unmounted)
            self.assertTrue(result.powered_off)
            self.assertEqual(formatter.calls[0][1].filesystem, Filesystem.FAT32)
            self.assertTrue(all(call[1]["shell"] is False for call in calls))
            self.assertTrue(any(call[0][1] == "mount" for call in calls))
            self.assertTrue(any(call[0][1] == "unmount" for call in calls))
            self.assertTrue(any(call[0][1] == "power-off" for call in calls))
            byte_updates = [item.bytes_done for item in updates if item.stage == "Copying"]
            self.assertEqual(byte_updates, sorted(byte_updates))
            self.assertEqual(updates[-1].stage, "Complete")
            self.assertEqual(updates[-1].fraction, 1.0)

    def test_populates_preformatted_ntfs_without_reformat_or_poweroff(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging, filesystem=Filesystem.NTFS)
            formatter = FakeFormatExecutor()
            calls: list[tuple] = []

            def hook(argv, _kwargs):
                if argv[0] == "/usr/bin/lsblk":
                    return completed(stdout=json.dumps({"blockdevices": [{
                        "path": "/dev/sdz1", "type": "part", "pkname": "/dev/sdz",
                        "fstype": "ntfs",
                    }]}))
                if argv[0] == "/usr/bin/findmnt":
                    return completed(stdout=json.dumps({"filesystems": [{
                        "source": "/dev/sdz1", "target": str(mountpoint),
                        "fstype": "ntfs3", "options": "rw,nosuid,nodev",
                    }]}))
                return None

            executor = self.make_executor(
                mountpoint, formatter, calls, command_hook=hook,
            )
            result = executor.populate_existing_partition(plan, "/dev/sdz1")
            self.assertEqual(formatter.calls, [])
            self.assertTrue(result.unmounted)
            self.assertFalse(result.powered_off)
            self.assertFalse(any(call[0][1] == "power-off" for call in calls))
            self.assertEqual(
                (mountpoint / "images" / "payload.bin").read_bytes(), b"payload",
            )
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "cannot be reused"):
                executor.populate_existing_partition(plan, "/dev/sdz1")

    def test_staging_change_before_execute_prevents_format(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            (staging / "README.txt").write_text("changed same-ish")
            formatter = FakeFormatExecutor()
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "changed"):
                self.make_executor(mountpoint, formatter, []).execute(plan)
            self.assertEqual(formatter.calls, [])

    def test_device_identity_or_block_number_change_prevents_format(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            wrong_block = type("Wrong", (), {
                "st_mode": stat.S_IFBLK, "st_rdev": os.makedev(65, 1),
            })()
            cases = (
                (lambda: [removable_device(serial="OTHER")], device_and_real_stat),
                (
                    lambda: [removable_device()],
                    lambda path: wrong_block if path == "/dev/sdz" else device_and_real_stat(path),
                ),
            )
            for lister, stat_func in cases:
                formatter = FakeFormatExecutor()
                with self.subTest(lister=lister):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        self.make_executor(
                            mountpoint, formatter, [], device_lister=lister,
                            stat_func=stat_func,
                        ).execute(plan)
                    self.assertEqual(formatter.calls, [])

    def test_formatter_failure_and_cancellation_are_mapped(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            for error, expected in (
                (FormattingError("mkfs failed"), ConstructedMediaError),
                (FormatCancelled("cancelled"), ConstructedMediaCancelled),
            ):
                with self.subTest(error=error):
                    executor = self.make_executor(
                        mountpoint, FakeFormatExecutor(error=error), [],
                    )
                    with self.assertRaises(expected):
                        executor.execute(plan)

    def test_staging_change_during_format_stops_before_mount_and_powers_off(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            formatter = FakeFormatExecutor(
                hook=lambda: (staging / "new.txt").write_text("late"),
            )
            calls: list[tuple] = []
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "changed"):
                self.make_executor(mountpoint, formatter, calls).execute(plan)
            self.assertFalse(any(call[0][1] == "mount" for call in calls))
            self.assertTrue(any(call[0][1] == "power-off" for call in calls))

    def test_rejects_formatter_partition_outside_target_or_non_block(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            for result, stat_func in (
                ("/dev/sdy1", device_and_real_stat),
                (
                    "/dev/sdz1",
                    lambda path: (
                        type("Regular", (), {"st_mode": stat.S_IFREG, "st_rdev": 0})()
                        if path == "/dev/sdz1" else device_and_real_stat(path)
                    ),
                ),
            ):
                calls: list[tuple] = []
                with self.subTest(result=result):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        self.make_executor(
                            mountpoint, FakeFormatExecutor(result=result), calls,
                            stat_func=stat_func,
                        ).execute(plan)
                    self.assertFalse(any(call[0][1] == "mount" for call in calls))

    def test_partition_and_mount_metadata_must_match_exact_fat32_source(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            plan = build_plan(staging)
            for kind in ("partition_parent", "mount_source", "mount_fstype", "mount_ro"):
                mountpoint = base / f"mount-{kind}"
                mountpoint.mkdir()

                def hook(argv, _kwargs, kind=kind):
                    if argv[0] == "/usr/bin/lsblk" and kind == "partition_parent":
                        return completed(stdout=json.dumps({"blockdevices": [{
                            "path": "/dev/sdz1", "type": "part",
                            "pkname": "/dev/sdy", "fstype": "vfat",
                        }]}))
                    if argv[0] == "/usr/bin/findmnt":
                        return completed(stdout=json.dumps({"filesystems": [{
                            "source": "/dev/sdy1" if kind == "mount_source" else "/dev/sdz1",
                            "target": str(mountpoint),
                            "fstype": "ntfs" if kind == "mount_fstype" else "vfat",
                            "options": "ro" if kind == "mount_ro" else "rw",
                        }]}))
                    return None

                calls: list[tuple] = []
                with self.subTest(kind=kind):
                    with self.assertRaises(ConstructedMediaSafetyError):
                        self.make_executor(
                            mountpoint, FakeFormatExecutor(), calls, command_hook=hook,
                        ).execute(plan)
                    if kind != "partition_parent":
                        self.assertTrue(any(call[0][1] == "unmount" for call in calls))

    def test_mount_directory_must_be_real_writable_and_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            plan = build_plan(staging)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            (mountpoint / "unexpected").write_text("not empty")
            calls: list[tuple] = []
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "non-empty"):
                self.make_executor(mountpoint, FakeFormatExecutor(), calls).execute(plan)
            self.assertTrue(any(call[0][1] == "unmount" for call in calls))

    def test_source_symlink_race_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base, payload=b"P" * 128)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            outside = base / "outside"
            outside.write_bytes(b"SECRET")
            plan = build_plan(staging)
            changed = False

            def progress(update):
                nonlocal changed
                if not changed and update.stage == "Copying" and update.relative_path:
                    changed = True
                    payload = staging / "images" / "payload.bin"
                    payload.unlink()
                    payload.symlink_to(outside)

            calls: list[tuple] = []
            with self.assertRaises(ConstructedMediaError):
                self.make_executor(
                    mountpoint, FakeFormatExecutor(), calls,
                ).execute(plan, progress)
            copied = mountpoint / "images" / "payload.bin"
            self.assertFalse(copied.exists())
            self.assertTrue(any(call[0][1] == "unmount" for call in calls))

    def test_readback_hash_detects_destination_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base, payload=b"P" * 4096)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            corrupted = False

            def progress(update):
                nonlocal corrupted
                if update.relative_path == "images/payload.bin" and not corrupted:
                    corrupted = True
                    (mountpoint / "images" / "payload.bin").write_bytes(b"X" * 4096)

            calls: list[tuple] = []
            with self.assertRaisesRegex(ConstructedMediaError, "verification failed"):
                self.make_executor(
                    mountpoint, FakeFormatExecutor(), calls,
                ).execute(plan, progress)

    def test_cancel_during_copy_stops_and_runs_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base, payload=b"P" * (COPY_BLOCK_BYTES + 1))
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            formatter = FakeFormatExecutor()
            calls: list[tuple] = []
            executor = self.make_executor(mountpoint, formatter, calls)

            def progress(update):
                if update.relative_path == "images/payload.bin":
                    executor.cancel()

            with self.assertRaises(ConstructedMediaCancelled):
                executor.execute(plan, progress)
            self.assertTrue(formatter.cancelled)
            self.assertTrue(any(call[0][1] == "unmount" for call in calls))
            self.assertTrue(any(call[0][1] == "power-off" for call in calls))

    def test_best_effort_cleanup_is_reported_without_masking_success(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)

            def hook(argv, _kwargs):
                if argv[0] == "/usr/bin/udisksctl" and argv[1] in {"unmount", "power-off"}:
                    return completed(1, stderr="busy")
                return None

            result = self.make_executor(
                mountpoint, FakeFormatExecutor(), [], command_hook=hook,
            ).execute(plan)
            self.assertFalse(result.unmounted)
            self.assertFalse(result.powered_off)

    def test_cancel_before_execute_touches_nothing_and_executor_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = make_staging(base)
            mountpoint = base / "mount"
            mountpoint.mkdir()
            plan = build_plan(staging)
            formatter = FakeFormatExecutor()
            calls: list[tuple] = []
            executor = self.make_executor(mountpoint, formatter, calls)
            executor.cancel()
            with self.assertRaises(ConstructedMediaCancelled):
                executor.execute(plan)
            self.assertEqual(formatter.calls, [])
            self.assertEqual(calls, [])
            with self.assertRaisesRegex(ConstructedMediaSafetyError, "cannot be reused"):
                executor.execute(plan)


if __name__ == "__main__":
    unittest.main()
