from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from isopropyl.bootloaders import BootloaderCatalog, BootloaderResource
from isopropyl.constructed import (
    ConstructedMediaError,
    ConstructedMediaResult,
)
from isopropyl.devices import Device
from isopropyl.formatting import FormattingError, PartitionTable
from isopropyl.uefi_ntfs import (
    ArchitecturePayload,
    BoundArtifact,
    PayloadTrust,
    UefiNtfsCancelled,
    UefiNtfsError,
    UefiNtfsExecutor,
    UefiNtfsSafetyError,
    UefiNtfsUnavailable,
    bind_uefi_ntfs_artifact,
    build_uefi_ntfs_media_plan,
    prepare_uefi_ntfs_artifact,
    probe_uefi_ntfs_logical_sector_size,
    validate_uefi_ntfs_media_plan,
)


ARTIFACT_DATA = b"tiny pinned UEFI NTFS fixture"
ARTIFACT_SHA = hashlib.sha256(ARTIFACT_DATA).hexdigest()


def device(**changes) -> Device:
    values = dict(
        path="/dev/sdz", size=256 * 1024 * 1024,
        model="Flash", vendor="Acme", transport="usb",
        serial="SERIAL", wwn="", major_minor="65:144",
        removable=True, hotplug=True, read_only=False,
        mountpoints=(), partitions=(),
    )
    values.update(changes)
    return Device(**values)


def staging_tree(parent: Path, architectures=("x64",)) -> Path:
    root = parent / "staging"
    (root / "EFI" / "BOOT").mkdir(parents=True)
    names = {
        "x64": "BOOTX64.EFI", "x86": "BOOTIA32.EFI",
        "ARM64": "BOOTAA64.EFI", "ARM": "BOOTARM.EFI",
        "RISC-V64": "BOOTRISCV64.EFI", "LoongArch64": "BOOTLOONGARCH64.EFI",
    }
    for architecture in architectures:
        (root / "EFI" / "BOOT" / names[architecture]).write_bytes(
            f"{architecture} loader".encode(),
        )
    (root / "sources").mkdir()
    (root / "sources" / "setup.bin").write_bytes(b"setup")
    return root


def finder(name: str) -> str:
    directory = "/usr/sbin" if name in {
        "sfdisk", "partprobe", "mkfs.ntfs",
    } else "/usr/bin"
    return f"{directory}/{name}"


def resource() -> BootloaderResource:
    return BootloaderResource(
        "uefi-ntfs", "2.8-rufus-2368e49a", "uefi-ntfs.img",
        "https://raw.githubusercontent.com/example/uefi-ntfs.img",
        ARTIFACT_SHA, len(ARTIFACT_DATA), ("raw.githubusercontent.com",),
    )


@contextmanager
def fixture_constants():
    with patch.multiple(
        "isopropyl.uefi_ntfs",
        UEFI_NTFS_SIZE=len(ARTIFACT_DATA),
        UEFI_NTFS_SHA256=ARTIFACT_SHA,
    ):
        yield


def artifact() -> BoundArtifact:
    return BoundArtifact(
        "uefi-ntfs", "2.8-rufus-2368e49a", "uefi-ntfs.img",
        ARTIFACT_SHA, ARTIFACT_DATA, 1, 2,
    )


def build_plan(root: Path, architectures=("x64",), **kwargs):
    return build_uefi_ntfs_media_plan(
        root, kwargs.pop("device", device()),
        kwargs.pop("partition_table", PartitionTable.GPT),
        architectures, kwargs.pop("artifact", artifact()),
        logical_sector_size=kwargs.pop("logical_sector_size", 512),
        finder=kwargs.pop("finder", finder),
        source_on_device=kwargs.pop("source_on_device", lambda _path, _device: False),
        **kwargs,
    )


def partition_metadata(plan, *, wrong_size=False) -> str:
    table = plan.layout.partition_table
    gpt = table is PartitionTable.GPT
    entries = []
    for index, spec in enumerate(plan.layout.partitions, start=1):
        if gpt:
            item = {
                "node": f"/dev/sdz{index}", "start": spec.start_sector,
                "size": spec.sector_count,
                "type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                "name": "ISOpropyl data" if index == 1 else "UEFI:NTFS",
            }
            if index == 2:
                item["attrs"] = "GUID:63"
        else:
            item = {
                "node": f"/dev/sdz{index}", "start": spec.start_sector,
                "size": spec.sector_count, "type": "7" if index == 1 else "ef",
            }
            if index == 1 and spec.bootable:
                item["bootable"] = True
        entries.append(item)
    if wrong_size:
        entries[1]["size"] = 1
    return json.dumps({"partitiontable": {
        "label": "gpt" if gpt else "dos", "device": "/dev/sdz",
        "unit": "sectors", "sectorsize": 512, "partitions": entries,
    }})


class ArtifactTests(unittest.TestCase):
    def test_binds_regular_singly_linked_exact_artifact(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            path = Path(directory) / "uefi-ntfs.img"
            path.write_bytes(ARTIFACT_DATA)
            bound = bind_uefi_ntfs_artifact(path, resource())
        self.assertEqual(bound.data, ARTIFACT_DATA)
        self.assertEqual(bound.sha256, ARTIFACT_SHA)
        self.assertGreater(bound.source_inode, 0)

    def test_rejects_symlink_hardlink_size_and_hash(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            base = Path(directory)
            good = base / "good.img"
            good.write_bytes(ARTIFACT_DATA)
            link = base / "link.img"
            link.symlink_to(good)
            with self.assertRaises(UefiNtfsSafetyError):
                bind_uefi_ntfs_artifact(link, resource())
            hard = base / "hard.img"
            os.link(good, hard)
            with self.assertRaisesRegex(UefiNtfsSafetyError, "singly linked"):
                bind_uefi_ntfs_artifact(good, resource())
            hard.unlink()
            good.write_bytes(ARTIFACT_DATA + b"extra")
            with self.assertRaisesRegex(UefiNtfsSafetyError, "1 MiB"):
                bind_uefi_ntfs_artifact(good, resource())
            good.write_bytes(b"X" * len(ARTIFACT_DATA))
            with self.assertRaisesRegex(UefiNtfsSafetyError, "SHA-256"):
                bind_uefi_ntfs_artifact(good, resource())

    def test_rejects_wrong_catalog_key_or_metadata(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            path = Path(directory) / "image"
            path.write_bytes(ARTIFACT_DATA)
            with self.assertRaisesRegex(UefiNtfsSafetyError, "supported UEFI:NTFS key"):
                bind_uefi_ntfs_artifact(
                    path, replace(resource(), version="other"),
                )
            with self.assertRaisesRegex(UefiNtfsSafetyError, "metadata"):
                bind_uefi_ntfs_artifact(
                    path, replace(resource(), sha256="0" * 64),
                )

    def test_preparation_requires_the_exact_pinned_catalog_origin(self):
        official = replace(
            resource(),
            url=(
                "https://raw.githubusercontent.com/pbatard/rufus/"
                "2368e49a82e854d3e702f824648cc723953dbb53/"
                "res/uefi/uefi-ntfs.img"
            ),
        )
        forged = (
            replace(
                official,
                url="https://raw.githubusercontent.com/pbatard/rufus/main/res/uefi/uefi-ntfs.img",
            ),
            replace(
                official,
                allowed_hosts=("github.com", "raw.githubusercontent.com"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            path = Path(directory) / "uefi-ntfs.img"
            path.write_bytes(ARTIFACT_DATA)
            with patch("isopropyl.uefi_ntfs.fetch_resource", return_value=path) as fetch:
                with patch(
                    "isopropyl.uefi_ntfs.load_catalog",
                    return_value=BootloaderCatalog((official,)),
                ):
                    self.assertEqual(
                        prepare_uefi_ntfs_artifact(cache_dir=Path(directory)).data,
                        ARTIFACT_DATA,
                    )
                self.assertEqual(fetch.call_count, 1)
                for item in forged:
                    with self.subTest(item=item):
                        fetch.reset_mock()
                        with patch(
                            "isopropyl.uefi_ntfs.load_catalog",
                            return_value=BootloaderCatalog((item,)),
                        ):
                            with self.assertRaisesRegex(
                                UefiNtfsSafetyError, "catalog entry",
                            ):
                                prepare_uefi_ntfs_artifact(cache_dir=Path(directory))
                        fetch.assert_not_called()


class SectorProbeTests(unittest.TestCase):
    @staticmethod
    def payload(*, logical_sector=512, serial="SERIAL") -> str:
        return json.dumps({"blockdevices": [{
            "path": "/dev/sdz", "size": 256 * 1024 * 1024,
            "type": "disk", "rm": True, "hotplug": True, "tran": "usb",
            "model": "Flash", "vendor": "Acme", "serial": serial,
            "wwn": "", "maj:min": "65:144", "mountpoints": [], "ro": False,
            "log-sec": logical_sector,
        }]})

    def test_probe_binds_identity_and_requires_512_before_planning(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, self.payload(), "")

        self.assertEqual(
            probe_uefi_ntfs_logical_sector_size(
                device(), finder=finder, runner=runner,
            ),
            512,
        )
        self.assertIn("--nodeps", calls[0][0])
        self.assertFalse(calls[0][1]["shell"])
        with self.assertRaises(UefiNtfsUnavailable):
            probe_uefi_ntfs_logical_sector_size(
                device(), finder=finder,
                runner=lambda argv, **_kwargs: subprocess.CompletedProcess(
                    argv, 0, self.payload(logical_sector=4096), "",
                ),
            )
        with self.assertRaisesRegex(UefiNtfsSafetyError, "changed"):
            probe_uefi_ntfs_logical_sector_size(
                device(), finder=finder,
                runner=lambda argv, **_kwargs: subprocess.CompletedProcess(
                    argv, 0, self.payload(serial="OTHER"), "",
                ),
            )

    def test_plan_refuses_an_unobserved_sector_size(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            with self.assertRaisesRegex(UefiNtfsSafetyError, "freshly observed"):
                build_uefi_ntfs_media_plan(
                    staging_tree(Path(directory)), device(), PartitionTable.GPT,
                    ("x64",), artifact(), finder=finder,
                    source_on_device=lambda *_args: False,
                )


class PlanTests(unittest.TestCase):
    def test_builds_exact_x64_gpt_ntfs_plan(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            validate_uefi_ntfs_media_plan(plan)
        self.assertEqual(plan.layout.logical_sector_size, 512)
        self.assertEqual(plan.content.filesystem.value, "ntfs")
        self.assertEqual(len(plan.layout.partitions), 2)
        self.assertEqual(plan.payloads[0].suffix, "x64")
        self.assertEqual(
            plan.payloads[0].trust, PayloadTrust.MICROSOFT_UEFI_CA_2011,
        )
        self.assertGreater(plan.data_capacity, plan.content.required_capacity)
        self.assertEqual(plan.tools.flock, "/usr/bin/flock")

    def test_missing_cooperative_lock_fails_during_plan_preflight(self):
        missing_flock = lambda name: None if name == "flock" else finder(name)
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            with self.assertRaisesRegex(UefiNtfsUnavailable, "flock"):
                build_plan(
                    staging_tree(Path(directory)), finder=missing_flock,
                )

    def test_supports_x86_arm64_and_explicit_unsigned_architectures(self):
        architectures = ("x86", "ARM64", "ARM", "RISC-V64")
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            root = staging_tree(Path(directory), architectures)
            with self.assertRaisesRegex(UefiNtfsSafetyError, "unsigned-payload"):
                build_plan(root, architectures)
            plan = build_plan(root, architectures, allow_unsigned_payloads=True)
        self.assertEqual(
            [item.suffix for item in plan.payloads],
            ["ia32", "aa64", "arm", "riscv64"],
        )
        self.assertEqual(plan.payloads[-1].trust, PayloadTrust.UNSIGNED)

    def test_blocks_loongarch_unknown_and_missing_fallback(self):
        for architecture, message in (
            ("LoongArch64", "no complete"),
            ("MIPS64", "does not support"),
        ):
            with self.subTest(architecture=architecture):
                with tempfile.TemporaryDirectory() as directory, fixture_constants():
                    root = staging_tree(
                        Path(directory),
                        (architecture,) if architecture != "MIPS64" else ("x64",),
                    )
                    with self.assertRaisesRegex(UefiNtfsSafetyError, message):
                        build_plan(root, (architecture,))
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            root = staging_tree(Path(directory), ("x64",))
            with self.assertRaisesRegex(UefiNtfsSafetyError, "lacks"):
                build_plan(root, ("x86",))

    def test_rejects_4kn_source_overlap_and_insufficient_data_capacity(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            root = staging_tree(Path(directory))
            with self.assertRaisesRegex(UefiNtfsSafetyError, "512-byte"):
                build_plan(root, logical_sector_size=4096)
            with self.assertRaisesRegex(UefiNtfsSafetyError, "stored on the target"):
                build_plan(root, source_on_device=lambda _path, _device: True)
            with (root / "huge.bin").open("wb") as stream:
                stream.truncate(220 * 1024 * 1024)
            with self.assertRaisesRegex(UefiNtfsSafetyError, "requires|does not fit"):
                build_plan(root)

    def test_forged_plan_components_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            cases = (
                replace(plan, data_capacity=1),
                replace(plan, artifact=replace(plan.artifact, data=b"bad")),
                replace(plan, payloads=()),
                replace(
                    plan,
                    payloads=(replace(plan.payloads[0], suffix="aa64"),),
                ),
                replace(plan, architectures=("ARM64",)),
                replace(plan, tools=replace(plan.tools, dd="/tmp/dd")),
                replace(plan, tools=replace(plan.tools, flock="/tmp/flock")),
            )
            for forged in cases:
                with self.subTest(forged=forged):
                    with self.assertRaises(UefiNtfsSafetyError):
                        validate_uefi_ntfs_media_plan(forged)


class FakeLayoutExecutor:
    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.cancelled = False

    def execute_multi(self, target, layout):
        self.calls.append((target, layout))
        if self.error:
            raise self.error
        return "/dev/sdz1", "/dev/sdz2"

    def cancel(self):
        self.cancelled = True


class FakeContentExecutor:
    def __init__(self, error=None, *, unmounted=True):
        self.error = error
        self.unmounted = unmounted
        self.calls = []
        self.cancelled = False

    def populate_existing_partition(self, plan, partition, progress, *, power_off):
        self.calls.append((plan, partition, power_off))
        if self.error:
            raise self.error
        progress(type("Update", (), {
            "stage": "Copying", "relative_path": "sources/setup.bin",
            "bytes_done": plan.total_bytes, "total_bytes": plan.total_bytes,
        })())
        return ConstructedMediaResult(
            plan.device.identity, partition, "/media/data",
            len(plan.files), plan.total_bytes, self.unmounted, False,
        )

    def cancel(self):
        self.cancelled = True


class BlockStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(65, 144)


class FakeProcess:
    def __init__(self, argv, readback, calls, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.readback = readback
        self.calls = calls
        self.returncode = 0
        self.terminated = False

    def communicate(self, input=None, timeout=None):
        self.calls.append((self.argv, input, self.kwargs))
        output = self.readback if any(arg.startswith("if=") for arg in self.argv) else b""
        return output, b""

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15


class StubbornProcess:
    def __init__(self, argv, events, *, on_first_communicate=None):
        self.argv = argv
        self.events = events
        self.on_first_communicate = on_first_communicate
        self.returncode = None
        self._communicates = 0
        self.killed = False

    def communicate(self, input=None, timeout=None):
        self._communicates += 1
        self.events.append(("communicate", input, timeout))
        if self._communicates == 1 and self.on_first_communicate is not None:
            self.on_first_communicate()
        if self.killed:
            self.returncode = -9
            return b"", b""
        raise subprocess.TimeoutExpired(self.argv, timeout)

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append(("terminate", None, None))

    def kill(self):
        self.events.append(("kill", None, None))
        self.killed = True


class ExecutorTests(unittest.TestCase):
    def make_executor(
        self, plan, *, readback=ARTIFACT_DATA, layout_error=None,
        content_error=None, content_unmounted=True, changed_device=False,
        wrong_geometry=False,
    ):
        layout = FakeLayoutExecutor(layout_error)
        content = FakeContentExecutor(content_error, unmounted=content_unmounted)
        commands = []
        process_calls = []

        def run(argv, **kwargs):
            commands.append((argv, kwargs))
            if "--json" in argv and "sfdisk" in argv[1]:
                return subprocess.CompletedProcess(
                    argv, 0, partition_metadata(plan, wrong_size=wrong_geometry), "",
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

        def popen(argv, **kwargs):
            return FakeProcess(argv, readback, process_calls, **kwargs)

        current = device(serial="CHANGED") if changed_device else device()
        executor = UefiNtfsExecutor(
            layout_executor=layout,  # type: ignore[arg-type]
            content_executor=content,  # type: ignore[arg-type]
            run_command=run, popen=popen,
            device_lister=lambda: [current],
            stat_func=lambda _path: BlockStat(),
        )
        return executor, layout, content, commands, process_calls

    def test_complete_flow_never_passes_cache_path_to_root_and_reads_back(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, layout, content, commands, processes = self.make_executor(plan)
            updates = []
            result = executor.execute(plan, updates.append)
        self.assertEqual(result.data_partition, "/dev/sdz1")
        self.assertEqual(result.boot_partition, "/dev/sdz2")
        self.assertTrue(result.powered_off)
        self.assertEqual(content.calls[0][1:], ("/dev/sdz1", False))
        dd_calls = [call for call in processes if "/usr/bin/dd" in call[0]]
        self.assertEqual(len(dd_calls), 2)
        self.assertEqual(
            dd_calls[0][0][:9],
            [
                "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive",
                "--nonblock", "--conflict-exit-code", "75", "--no-fork",
                "/dev/sdz", "/usr/bin/dd",
            ],
        )
        self.assertEqual(dd_calls[0][1], ARTIFACT_DATA)
        self.assertIsNone(dd_calls[1][1])
        self.assertFalse(any("cache" in argument for call in dd_calls for argument in call[0]))
        self.assertEqual(updates[-1].stage, "Complete")
        self.assertTrue(any(call[0][1] == "power-off" for call in commands))

    def test_raw_readback_corruption_fails_and_powers_off(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, _layout, _content, commands, _processes = self.make_executor(
                plan, readback=b"X" * len(ARTIFACT_DATA),
            )
            with self.assertRaisesRegex(UefiNtfsError, "read-back"):
                executor.execute(plan)
        self.assertTrue(any(call[0][1] == "power-off" for call in commands))

    def test_target_or_geometry_change_stops_before_raw_write(self):
        for option in ("target", "geometry"):
            with self.subTest(option=option):
                with tempfile.TemporaryDirectory() as directory, fixture_constants():
                    plan = build_plan(staging_tree(Path(directory)))
                    executor, _layout, content, commands, processes = self.make_executor(
                        plan,
                        changed_device=option == "target",
                        wrong_geometry=option == "geometry",
                    )
                    with self.assertRaises(UefiNtfsSafetyError):
                        executor.execute(plan)
                    self.assertEqual(processes, [])
                    if option == "target":
                        self.assertEqual(content.calls, [])
                        self.assertFalse(any(
                            call[0][1] == "power-off" for call in commands
                        ))

    def test_layout_and_content_failures_are_not_hidden(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, *_ = self.make_executor(
                plan, layout_error=FormattingError("layout failed"),
            )
            with self.assertRaisesRegex(UefiNtfsError, "layout failed"):
                executor.execute(plan)
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, *_ = self.make_executor(
                plan, content_error=ConstructedMediaError("copy failed"),
            )
            with self.assertRaisesRegex(ConstructedMediaError, "copy failed"):
                executor.execute(plan)

    def test_failed_data_unmount_stops_before_raw_helper_write(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, _layout, _content, _commands, processes = self.make_executor(
                plan, content_unmounted=False,
            )
            with self.assertRaisesRegex(UefiNtfsError, "cleanly unmounted"):
                executor.execute(plan)
        self.assertEqual(processes, [])

    def test_raw_dd_lock_conflict_has_specific_error(self):
        calls = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, b"", calls, **kwargs)
            process.returncode = 75
            return process

        executor = UefiNtfsExecutor(
            layout_executor=FakeLayoutExecutor(),  # type: ignore[arg-type]
            content_executor=FakeContentExecutor(),  # type: ignore[arg-type]
            popen=popen,
        )
        with self.assertRaisesRegex(UefiNtfsError, "lock-aware storage operation"):
            executor._run_dd(("/usr/bin/pkexec", "/usr/bin/dd"), b"payload")

    def test_cancel_before_start_touches_nothing_and_executor_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory, fixture_constants():
            plan = build_plan(staging_tree(Path(directory)))
            executor, layout, content, commands, processes = self.make_executor(plan)
            executor.cancel()
            with self.assertRaises(UefiNtfsCancelled):
                executor.execute(plan)
            self.assertTrue(layout.cancelled)
            self.assertTrue(content.cancelled)
            self.assertEqual(commands, [])
            self.assertEqual(processes, [])
            with self.assertRaisesRegex(UefiNtfsSafetyError, "cannot be reused"):
                executor.execute(plan)

    def test_raw_io_timeout_escalates_to_kill_reaps_and_clears_process(self):
        events = []
        holder = {}

        def popen(argv, **_kwargs):
            process = StubbornProcess(argv, events)
            holder["process"] = process
            return process

        moments = iter((0.0, 0.0, 2.0))
        executor = UefiNtfsExecutor(
            layout_executor=FakeLayoutExecutor(),  # type: ignore[arg-type]
            content_executor=FakeContentExecutor(),  # type: ignore[arg-type]
            popen=popen,
            raw_io_timeout=1.0,
            process_stop_timeout=0.5,
            monotonic=lambda: next(moments),
        )
        with self.assertRaisesRegex(UefiNtfsError, "bounded time limit"):
            executor._run_dd(("/usr/bin/pkexec", "/usr/bin/dd"), b"payload")

        process = holder["process"]
        self.assertTrue(process.killed)
        self.assertEqual(process.returncode, -9)
        self.assertIsNone(executor._process)
        self.assertEqual(
            [event[0] for event in events],
            ["communicate", "terminate", "communicate", "kill", "communicate"],
        )
        self.assertEqual(events[0][1], b"payload")
        self.assertTrue(all(
            event[2] <= 0.5
            for event in events if event[0] == "communicate"
        ))

    def test_inflight_cancel_escalates_to_kill_and_reaps(self):
        events = []
        holder = {}

        def popen(argv, **_kwargs):
            process = StubbornProcess(
                argv, events,
                on_first_communicate=lambda: holder["executor"].cancel(),
            )
            holder["process"] = process
            return process

        executor = UefiNtfsExecutor(
            layout_executor=FakeLayoutExecutor(),  # type: ignore[arg-type]
            content_executor=FakeContentExecutor(),  # type: ignore[arg-type]
            popen=popen,
            raw_io_timeout=10.0,
            process_stop_timeout=0.25,
            monotonic=lambda: 0.0,
        )
        holder["executor"] = executor
        with self.assertRaises(UefiNtfsCancelled):
            executor._run_dd(("/usr/bin/pkexec", "/usr/bin/dd"), b"payload")

        process = holder["process"]
        self.assertTrue(process.killed)
        self.assertEqual(process.returncode, -9)
        self.assertIsNone(executor._process)
        self.assertEqual([event[0] for event in events].count("kill"), 1)
        self.assertGreaterEqual([event[0] for event in events].count("terminate"), 1)


if __name__ == "__main__":
    unittest.main()
