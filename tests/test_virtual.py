# SPDX-License-Identifier: AGPL-3.0-or-later

import bz2
import io
import gzip
import json
import lzma
import os
import subprocess
import tempfile
import threading
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from isopropyl.sources import SourceIdentity

from isopropyl.virtual import (
    COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES, MAX_INFO_JSON,
    CompressedVirtualDiskPreparer, VirtualConversionCancelled,
    VirtualDiskChanged, VirtualDiskError, VirtualDiskStager,
    VIRTUAL_STAGING_FREE_RESERVE_BYTES, inspect_virtual_disk, resolve_qemu_img,
)


class CallerCancellation(OSError):
    pass


def json_result(payload: object, returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        [], returncode, json.dumps(payload).encode(), b"qemu error" if returncode else b""
    )


class FinishedProcess:
    def __init__(self, command: list[str], size: int, *, wrong_size: bool = False) -> None:
        self.command = command
        destination = Path(command[-1])
        with destination.open("wb") as stream:
            stream.truncate(size - 512 if wrong_size else size)
        self.stdout = io.BytesIO(b"    (0.00/100%)\r    (50.00/100%)\r    (100.00/100%)\r")
        self.stderr = io.BytesIO()
        self.returncode: int | None = 0

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


class BlockingProcess:
    def __init__(self) -> None:
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            if timeout is not None:
                raise subprocess.TimeoutExpired("qemu-img", timeout)
            raise AssertionError("wait without termination")
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


class VirtualDiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "disk.vhdx"
        self.source.write_bytes(b"vhdx-container")
        self.tool = self.root / "qemu-img"
        self.tool.write_bytes(b"mock executable")
        self.tool.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inspect(self, payload: object | None = None):
        description = payload or {
            "filename": str(self.source), "format": "vhdx",
            "virtual-size": 4096, "actual-size": 1024,
            "format-specific": {"type": "vhdx", "data": {}},
        }
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command: list[str], **kwargs: object):
            calls.append((command, kwargs))
            return json_result(description)

        result = inspect_virtual_disk(self.source, qemu_img=self.tool, runner=runner)
        return result, calls

    def test_info_parsing_uses_absolute_shell_free_qemu_img(self):
        info, calls = self.inspect()
        self.assertEqual(info.format, "vhdx")
        self.assertEqual(info.display_format, "VHDX")
        self.assertEqual(info.virtual_size, 4096)
        command, kwargs = calls[0]
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertEqual(command[1:3], ["info", "--output=json"])
        self.assertRegex(command[-1], r"^/proc/self/fd/\d+$")
        self.assertNotIn(str(self.source), command)
        inherited = int(command[-1].rsplit("/", 1)[-1])
        self.assertEqual(kwargs["pass_fds"], (inherited,))
        self.assertIs(kwargs["shell"], False)

    def test_vhd_and_qcow_formats_are_accepted_without_extension_guessing(self):
        for image_format, display in (("vpc", "VHD"), ("qcow", "QCOW"), ("qcow2", "QCOW2")):
            with self.subTest(image_format=image_format):
                info, _ = self.inspect({
                    "format": image_format, "virtual-size": 4096,
                    "format-specific": {"type": image_format, "data": {}},
                })
                self.assertEqual(info.display_format, display)

    def test_relative_or_non_executable_tool_is_rejected(self):
        with self.assertRaisesRegex(VirtualDiskError, "absolute"):
            resolve_qemu_img(Path("qemu-img"))
        self.tool.chmod(0o600)
        with self.assertRaisesRegex(VirtualDiskError, "executable"):
            resolve_qemu_img(self.tool)

    def test_backing_encryption_corruption_and_format_conflicts_are_rejected(self):
        cases = (
            ({"format": "qcow2", "virtual-size": 4096, "backing-filename": "base.qcow2"}, "backing"),
            ({"format": "qcow2", "virtual-size": 4096, "encrypted": True}, "encryption"),
            ({"format": "qcow2", "virtual-size": 4096,
              "format-specific": {"type": "qcow2", "data": {"corrupt": True}}}, "corruption"),
            ({"format": "vhdx", "virtual-size": 4096,
              "format-specific": {"type": "qcow2", "data": {}}}, "conflicting"),
        )
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(VirtualDiskError, message):
                    self.inspect(payload)

    def test_malformed_json_types_sizes_and_unsupported_formats_fail_closed(self):
        def run(stdout: bytes):
            return inspect_virtual_disk(
                self.source, qemu_img=self.tool,
                runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout, b""),
            )

        with self.assertRaisesRegex(VirtualDiskError, "malformed JSON"):
            run(b"{")
        with self.assertRaisesRegex(VirtualDiskError, "must be an object"):
            run(b"[]")
        with self.assertRaisesRegex(VirtualDiskError, "Unsupported"):
            run(b'{"format":"raw","virtual-size":4096}')
        with self.assertRaisesRegex(VirtualDiskError, "integer"):
            run(b'{"format":"vhdx","virtual-size":true}')
        with self.assertRaisesRegex(VirtualDiskError, "aligned"):
            run(b'{"format":"vhdx","virtual-size":513}')
        with self.assertRaisesRegex(VirtualDiskError, "oversized"):
            run(b" " * (MAX_INFO_JSON + 1))

    def test_source_identity_change_during_inspection_is_rejected(self):
        def runner(*_args: object, **_kwargs: object):
            self.source.write_bytes(b"changed container")
            return json_result({"format": "vhdx", "virtual-size": 4096})

        with self.assertRaises(VirtualDiskChanged):
            inspect_virtual_disk(self.source, qemu_img=self.tool, runner=runner)

    def test_source_ctime_change_during_inspection_is_rejected(self):
        before = self.source.stat()

        def runner(*_args: object, **_kwargs: object):
            self.source.write_bytes(b"X" * before.st_size)
            os.utime(
                self.source,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            return json_result({"format": "vhdx", "virtual-size": 4096})

        with self.assertRaises(VirtualDiskChanged):
            inspect_virtual_disk(self.source, qemu_img=self.tool, runner=runner)

    def test_inspection_rejects_symlinks_and_preserves_live_cancellation(self):
        link = self.root / "linked.vhdx"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(VirtualDiskError, "opened safely"):
            inspect_virtual_disk(link, qemu_img=self.tool, runner=lambda *_a, **_k: None)

        process = BlockingProcess()
        signal = CallerCancellation("inspection cancelled")
        checks = 0

        def cancel_during_info() -> None:
            nonlocal checks
            checks += 1
            if checks >= 3:
                raise signal

        with (
            patch("isopropyl.virtual.subprocess.Popen", return_value=process),
            self.assertRaises(CallerCancellation) as caught,
        ):
            inspect_virtual_disk(
                self.source, qemu_img=self.tool,
                cancel_check=cancel_during_info,
            )
        self.assertIs(caught.exception, signal)
        self.assertIsNotNone(process.returncode)

    def test_compressed_preparer_decodes_inspects_and_cleans_private_stage(self):
        source = self.root / "guest.vhdx.gz"
        payload = b"private-vhdx-container" * 257
        source.write_bytes(gzip.compress(payload))
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command: list[str], **kwargs: object):
            calls.append((command, kwargs))
            descriptor = kwargs["pass_fds"][0]  # type: ignore[index]
            self.assertEqual(os.pread(descriptor, len(payload), 0), payload)
            self.assertNotIn(str(source), command)
            return json_result({
                "format": "vhdx", "virtual-size": 8192,
                "actual-size": len(payload),
                "format-specific": {"type": "vhdx", "data": {}},
            })

        status = source.stat()
        expected = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        prepared = CompressedVirtualDiskPreparer(
            qemu_img=self.tool, info_runner=runner,
        ).prepare(
            source, expected_identity=expected,
            expected_format="vhdx", expected_virtual_size=8192,
            temporary_root=self.root,
        )
        directory = prepared.path.parent
        try:
            self.assertEqual(prepared.path.read_bytes(), payload)
            self.assertEqual(prepared.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(prepared.compression, "gzip")
            self.assertEqual(prepared.decoded_size, len(payload))
            self.assertEqual(prepared.info.format, "vhdx")
            self.assertEqual(prepared.info.virtual_size, 8192)
            self.assertEqual(prepared.original_identity.size, status.st_size)
            command, kwargs = calls[0]
            self.assertRegex(command[-1], r"^/proc/self/fd/\d+$")
            self.assertEqual(
                kwargs["pass_fds"],
                (int(command[-1].rsplit("/", 1)[-1]),),
            )
        finally:
            prepared.close()
        self.assertFalse(directory.exists())
        prepared.close()

    def test_single_file_zip_uses_member_suffix_for_compressed_virtual(self):
        source = self.root / "generic.zip"
        payload = b"qcow2-container"
        with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/guest.qcow2", payload)

        prepared = CompressedVirtualDiskPreparer(
            qemu_img=self.tool,
            info_runner=lambda *_args, **_kwargs: json_result({
                "format": "qcow2", "virtual-size": 4096,
                "format-specific": {"type": "qcow2", "data": {}},
            }),
        ).prepare(source, temporary_root=self.root)
        try:
            self.assertEqual(prepared.path.suffix, ".qcow2")
            self.assertEqual(prepared.path.read_bytes(), payload)
            self.assertEqual(prepared.compression, "zip")
        finally:
            prepared.close()

    def test_in_process_compression_aliases_reach_virtual_inspection(self):
        payload = b"virtual-container" * 257
        wrappers = {
            ".gz": gzip.compress(payload),
            ".gzip": gzip.compress(payload),
            ".bz2": bz2.compress(payload),
            ".bzip2": bz2.compress(payload),
            ".xz": lzma.compress(payload, format=lzma.FORMAT_XZ),
            ".lzma": lzma.compress(payload, format=lzma.FORMAT_ALONE),
        }
        for suffix, encoded in wrappers.items():
            with self.subTest(suffix=suffix):
                source = self.root / f"guest.qcow2{suffix}"
                source.write_bytes(encoded)
                prepared = CompressedVirtualDiskPreparer(
                    qemu_img=self.tool,
                    info_runner=lambda *_args, **_kwargs: json_result({
                        "format": "qcow2", "virtual-size": 4096,
                        "format-specific": {"type": "qcow2", "data": {}},
                    }),
                ).prepare(source, temporary_root=self.root)
                try:
                    self.assertEqual(prepared.path.read_bytes(), payload)
                    self.assertEqual(prepared.info.format, "qcow2")
                finally:
                    prepared.close()

    def test_optional_external_compression_aliases_route_through_preparer(self):
        payload = b"external-decoder-container" * 129

        @contextmanager
        def decoded_stream(*_args, **_kwargs):
            yield io.BytesIO(payload)

        for suffix, method in (
            (".zst", "_open_zstd"),
            (".zstd", "_open_zstd"),
            (".Z", "_open_external_decoder"),
            (".z", "_open_external_decoder"),
        ):
            with self.subTest(suffix=suffix):
                source = self.root / f"guest.vhdx{suffix}"
                source.write_bytes(b"encoded fixture")
                with patch(
                    f"isopropyl.sources.ImageSource.{method}",
                    new=decoded_stream,
                ):
                    prepared = CompressedVirtualDiskPreparer(
                        qemu_img=self.tool,
                        info_runner=lambda *_args, **_kwargs: json_result({
                            "format": "vhdx", "virtual-size": 4096,
                            "format-specific": {"type": "vhdx", "data": {}},
                        }),
                    ).prepare(source, temporary_root=self.root)
                try:
                    self.assertEqual(prepared.path.read_bytes(), payload)
                    self.assertEqual(prepared.info.format, "vhdx")
                finally:
                    prepared.close()

    def test_compressed_preparer_bounds_space_and_confirmation_metadata(self):
        source = self.root / "guest.vhdx.gz"
        payload = b"X" * 4096
        source.write_bytes(gzip.compress(payload))
        result = {
            "format": "vhdx", "virtual-size": 8192,
            "format-specific": {"type": "vhdx", "data": {}},
        }

        before = set(self.root.iterdir())
        with self.assertRaisesRegex(VirtualDiskError, "safety cap"):
            CompressedVirtualDiskPreparer(
                qemu_img=self.tool, info_runner=lambda *_a, **_k: json_result(result),
            ).prepare(
                source, temporary_root=self.root,
                maximum_decoded_size=len(payload) - 1,
            )
        self.assertEqual(set(self.root.iterdir()), before)

        ample = type("Usage", (), {
            "free": COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES + len(payload) + 1,
        })()
        exhausted = type("Usage", (), {
            "free": COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES,
        })()
        with (
            patch(
                "isopropyl.virtual.shutil.disk_usage",
                side_effect=(ample, exhausted),
            ),
            self.assertRaisesRegex(VirtualDiskError, "free-space reserve"),
        ):
            CompressedVirtualDiskPreparer(
                qemu_img=self.tool, info_runner=lambda *_a, **_k: json_result(result),
            ).prepare(source, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before)

        cases = (
            ({"expected_identity": (0, 0, 0, 0, 0)}, "after confirmation"),
            ({"expected_format": "qcow2"}, "format changed"),
            ({"expected_virtual_size": 4096}, "size changed"),
        )
        for arguments, pattern in cases:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(
                VirtualDiskChanged, pattern,
            ):
                CompressedVirtualDiskPreparer(
                    qemu_img=self.tool,
                    info_runner=lambda *_a, **_k: json_result(result),
                ).prepare(source, temporary_root=self.root, **arguments)
            self.assertEqual(set(self.root.iterdir()), before)

    def test_compressed_preparer_rejects_suffix_format_mismatch_and_cleans(self):
        source = self.root / "guest.vhd.gz"
        source.write_bytes(gzip.compress(b"container"))
        before = set(self.root.iterdir())
        with self.assertRaisesRegex(VirtualDiskError, "does not match"):
            CompressedVirtualDiskPreparer(
                qemu_img=self.tool,
                info_runner=lambda *_a, **_k: json_result({
                    "format": "vhdx", "virtual-size": 4096,
                }),
            ).prepare(source, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_compressed_outer_change_during_qemu_inspection_fails_closed(self):
        source = self.root / "guest.vhdx.gz"
        source.write_bytes(gzip.compress(b"container"))
        before_entries = set(self.root.iterdir())
        before_status = source.stat()

        def mutate_outer(*_args: object, **_kwargs: object):
            source.write_bytes(b"X" * before_status.st_size)
            os.utime(
                source,
                ns=(before_status.st_atime_ns, before_status.st_mtime_ns),
            )
            return json_result({"format": "vhdx", "virtual-size": 4096})

        with self.assertRaises(VirtualDiskChanged):
            CompressedVirtualDiskPreparer(
                qemu_img=self.tool, info_runner=mutate_outer,
            ).prepare(source, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before_entries)

    def test_compressed_preparer_cancel_during_info_reaps_and_cleans(self):
        source = self.root / "guest.vhdx.gz"
        source.write_bytes(gzip.compress(b"container"))
        before = set(self.root.iterdir())
        process = BlockingProcess()
        spawned = threading.Event()

        def factory(*_args: object, **_kwargs: object):
            spawned.set()
            return process

        preparer = CompressedVirtualDiskPreparer(qemu_img=self.tool)
        errors: list[BaseException] = []

        def run() -> None:
            try:
                preparer.prepare(source, temporary_root=self.root)
            except BaseException as error:
                errors.append(error)

        with patch("isopropyl.virtual.subprocess.Popen", side_effect=factory):
            worker = threading.Thread(target=run)
            worker.start()
            self.assertTrue(spawned.wait(2))
            preparer.cancel()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], VirtualConversionCancelled))
        self.assertIsNotNone(process.returncode)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_compressed_preparer_cancel_during_decode_cleans_without_qemu(self):
        source = self.root / "guest.vhdx.gz"
        source.write_bytes(b"compressed fixture")
        before = set(self.root.iterdir())
        preparer = CompressedVirtualDiskPreparer(qemu_img=self.tool)

        class FakeSource:
            compressed = True
            compression = "gzip"
            identity = SourceIdentity(1, 2, 3, 4, 5)
            closed = False

            def decoded_name(self, *, cancel_check=None):
                if cancel_check is not None:
                    cancel_check()
                return "guest.vhdx"

            def chunks(self, expected_size=None, cancel_check=None):
                del expected_size, cancel_check
                yield b"A" * 512
                preparer.cancel()
                yield b"B" * 512

            def close(self):
                self.closed = True

        fake = FakeSource()
        with (
            patch("isopropyl.virtual.open_image_source", return_value=fake),
            patch("isopropyl.virtual.resolve_qemu_img") as resolve,
            self.assertRaises(VirtualConversionCancelled),
        ):
            preparer.prepare(source, temporary_root=self.root)

        resolve.assert_not_called()
        self.assertTrue(fake.closed)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_conversion_is_explicit_raw_sparse_private_and_exact(self):
        info, _ = self.inspect()
        commands: list[list[str]] = []
        process_kwargs: list[dict[str, object]] = []

        def factory(command: list[str], **kwargs: object):
            commands.append(command)
            process_kwargs.append(kwargs)
            return FinishedProcess(command, info.virtual_size)

        updates: list[tuple[int, int]] = []
        staged = VirtualDiskStager(factory).stage(
            info, lambda done, total: updates.append((done, total)),
            temporary_root=self.root,
        )
        try:
            self.assertTrue(staged.path.is_file())
            self.assertEqual(staged.path.stat().st_size, info.virtual_size)
            self.assertEqual(staged.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(staged.path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(updates[-1], (4096, 4096))
            command = commands[0]
            self.assertIn("--source-format", command)
            self.assertEqual(command[command.index("--source-format") + 1], "vhdx")
            self.assertEqual(command[command.index("--target-format") + 1], "raw")
            self.assertEqual(command[command.index("--sparse-size") + 1], "4k")
            self.assertRegex(command[-2], r"^/proc/self/fd/\d+$")
            self.assertNotIn(str(self.source), command)
            inherited = int(command[-2].rsplit("/", 1)[-1])
            self.assertEqual(process_kwargs[0]["pass_fds"], (inherited,))
            self.assertNotEqual(staged.path.read_bytes()[:4], self.source.read_bytes()[:4])
        finally:
            directory = staged.path.parent
            staged.close()
        self.assertFalse(directory.exists())

    def test_wrong_output_size_fails_and_cleans_partial_stage(self):
        info, _ = self.inspect()
        before = set(self.root.iterdir())
        stager = VirtualDiskStager(
            lambda command, **_kwargs: FinishedProcess(command, info.virtual_size, wrong_size=True)
        )
        with self.assertRaisesRegex(VirtualDiskError, "expected"):
            stager.stage(info, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_default_staging_requires_full_virtual_size_free(self):
        info, _ = self.inspect()
        with patch("isopropyl.virtual.shutil.disk_usage") as disk_usage:
            # disk_usage() returns a tuple with total, used, free attributes.
            disk_usage.return_value = type(
                "Usage", (), {"total": 8192, "used": 4097, "free": 4095}
            )()
            with self.assertRaisesRegex(VirtualDiskError, "enough free space"):
                VirtualDiskStager().stage(info, temporary_root=self.root)

    def test_conversion_preserves_fixed_free_space_reserve(self):
        info, _ = self.inspect()
        boundary = type("Usage", (), {
            "free": info.virtual_size + VIRTUAL_STAGING_FREE_RESERVE_BYTES - 1,
        })()
        with (
            patch("isopropyl.virtual.shutil.disk_usage", return_value=boundary),
            self.assertRaisesRegex(VirtualDiskError, "safety reserve"),
        ):
            VirtualDiskStager().stage(info, temporary_root=self.root)

        before = set(self.root.iterdir())
        ample = type("Usage", (), {
            "free": info.virtual_size + VIRTUAL_STAGING_FREE_RESERVE_BYTES,
        })()
        exhausted = type("Usage", (), {
            "free": VIRTUAL_STAGING_FREE_RESERVE_BYTES - 1,
        })()
        with (
            patch(
                "isopropyl.virtual.shutil.disk_usage",
                side_effect=(ample, exhausted),
            ),
            self.assertRaisesRegex(VirtualDiskError, "consumed.*reserve"),
        ):
            VirtualDiskStager(
                lambda command, **_kwargs: FinishedProcess(
                    command, info.virtual_size,
                )
            ).stage(info, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_cancellation_before_and_during_conversion_cleans_up(self):
        info, _ = self.inspect()
        before = set(self.root.iterdir())
        stager = VirtualDiskStager()
        stager.cancel()
        with self.assertRaises(VirtualConversionCancelled):
            stager.stage(info, temporary_root=self.root)

        process = BlockingProcess()
        started = threading.Event()

        def factory(_command: list[str], **_kwargs: object):
            started.set()
            return process

        stager = VirtualDiskStager(factory)
        errors: list[BaseException] = []

        def run_stage() -> None:
            try:
                stager.stage(info, temporary_root=self.root)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run_stage)
        worker.start()
        self.assertTrue(started.wait(2))
        stager.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], VirtualConversionCancelled))
        self.assertEqual(set(self.root.iterdir()), before)

    def test_source_change_during_conversion_rejects_and_cleans_stage(self):
        info, _ = self.inspect()
        before = set(self.root.iterdir())

        def factory(command: list[str], **_kwargs: object):
            process = FinishedProcess(command, info.virtual_size)
            self.source.write_bytes(b"container modified during conversion")
            return process

        with self.assertRaises(VirtualDiskChanged):
            VirtualDiskStager(factory).stage(info, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_source_ctime_change_during_conversion_rejects_and_cleans_stage(self):
        info, _ = self.inspect()
        before_entries = set(self.root.iterdir())
        before = self.source.stat()

        def factory(command: list[str], **_kwargs: object):
            process = FinishedProcess(command, info.virtual_size)
            self.source.write_bytes(b"Y" * before.st_size)
            os.utime(
                self.source,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            return process

        with self.assertRaises(VirtualDiskChanged):
            VirtualDiskStager(factory).stage(info, temporary_root=self.root)
        self.assertEqual(set(self.root.iterdir()), before_entries)


if __name__ == "__main__":
    unittest.main()
