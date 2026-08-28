# SPDX-License-Identifier: AGPL-3.0-or-later

import bz2
import io
import gzip
import json
import lzma
import os
import shutil
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
    def __init__(
        self,
        command: list[str],
        size: int,
        *,
        wrong_size: bool = False,
        returncode: int = 0,
        stdout: bytes | None = None,
        stderr: bytes = b"",
    ) -> None:
        self.command = command
        destination = Path(command[-1])
        with destination.open("wb") as stream:
            stream.truncate(size - 512 if wrong_size else size)
        self.stdout = io.BytesIO(
            stdout
            if stdout is not None
            else b"    (0.00/100%)\r    (50.00/100%)\r    (100.00/100%)\r"
        )
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = returncode

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

    @contextmanager
    def anonymous_output(self):
        if not hasattr(os, "O_TMPFILE"):
            self.skipTest("O_TMPFILE is unavailable")
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        descriptor = -1
        try:
            try:
                descriptor = os.open(
                    ".",
                    os.O_TMPFILE | os.O_EXCL | os.O_RDWR,
                    0o600,
                    dir_fd=directory,
                )
            except OSError as error:
                self.skipTest(f"The test filesystem lacks O_TMPFILE: {error}")
            os.fchmod(descriptor, 0o600)
            yield descriptor
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            os.close(directory)

    @staticmethod
    def matching_info_result(info):
        return json_result({
            "format": info.format,
            "virtual-size": info.virtual_size,
            "actual-size": info.actual_size,
            "format-specific": {"type": info.format, "data": {}},
        })

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

    def test_external_qcow_data_file_metadata_is_rejected_with_normalized_keys(self):
        cases = (
            {"data-file": "/tmp/external.raw"},
            {"data_file": "/tmp/external.raw"},
            {"data-file-raw": True},
            {"data_file_raw": 1},
        )
        for metadata in cases:
            with self.subTest(metadata=metadata), self.assertRaisesRegex(
                VirtualDiskError,
                "external data-file",
            ):
                self.inspect({
                    "format": "qcow2",
                    "virtual-size": 4096,
                    "format-specific": {
                        "type": "qcow2",
                        "data": metadata,
                    },
                })

        info, _ = self.inspect({
            "format": "qcow2",
            "virtual-size": 4096,
            "format-specific": {"type": "qcow2", "data": {}},
        })
        process_calls = []

        def must_not_convert(*args: object, **kwargs: object):
            process_calls.append((args, kwargs))
            raise AssertionError("conversion reached external data-file input")

        with self.anonymous_output() as output:
            with self.assertRaisesRegex(VirtualDiskError, "external data-file"):
                VirtualDiskStager(
                    must_not_convert,
                    info_runner=lambda *_args, **_kwargs: json_result({
                        "format": "qcow2",
                        "virtual-size": 4096,
                        "format-specific": {
                            "type": "qcow2",
                            "data": {
                                "data-file": "/tmp/external.raw",
                                "data-file-raw": True,
                            },
                        },
                    }),
                ).convert_into_descriptor(info, output)
            self.assertEqual(os.fstat(output).st_size, 0)
        self.assertEqual(process_calls, [])

    def test_real_qemu_external_qcow_data_file_is_rejected_on_inspect_and_convert(self):
        qemu_command = shutil.which("qemu-img")
        if qemu_command is None:
            self.skipTest("qemu-img is unavailable")
        qemu_img = Path(qemu_command).resolve(strict=True)
        image = self.root / "external-data.qcow2"
        data_file = self.root / "external-data.raw"
        created = subprocess.run(
            [
                str(qemu_img),
                "create",
                "-f",
                "qcow2",
                "-o",
                f"data_file={data_file},data_file_raw=on",
                str(image),
                "4096",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
            shell=False,
        )
        if created.returncode:
            diagnostic = created.stderr.decode(errors="replace").strip()
            self.skipTest(
                "qemu-img cannot create external-data QCOW2 fixtures: "
                f"{diagnostic[-300:]}"
            )

        with self.assertRaisesRegex(VirtualDiskError, "external data-file"):
            inspect_virtual_disk(image, qemu_img=qemu_img)

        safe_info = inspect_virtual_disk(
            image,
            qemu_img=qemu_img,
            runner=lambda *_args, **_kwargs: json_result({
                "format": "qcow2",
                "virtual-size": 4096,
                "format-specific": {"type": "qcow2", "data": {}},
            }),
        )
        process_calls = []

        def must_not_convert(*args: object, **kwargs: object):
            process_calls.append((args, kwargs))
            raise AssertionError("conversion reached external data-file input")

        with self.anonymous_output() as output:
            with self.assertRaisesRegex(VirtualDiskError, "external data-file"):
                VirtualDiskStager(must_not_convert).convert_into_descriptor(
                    safe_info,
                    output,
                )
            self.assertEqual(os.fstat(output).st_size, 0)
        self.assertEqual(process_calls, [])

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

    def test_descriptor_conversion_uses_only_bound_proc_fds_and_keeps_ownership(self):
        info, _ = self.inspect()
        calls: list[tuple[list[str], dict[str, object]]] = []
        updates: list[tuple[int, int]] = []

        def factory(command: list[str], **kwargs: object):
            calls.append((command, kwargs))
            return FinishedProcess(command, info.virtual_size)

        with self.anonymous_output() as output:
            before = os.fstat(output)
            VirtualDiskStager(
                factory,
                info_runner=lambda *_args, **_kwargs: self.matching_info_result(info),
            ).convert_into_descriptor(
                info,
                output,
                lambda done, total: updates.append((done, total)),
            )
            after = os.fstat(output)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(after.st_nlink, 0)
            self.assertEqual(after.st_mode & 0o777, 0o600)
            self.assertEqual(after.st_size, info.virtual_size)
            self.assertEqual(updates[-1], (info.virtual_size, info.virtual_size))

        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[0], str(info.qemu_img.path))
        self.assertEqual(command[1:3], ["convert", "--progress"])
        self.assertEqual(command[command.index("--source-format") + 1], info.format)
        self.assertEqual(command[command.index("--target-format") + 1], "raw")
        self.assertRegex(command[-2], r"^/proc/self/fd/\d+$")
        self.assertRegex(command[-1], r"^/proc/self/fd/\d+$")
        self.assertNotEqual(command[-2], command[-1])
        inherited = tuple(
            int(item.rsplit("/", 1)[-1]) for item in command[-2:]
        )
        self.assertEqual(kwargs["pass_fds"], inherited)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], subprocess.PIPE)
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["close_fds"], True)
        self.assertNotIn(str(info.path), command)

    def test_descriptor_conversion_revalidates_format_and_size_before_qemu(self):
        info, _ = self.inspect()
        cases = (
            ({"format": "qcow2", "virtual-size": info.virtual_size}, "format"),
            ({"format": info.format, "virtual-size": info.virtual_size * 2}, "size"),
        )
        for payload, _label in cases:
            with self.subTest(payload=payload), self.anonymous_output() as output:
                factory_calls = []

                def factory(*args: object, **kwargs: object):
                    factory_calls.append((args, kwargs))
                    raise AssertionError("conversion reached stale metadata")

                with self.assertRaisesRegex(
                    VirtualDiskChanged,
                    "format or guest-visible size changed",
                ):
                    VirtualDiskStager(
                        factory,
                        info_runner=lambda *_args, value=payload, **_kwargs: json_result(
                            {
                                **value,
                                "format-specific": {
                                    "type": value["format"],
                                    "data": {},
                                },
                            }
                        ),
                    ).convert_into_descriptor(info, output)
                self.assertEqual(factory_calls, [])
                self.assertEqual(os.fstat(output).st_size, 0)

    def test_descriptor_conversion_rejects_linked_readonly_and_nonempty_outputs(self):
        info, _ = self.inspect()
        runner = lambda *_args, **_kwargs: self.matching_info_result(info)
        linked = self.root / "linked-output.raw"
        linked.write_bytes(b"")
        linked_descriptor = os.open(linked, os.O_RDWR)
        try:
            with self.assertRaisesRegex(VirtualDiskError, "unlinked"):
                VirtualDiskStager(info_runner=runner).convert_into_descriptor(
                    info,
                    linked_descriptor,
                )
        finally:
            os.close(linked_descriptor)

        with self.anonymous_output() as output:
            readonly = os.open(f"/proc/self/fd/{output}", os.O_RDONLY)
            try:
                with self.assertRaisesRegex(VirtualDiskError, "read/write"):
                    VirtualDiskStager(info_runner=runner).convert_into_descriptor(
                        info,
                        readonly,
                    )
            finally:
                os.close(readonly)
        with self.anonymous_output() as output:
            os.write(output, b"not empty")
            with self.assertRaisesRegex(VirtualDiskError, "private 0600"):
                VirtualDiskStager(info_runner=runner).convert_into_descriptor(
                    info,
                    output,
                )

    def test_descriptor_conversion_detects_caller_fd_substitution(self):
        info, _ = self.inspect()
        replacement = -1
        with self.anonymous_output() as output:
            original_number = output

            def factory(command: list[str], **_kwargs: object):
                nonlocal replacement
                os.close(original_number)
                replacement = os.open("/dev/null", os.O_RDONLY)
                self.assertEqual(replacement, original_number)
                return FinishedProcess(command, info.virtual_size)

            with self.assertRaisesRegex(VirtualDiskChanged, "substituted"):
                VirtualDiskStager(
                    factory,
                    info_runner=lambda *_args, **_kwargs: self.matching_info_result(info),
                ).convert_into_descriptor(info, output)
        replacement = -1

    def test_descriptor_conversion_cancellation_reaps_qemu_and_preserves_empty_fd(self):
        info, _ = self.inspect()
        process = BlockingProcess()
        started = threading.Event()

        def factory(_command: list[str], **_kwargs: object):
            started.set()
            return process

        stager = VirtualDiskStager(
            factory,
            info_runner=lambda *_args, **_kwargs: self.matching_info_result(info),
        )
        errors: list[BaseException] = []
        with self.anonymous_output() as output:
            def run() -> None:
                try:
                    stager.convert_into_descriptor(info, output)
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=run)
            worker.start()
            self.assertTrue(started.wait(2))
            stager.cancel()
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertTrue(
                errors and isinstance(errors[0], VirtualConversionCancelled)
            )
            self.assertIsNotNone(process.returncode)
            self.assertEqual(os.fstat(output).st_size, 0)

    def test_descriptor_conversion_bounds_stall_errors_and_unexpected_output(self):
        info, _ = self.inspect()
        matching = lambda *_args, **_kwargs: self.matching_info_result(info)

        process = BlockingProcess()
        with (
            self.anonymous_output() as output,
            patch(
                "isopropyl.virtual.VIRTUAL_CONVERSION_STALL_TIMEOUT_SECONDS",
                0.0,
            ),
            self.assertRaisesRegex(VirtualDiskError, "stopped reporting progress"),
        ):
            VirtualDiskStager(
                lambda *_args, **_kwargs: process,
                info_runner=matching,
            ).convert_into_descriptor(info, output)
        self.assertIsNotNone(process.returncode)

        cases = (
            ({"returncode": 7, "stderr": b"bounded qemu failure"}, "bounded qemu failure"),
            ({"stdout": b"unexpected success chatter"}, "unexpected conversion output"),
            ({"stderr": b"unexpected success diagnostic"}, "unexpected diagnostics"),
        )
        for arguments, message in cases:
            with self.subTest(arguments=arguments), self.anonymous_output() as output:
                with self.assertRaisesRegex(VirtualDiskError, message):
                    VirtualDiskStager(
                        lambda command, **_kwargs: FinishedProcess(
                            command,
                            info.virtual_size,
                            **arguments,
                        ),
                        info_runner=matching,
                    ).convert_into_descriptor(info, output)

        with self.anonymous_output() as output, self.assertRaisesRegex(
            VirtualDiskChanged,
            "wrong size",
        ):
            VirtualDiskStager(
                lambda command, **_kwargs: FinishedProcess(
                    command,
                    info.virtual_size,
                    wrong_size=True,
                ),
                info_runner=matching,
            ).convert_into_descriptor(info, output)

    def test_descriptor_conversion_rechecks_source_identity_after_qemu(self):
        info, _ = self.inspect()
        before = self.source.stat()

        def factory(command: list[str], **_kwargs: object):
            process = FinishedProcess(command, info.virtual_size)
            self.source.write_bytes(b"Z" * before.st_size)
            os.utime(
                self.source,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            return process

        with self.anonymous_output() as output, self.assertRaises(VirtualDiskChanged):
            VirtualDiskStager(
                factory,
                info_runner=lambda *_args, **_kwargs: self.matching_info_result(info),
            ).convert_into_descriptor(info, output)

    def test_descriptor_conversion_accepts_existing_compressed_container_stage(self):
        compressed = self.root / "guest.vhdx.gz"
        payload = b"decoded-container" * 257
        compressed.write_bytes(gzip.compress(payload))
        info_result = lambda *_args, **_kwargs: json_result({
            "format": "vhdx",
            "virtual-size": 4096,
            "format-specific": {"type": "vhdx", "data": {}},
        })
        prepared = CompressedVirtualDiskPreparer(
            qemu_img=self.tool,
            info_runner=info_result,
        ).prepare(compressed, temporary_root=self.root)
        try:
            with self.anonymous_output() as output:
                VirtualDiskStager(
                    lambda command, **_kwargs: FinishedProcess(command, 4096),
                    info_runner=info_result,
                ).convert_into_descriptor(prepared.info, output)
                self.assertEqual(os.fstat(output).st_size, 4096)
        finally:
            prepared.close()

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
