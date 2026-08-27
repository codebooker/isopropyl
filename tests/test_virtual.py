# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.virtual import (
    MAX_INFO_JSON, VirtualConversionCancelled, VirtualDiskChanged, VirtualDiskError,
    VirtualDiskStager, inspect_virtual_disk, resolve_qemu_img,
)


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

    def test_conversion_is_explicit_raw_sparse_private_and_exact(self):
        info, _ = self.inspect()
        commands: list[list[str]] = []

        def factory(command: list[str], **_kwargs: object):
            commands.append(command)
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


if __name__ == "__main__":
    unittest.main()
