#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Opt-in GRUB 2.14 intentional-rescue certification under SeaBIOS.

This source-tree maintainer tool obtains ISOpropyl's exact catalog bundle,
builds an empty private MBR/FAT32 image with the production GRUB rescue
planner and builder, copies only the builder's re-attested byte stream into a
sealed read-only memfd, and observes the intentional ``grub rescue>`` prompt.

No image pathname or block-device path is accepted.  QEMU runs unprivileged
under TCG in fresh user and network namespaces, with no guest NIC, snapshot
writes, and a fixed 80x25 curses display attached to a private pseudo-terminal.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

# Direct execution puts ``tools/`` rather than the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.bootloaders import (
    BoundBootBundle,
    CatalogError,
    DependencyUnavailable,
    DownloadError,
    prepare_bundle,
)
from isopropyl.grub_rescue import (
    GRUB_FAMILY,
    GRUB_PURPOSE,
    GRUB_VERSION,
    PROFILE_ID,
    RESULT_SEMANTICS,
    GrubRescueBuilder,
    GrubRescueError,
    GrubRescueResult,
    PreparedGrubRescueImage,
    build_grub_rescue_plan,
)
from isopropyl.private_fat32 import PARTITION_START_SECTOR, SECTOR_SIZE
from tools import certify_freedos_boot as _hardened_qemu


BOOT_MARKERS = (
    "Booting from Hard Disk...",
    "Welcome to GRUB!",
    "Entering rescue mode...",
    "grub rescue>",
)
PRIVATE_IMAGE_SIZE = 36_888_576
DEFAULT_TIMEOUT = 30
MIN_TIMEOUT = 5
MAX_TIMEOUT = 180
MAX_TERMINAL_STREAM = _hardened_qemu.MAX_TERMINAL_STREAM
MAX_DIAGNOSTIC_BYTES = _hardened_qemu.MAX_DIAGNOSTIC_BYTES
DEFAULT_EXECUTABLE_PATH = _hardened_qemu.DEFAULT_EXECUTABLE_PATH
REQUIRED_MEMFD_SEALS = _hardened_qemu.REQUIRED_MEMFD_SEALS

BootCertificationError = _hardened_qemu.BootCertificationError
FileIdentity = _hardened_qemu.FileIdentity
QemuIdentity = _hardened_qemu.QemuIdentity
BootCapture = _hardened_qemu.BootCapture
resolve_qemu = _hardened_qemu.resolve_qemu
verify_qemu_unchanged = _hardened_qemu.verify_qemu_unchanged
query_qemu_version = _hardened_qemu.query_qemu_version


@dataclass
class BoundExecutable:
    """One non-set-ID executable bound by descriptor, identity, and digest."""

    path: Path
    fd: int
    identity: FileIdentity
    sha256: str
    expected_name: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "BoundExecutable":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass
class SealedPreparedImage:
    fd: int
    size: int
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "SealedPreparedImage":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class PipelineEvidence:
    bundle: BoundBootBundle
    result: GrubRescueResult
    partition_sectors: int
    staging_root_initially_empty: bool
    build_workspace_initially_empty: bool


def _descriptor_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"


def _resolve_bound_executable(
    expected_name: str,
    path: Path | None = None,
) -> BoundExecutable:
    if path is None:
        found = shutil.which(expected_name, path=DEFAULT_EXECUTABLE_PATH)
        if found is None:
            raise BootCertificationError(f"{expected_name} is not installed")
        candidate = Path(found)
    else:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise BootCertificationError(
                f"The {expected_name} executable path must be absolute"
            )
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        if resolved.name != expected_name:
            raise BootCertificationError(
                f"The executable must be named {expected_name}"
            )
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not os.access(resolved, os.X_OK)
        ):
            raise BootCertificationError(
                f"{expected_name} must be an executable, non-set-ID regular file"
            )
        identity = _hardened_qemu._identity(status)
        digest = _hardened_qemu._sha256_fd(
            descriptor, status.st_size, description=f"{expected_name} executable",
        )
        if (
            _hardened_qemu._identity(os.fstat(descriptor)) != identity
            or _hardened_qemu._path_identity(
                resolved, description=f"{expected_name} executable",
            ) != identity
        ):
            raise BootCertificationError(
                f"{expected_name} changed while it was bound"
            )
        result = BoundExecutable(
            resolved, descriptor, identity, digest, expected_name,
        )
        descriptor = -1
        return result
    except BootCertificationError:
        raise
    except OSError as error:
        raise BootCertificationError(
            f"Could not resolve {expected_name}: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def resolve_unshare(path: Path | None = None) -> BoundExecutable:
    return _resolve_bound_executable("unshare", path)


def verify_executable_unchanged(executable: BoundExecutable) -> None:
    try:
        current = _hardened_qemu._identity(os.fstat(executable.fd))
        path_identity = _hardened_qemu._path_identity(
            executable.path,
            description=f"{executable.expected_name} executable",
        )
        digest = _hardened_qemu._sha256_fd(
            executable.fd,
            executable.identity.size,
            description=f"{executable.expected_name} executable",
        )
    except OSError as error:
        raise BootCertificationError(
            f"Could not recheck {executable.expected_name}: {error}"
        ) from error
    if (
        current != executable.identity
        or path_identity != executable.identity
        or digest != executable.sha256
        or _hardened_qemu._identity(os.fstat(executable.fd))
        != executable.identity
        or _hardened_qemu._path_identity(
            executable.path,
            description=f"{executable.expected_name} executable",
        ) != executable.identity
    ):
        raise BootCertificationError(
            f"{executable.expected_name} changed during certification"
        )


def _new_sealable_memfd(name: str) -> int:
    required = ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")
    if any(not hasattr(os, item) for item in required):
        raise BootCertificationError(
            "Safe certification requires Linux sealed memfd support"
        )
    seal_names = (
        "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
        "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL",
    )
    if any(not hasattr(fcntl, item) for item in seal_names):
        raise BootCertificationError("Safe certification requires Linux file seals")
    try:
        return os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except OSError as error:
        raise BootCertificationError(f"Could not create a sealed memfd: {error}") from error


def _write_all(fd: int, data: bytes, offset: int) -> None:
    consumed = 0
    while consumed < len(data):
        written = os.pwrite(fd, data[consumed:], offset + consumed)
        if written <= 0:
            raise BootCertificationError("Could not populate the sealed GRUB image")
        consumed += written


def _seal_readonly(fd: int, size: int, expected_sha256: str) -> int:
    readonly = -1
    try:
        if os.fstat(fd).st_size != size:
            raise BootCertificationError("The GRUB memfd snapshot has the wrong size")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
            raise BootCertificationError("The GRUB memfd snapshot could not be fully sealed")
        readonly = os.open(_descriptor_path(fd), os.O_RDONLY | os.O_CLOEXEC)
        digest = _hardened_qemu._sha256_fd(
            readonly, size, description="sealed prepared GRUB image",
        )
        if digest != expected_sha256:
            raise BootCertificationError(
                "The sealed GRUB snapshot changed while it was created"
            )
        result = readonly
        readonly = -1
        return result
    except OSError as error:
        raise BootCertificationError(f"Could not seal the GRUB snapshot: {error}") from error
    finally:
        if readonly >= 0:
            os.close(readonly)


def seal_prepared_image(prepared: PreparedGrubRescueImage) -> SealedPreparedImage:
    """Seal only the production owner's complete, re-attested byte stream."""

    result = prepared.result
    size = result.image_size
    expected = result.final_image_sha256
    if (
        type(size) is not int or size <= 0
        or type(expected) is not str or len(expected) != 64
    ):
        raise BootCertificationError("The prepared GRUB result is invalid")
    writable = _new_sealable_memfd("isopropyl-grub-rescue-prepared")
    try:
        digest = hashlib.sha256()
        offset = 0
        for block in prepared.chunks(1024 * 1024):
            if type(block) is not bytes or not block or offset + len(block) > size:
                raise BootCertificationError("The prepared GRUB byte stream is invalid")
            _write_all(writable, block, offset)
            digest.update(block)
            offset += len(block)
        if offset != size:
            raise BootCertificationError("The prepared GRUB byte stream is truncated")
        rendered = digest.hexdigest()
        if rendered != expected:
            raise BootCertificationError(
                "The prepared GRUB byte stream failed its final attestation"
            )
        readonly = _seal_readonly(writable, size, rendered)
        return SealedPreparedImage(readonly, size, rendered)
    finally:
        os.close(writable)


def verify_sealed_prepared_image(image: SealedPreparedImage) -> None:
    try:
        status = os.fstat(image.fd)
        seals = fcntl.fcntl(image.fd, fcntl.F_GET_SEALS)
    except OSError as error:
        raise BootCertificationError(
            f"Could not recheck the sealed GRUB image: {error}"
        ) from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_size != image.size
        or seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS
        or _hardened_qemu._sha256_fd(
            image.fd, image.size, description="sealed prepared GRUB image",
        ) != image.sha256
    ):
        raise BootCertificationError("The sealed prepared GRUB image changed")


def _make_empty_private_directory(parent: Path, name: str) -> Path:
    path = parent / name
    try:
        path.mkdir(mode=0o700)
        status = path.stat(follow_symlinks=False)
    except OSError as error:
        raise BootCertificationError(
            f"Could not create the empty private {name}: {error}"
        ) from error
    if not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o700:
        raise BootCertificationError(f"The private {name} is not a mode-0700 directory")
    if any(path.iterdir()):
        raise BootCertificationError(f"The private {name} is not empty")
    return path


def prepare_certification_pipeline(
    workspace: Path,
    *,
    cache_dir: Path | None = None,
) -> tuple[SealedPreparedImage, PipelineEvidence]:
    """Download/cache, plan, and build only through production entry points."""

    root = Path(workspace)
    if not root.is_dir() or any(root.iterdir()):
        raise BootCertificationError("The certification workspace must start empty")
    staging_root = _make_empty_private_directory(root, "empty-staging")
    build_workspace = _make_empty_private_directory(root, "build-workspace")
    bundle = prepare_bundle(
        GRUB_FAMILY,
        GRUB_VERSION,
        GRUB_PURPOSE,
        cache_dir=cache_dir,
        overall_timeout=180,
    )
    plan = build_grub_rescue_plan(
        bundle,
        staging_root,
        build_workspace,
        image_size=PRIVATE_IMAGE_SIZE,
    )
    prepared: PreparedGrubRescueImage | None = None
    sealed: SealedPreparedImage | None = None
    try:
        prepared = GrubRescueBuilder().execute(plan)
        result = prepared.result
        sealed = seal_prepared_image(prepared)
        evidence = PipelineEvidence(
            bundle,
            result,
            plan.private_plan.geometry.partition_sectors,
            True,
            True,
        )
        output = sealed
        sealed = None
        return output, evidence
    finally:
        if sealed is not None:
            sealed.close()
        if prepared is not None:
            prepared.close()


def build_qemu_command(
    unshare_fd: int,
    qemu_fd: int,
    source_fd: int,
) -> tuple[str, ...]:
    """Build the fixed namespace, TCG, SeaBIOS, fd-only command."""

    return (
        _descriptor_path(unshare_fd),
        "--user", "--map-current-user", "--net", "--",
        _descriptor_path(qemu_fd),
        "-no-user-config",
        "-sandbox", "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
        "-machine", "pc,accel=tcg",
        "-cpu", "qemu32",
        "-m", "64M",
        "-snapshot",
        "-boot", "order=c,strict=on",
        "-add-fd", f"fd={source_fd},set=1,opaque=grub-rescue-prepared",
        "-drive",
        (
            "file=/dev/fdset/1,if=ide,index=0,media=disk,format=raw,"
            "snapshot=on"
        ),
        "-nic", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-display", "curses,charset=CP437",
        "-no-reboot",
        "-no-shutdown",
    )


class TerminalScreenCapture(_hardened_qemu.TerminalScreenCapture):
    """Use the hardened 80x25 model with exact ordered GRUB markers."""

    @property
    def complete(self) -> bool:
        return len(self._markers) == len(BOOT_MARKERS)

    def _check_row(self, row: int) -> None:
        if self.complete:
            return
        expected = BOOT_MARKERS[len(self._markers)]
        if expected in "".join(self._screen[row]):
            self._markers.append(expected)


def capture_qemu_boot(
    qemu: QemuIdentity,
    namespace_tool: BoundExecutable,
    source_fd: int,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> BootCapture:
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be an integer from {MIN_TIMEOUT} to {MAX_TIMEOUT}")
    verify_qemu_unchanged(qemu)
    verify_executable_unchanged(namespace_tool)
    command = build_qemu_command(namespace_tool.fd, qemu.fd, source_fd)
    master_fd = slave_fd = -1
    process: subprocess.Popen[bytes] | None = None
    terminal = TerminalScreenCapture()
    diagnostic = bytearray()
    started = time.monotonic()
    deadline = started + timeout
    selector = selectors.DefaultSelector()
    complete = False
    try:
        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(
            slave_fd,
            _hardened_qemu.termios_tiocswinsz(),
            struct.pack("HHHH", 25, 80, 0, 0),
        )
        os.set_blocking(master_fd, False)
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(namespace_tool.fd, qemu.fd, source_fd),
            start_new_session=True,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH,
                "TERM": "xterm-256color",
            },
        )
        os.close(slave_fd)
        slave_fd = -1
        selector.register(master_fd, selectors.EVENT_READ, "terminal")
        if process.stderr is None:
            raise BootCertificationError("QEMU diagnostic pipe was not created")
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stderr, selectors.EVENT_READ, "diagnostic")
        while True:
            if terminal.complete:
                complete = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if process.poll() is not None and not selector.get_map():
                break
            for key, _mask in selector.select(min(remaining, 0.25)):
                try:
                    block = os.read(key.fd, 65_536)
                except OSError as error:
                    if error.errno == errno.EIO and key.data == "terminal":
                        block = b""
                    elif error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    else:
                        raise BootCertificationError(
                            f"Could not read QEMU {key.data} output: {error}"
                        ) from error
                if not block:
                    selector.unregister(key.fileobj)
                elif key.data == "terminal":
                    terminal.feed(block)
                elif len(diagnostic) < MAX_DIAGNOSTIC_BYTES:
                    available = MAX_DIAGNOSTIC_BYTES - len(diagnostic)
                    diagnostic.extend(block[:available])
        if not complete:
            missing = list(BOOT_MARKERS[len(terminal.markers):])
            reason = (
                "QEMU exited before certification"
                if process.poll() is not None else "QEMU boot timed out"
            )
            details = _hardened_qemu._bounded_diagnostic(diagnostic)
            suffix = f"; diagnostic: {details}" if details else ""
            raise BootCertificationError(
                f"{reason}; missing exact markers: {missing!r}{suffix}"
            )
        return BootCapture(
            terminal.markers,
            terminal.size,
            round(time.monotonic() - started, 3),
        )
    except OSError as error:
        raise BootCertificationError(f"Could not run qemu-system-x86_64: {error}") from error
    finally:
        selector.close()
        stop_error: BootCertificationError | None = None
        if process is not None:
            try:
                _hardened_qemu._stop_and_reap(process)
            except BootCertificationError as error:
                stop_error = error
            if process.stderr is not None:
                process.stderr.close()
        if master_fd >= 0:
            os.close(master_fd)
        if slave_fd >= 0:
            os.close(slave_fd)
        if stop_error is not None:
            raise stop_error


def _bundle_json(bundle: BoundBootBundle) -> dict[str, object]:
    return {
        "family": bundle.family,
        "version": bundle.version,
        "purpose": bundle.purpose,
        "license": bundle.license,
        "provenance_url": bundle.provenance_url,
        "artifacts": [
            {"name": item.name, "size": item.size, "sha256": item.sha256}
            for item in bundle.artifacts
        ],
    }


def certify_grub_rescue_boot(
    *,
    qemu_path: Path | None = None,
    unshare_path: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    cache_dir: Path | None = None,
) -> dict[str, object]:
    if os.geteuid() == 0:
        raise BootCertificationError("GRUB rescue certification refuses to run as root")
    with (
        resolve_qemu(qemu_path) as qemu,
        resolve_unshare(unshare_path) as namespace_tool,
        tempfile.TemporaryDirectory(prefix="isopropyl-grub-rescue-cert-") as temporary,
    ):
        qemu_version = query_qemu_version(qemu)
        image: SealedPreparedImage | None = None
        try:
            try:
                image, evidence = prepare_certification_pipeline(
                    Path(temporary), cache_dir=cache_dir,
                )
            except BootCertificationError:
                raise
            except (
                CatalogError,
                DependencyUnavailable,
                DownloadError,
                GrubRescueError,
            ) as error:
                raise BootCertificationError(
                    f"The GRUB rescue production pipeline failed safely: {error}"
                ) from error
            verify_sealed_prepared_image(image)
            verify_qemu_unchanged(qemu)
            verify_executable_unchanged(namespace_tool)
            capture_error: BaseException | None = None
            capture: BootCapture | None = None
            try:
                capture = capture_qemu_boot(
                    qemu, namespace_tool, image.fd, timeout=timeout,
                )
            except BaseException as error:
                capture_error = error
            verify_sealed_prepared_image(image)
            verify_qemu_unchanged(qemu)
            verify_executable_unchanged(namespace_tool)
            if capture_error is not None:
                raise capture_error
            assert capture is not None
            result = evidence.result
            return {
                "schema_version": 1,
                "certified": True,
                "profile": PROFILE_ID,
                "result_semantics": RESULT_SEMANTICS,
                "bootloader_bundle": _bundle_json(evidence.bundle),
                "provenance": {
                    "catalog_bundle_hashes_verified": True,
                    "source_reproduction_verified": False,
                    "source_reproduction_note": (
                        "This run verifies the exact pinned catalog bytes; it does not "
                        "rebuild GRUB 2.14 from upstream source."
                    ),
                },
                "construction": {
                    "production_planner": "build_grub_rescue_plan",
                    "production_builder": "GrubRescueBuilder.execute",
                    "staging_root_initially_empty": evidence.staging_root_initially_empty,
                    "build_workspace_initially_empty": evidence.build_workspace_initially_empty,
                    "plan_sha256": result.plan_sha256,
                    "private_plan_sha256": result.private_plan_sha256,
                    "unpatched_image_sha256": result.unpatched_image_sha256,
                    "final_image_sha256": result.final_image_sha256,
                    "final_fat_manifest_sha256": result.final_fat_manifest_sha256,
                    "boot_image_sha256": result.boot_image_sha256,
                    "bootstrap_sha256": result.bootstrap_sha256,
                    "final_mbr_sha256": result.final_mbr_sha256,
                    "core_sha256": result.core_sha256,
                    "core_offset": result.core_offset,
                    "core_size": result.core_size,
                    "core_padded_size": result.core_padded_size,
                    "embedding_gap_zero_verified": result.embedding_gap_zero_verified,
                    "files_verified": result.files_verified,
                    "directories_verified": result.directories_verified,
                    "bytes_verified": result.bytes_verified,
                },
                "layout": {
                    "sector_size": SECTOR_SIZE,
                    "partition_table": "MBR",
                    "partition_count": 1,
                    "partition_1_active": True,
                    "partition_1_type": "0x0c-fat32-lba",
                    "partition_1_start_sector": PARTITION_START_SECTOR,
                    "partition_1_sectors": evidence.partition_sectors,
                    "filesystem": "FAT32",
                    "disk_signature": result.disk_signature,
                    "volume_id": result.volume_id,
                    "filesystem_file_count": result.files_verified,
                    "filesystem_content_bytes": result.bytes_verified,
                },
                "prepared_image": {
                    "size": image.size,
                    "sha256": image.sha256,
                    "sealed_memfd": True,
                    "descriptor_access": "read-only",
                },
                "markers": list(capture.markers),
                "capture": {
                    "method": "qemu-curses-private-pty-80x25-screen",
                    "terminal_stream_bytes": capture.terminal_stream_bytes,
                    "elapsed_seconds": capture.elapsed_seconds,
                },
                "isolation": {
                    "acceleration": "tcg",
                    "firmware": "SeaBIOS",
                    "snapshot": True,
                    "source_read_only": True,
                    "source_sealed_memfd": True,
                    "user_namespace": True,
                    "network_namespace": "new-empty-namespace",
                    "guest_network": "none",
                    "attached_host_block_devices": [],
                    "unprivileged_process": True,
                    "qemu_executable_set_id": False,
                    "namespace_executable_set_id": False,
                    "qemu_seccomp": True,
                    "qemu_seccomp_policy": (
                        "on,obsolete=deny,spawn=deny,resourcecontrol=deny"
                    ),
                },
                "scope": {
                    "grub_version": GRUB_VERSION,
                    "source_reproduction_verified": False,
                    "bios_first_stage_core_and_rescue_prompt_certified": True,
                    "intentional_rescue_prompt_certified": True,
                    "normal_mode_or_menu_certified": False,
                    "kernel_or_operating_system_certified": False,
                    "uefi_certified": False,
                    "secure_boot_certified": False,
                    "physical_media_certified": False,
                    "privileged_device_transaction_certified": False,
                },
                "qemu": {
                    "executable": str(qemu.path),
                    "sha256": qemu.sha256,
                    "version": qemu_version,
                },
                "namespace_tool": {
                    "executable": str(namespace_tool.path),
                    "sha256": namespace_tool.sha256,
                    "arguments": [
                        "--user", "--map-current-user", "--net", "--",
                    ],
                },
            }
        finally:
            if image is not None:
                image.close()


def _timeout(value: str) -> int:
    try:
        timeout = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be from {MIN_TIMEOUT} to {MAX_TIMEOUT} seconds"
        )
    return timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="store_true",
        help=(
            "explicitly opt in to exact catalog download/cache access, private "
            "regular-file construction, and isolated networkless QEMU boot"
        ),
    )
    parser.add_argument("--qemu", type=Path, help="absolute qemu-system-x86_64 path")
    parser.add_argument("--unshare", type=Path, help="absolute unshare path")
    parser.add_argument("--timeout", type=_timeout, default=DEFAULT_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("certification is opt-in; pass --run to prepare and boot the image")
    try:
        observation = certify_grub_rescue_boot(
            qemu_path=args.qemu,
            unshare_path=args.unshare,
            timeout=args.timeout,
        )
    except (BootCertificationError, ValueError, OSError) as error:
        print(f"certification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
