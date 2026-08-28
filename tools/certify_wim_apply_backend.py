#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Opt-in, device-free certification of descriptor-native WIM-to-NTFS apply.

The tool creates a tiny WIM and a sparse regular-file NTFS image, passes both
as inherited descriptors to ISOpropyl's production certification backend, and
then verifies the applied probe file with ntfsls. It never discovers, opens, or
accepts a host block-device path and requires no root privileges or network.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.wim_apply_backend import (
    WIMLIB_IMAGEX_PATH,
    WimApplyBackendError,
    WimApplyCertificationPlan,
    apply_wim_to_certification_image,
    lock_down_wim_apply_process,
)

MKNTFS_PATH = "/usr/sbin/mkntfs"
NTFSLS_PATH = "/usr/bin/ntfsls"
NTFSCAT_PATH = "/usr/bin/ntfscat"
NTFSINFO_PATH = "/usr/bin/ntfsinfo"
TARGET_SIZE = 128 * 1024 * 1024
PARTITION_START_SECTOR = 796_672
PROBE_NAME = "isopropyl-wim-apply-probe.txt"
PROBE_BYTES = b"ISOpropyl descriptor-native WIM apply certification v1\n"
ENVIRONMENT = {
    "LC_ALL": "C",
    "LANG": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapabilityHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class _CapabilityData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


class CertificationError(RuntimeError):
    pass


def _drop_active_capability_sets() -> None:
    """Irreversibly clear this process's effective/permitted/inheritable sets."""

    libc = ctypes.CDLL(None, use_errno=True)
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapabilityData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        error = ctypes.get_errno()
        raise CertificationError("cannot read process capability sets") from OSError(
            error,
            os.strerror(error),
        )
    for item in data:
        item.effective = 0
        item.permitted = 0
        item.inheritable = 0
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        error = ctypes.get_errno()
        raise CertificationError("cannot clear process capability sets") from OSError(
            error,
            os.strerror(error),
        )


def _tool(path: str) -> dict[str, object]:
    try:
        status = os.lstat(path)
    except OSError as error:
        raise CertificationError(f"required tool is unavailable: {path}") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
        or not status.st_mode & 0o111
        or os.path.realpath(path) != path
    ):
        raise CertificationError(f"required tool is not trusted: {path}")
    try:
        file_capabilities = os.getxattr(
            path,
            "security.capability",
            follow_symlinks=False,
        )
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise CertificationError(
                f"cannot attest required tool capabilities: {path}",
            ) from error
        file_capabilities = b""
    if file_capabilities:
        raise CertificationError(f"required tool has file capabilities: {path}")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return {
        "path": path,
        "size": status.st_size,
        "sha256": digest.hexdigest(),
    }


def _run(
    argv: Sequence[str],
    *,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=ENVIRONMENT,
        close_fds=True,
        pass_fds=tuple(pass_fds),
        shell=False,
        timeout=120,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").replace("\0", "").strip()
        rendered = " ".join(argv)
        raise CertificationError(
            f"command failed ({rendered}): {detail[:1800] or 'no diagnostic'}",
        )
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _sha256_descriptor(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise CertificationError("the anonymous target ended during hashing")
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _process_privilege_state() -> dict[str, object]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise CertificationError("cannot inspect process capabilities") from error
    fields: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name in {"Uid", "CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd"}:
            if name in fields:
                raise CertificationError("process privilege state is ambiguous")
            fields[name] = value.strip()
    if set(fields) != {"Uid", "CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd"}:
        raise CertificationError("process privilege state is incomplete")
    try:
        uids = tuple(int(value, 10) for value in fields["Uid"].split())
        capabilities = {
            name: int(fields[name], 16)
            for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd")
        }
    except ValueError as error:
        raise CertificationError("process privilege state is malformed") from error
    if len(uids) != 4:
        raise CertificationError("process UID state is malformed")
    return {
        "uids": uids,
        "capabilities": capabilities,
    }


def _require_unprivileged_process(
    state: dict[str, object],
) -> tuple[tuple[int, int, int, int], dict[str, int]]:
    uids = state.get("uids")
    capabilities = state.get("capabilities")
    if (
        not isinstance(uids, tuple)
        or len(uids) != 4
        or any(type(uid) is not int for uid in uids)
        or not isinstance(capabilities, dict)
        or any(
            type(capabilities.get(name)) is not int
            for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd")
        )
    ):
        raise CertificationError("process privilege state is invalid")
    typed_uids = (uids[0], uids[1], uids[2], uids[3])
    typed_capabilities = {
        name: int(capabilities[name])
        for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd")
    }
    if any(uid == 0 for uid in typed_uids) or any(
        typed_capabilities[name] != 0
        for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")
    ):
        raise CertificationError(
            "certification requires non-root real/effective/saved/fs UIDs and no "
            "inheritable, permitted, effective, or ambient capabilities",
        )
    return typed_uids, typed_capabilities


def _anonymous_target(directory: str) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_TMPFILE"):
        try:
            return os.open(directory, flags | os.O_TMPFILE, 0o600)
        except OSError:
            pass
    descriptor, path = tempfile.mkstemp(prefix="target-", suffix=".img", dir=directory)
    try:
        os.chmod(path, 0o600)
        os.unlink(path)
        return descriptor
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def certify() -> dict[str, object]:
    _drop_active_capability_sets()
    privilege = _process_privilege_state()
    uids, capabilities = _require_unprivileged_process(privilege)
    lock_down_wim_apply_process()
    tools = {
        "wimlib_imagex": _tool(WIMLIB_IMAGEX_PATH),
        "mkntfs": _tool(MKNTFS_PATH),
        "ntfsls": _tool(NTFSLS_PATH),
        "ntfscat": _tool(NTFSCAT_PATH),
        "ntfsinfo": _tool(NTFSINFO_PATH),
    }
    version = _run((WIMLIB_IMAGEX_PATH, "--version")).stdout.decode(
        "utf-8",
        errors="strict",
    ).splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="isopropyl-wim-cert-") as temporary:
        os.chmod(temporary, 0o700)
        root = Path(temporary)
        source_tree = root / "source"
        source_tree.mkdir(mode=0o700)
        (source_tree / PROBE_NAME).write_bytes(PROBE_BYTES)
        wim = root / "source.wim"
        _run(
            (
                WIMLIB_IMAGEX_PATH,
                "capture",
                str(source_tree),
                str(wim),
                "ISOpropyl certification",
                "--compress=none",
                "--quiet",
            ),
        )
        target_descriptor = _anonymous_target(temporary)
        try:
            os.ftruncate(target_descriptor, TARGET_SIZE)
            os.fsync(target_descriptor)
            target_ref = f"/proc/self/fd/{target_descriptor}"
            target_fds = (target_descriptor,)
            _run(
                (
                    MKNTFS_PATH,
                    "-F",
                    "-Q",
                    "-s",
                    "512",
                    "-p",
                    str(PARTITION_START_SECTOR),
                    "-H",
                    "255",
                    "-S",
                    "63",
                    "-L",
                    "Windows",
                    target_ref,
                ),
                pass_fds=target_fds,
            )
            fresh_listing = _run(
                (NTFSLS_PATH, "-f", "-l", "-p", "/", target_ref),
                pass_fds=target_fds,
            ).stdout
            if fresh_listing.strip():
                raise CertificationError(
                    "the fresh NTFS image unexpectedly contains user files",
                )
            before_info = _run(
                (NTFSINFO_PATH, "-f", "-m", target_ref),
                pass_fds=target_fds,
            ).stdout
            for marker in (
                b"Volume Flags: 0x0000",
                b"Sector Size: 512",
                b"Cluster Size: 4096",
            ):
                if marker not in before_info:
                    raise CertificationError(
                        "the fresh NTFS metadata is not clean and canonical",
                    )
            volume_serial = struct.unpack(
                "<Q",
                os.pread(target_descriptor, 8, 72),
            )[0]
            plan = WimApplyCertificationPlan(
                source_size=wim.stat().st_size,
                source_sha256=_sha256(wim),
                image_index=1,
                target_size=TARGET_SIZE,
                fresh_target_sha256=_sha256_descriptor(
                    target_descriptor,
                    TARGET_SIZE,
                ),
                partition_start_sector=PARTITION_START_SECTOR,
                ntfs_volume_serial=volume_serial,
                temporary_directory=temporary,
            )
            source_descriptor = os.open(wim, os.O_RDONLY | os.O_CLOEXEC)
            try:
                result = apply_wim_to_certification_image(
                    plan,
                    source_descriptor,
                    target_descriptor,
                )
            finally:
                os.close(source_descriptor)
            listing = _run(
                (NTFSLS_PATH, "-f", "-l", "-p", "/", target_ref),
                pass_fds=target_fds,
            ).stdout
            lines = [
                line.strip()
                for line in listing.decode("utf-8", errors="strict").splitlines()
                if line.strip()
            ]
            expected_listing = re.compile(
                rf"^{len(PROBE_BYTES)}\s+.+\s+{re.escape(PROBE_NAME)}$",
            )
            if len(lines) != 1 or expected_listing.fullmatch(lines[0]) is None:
                raise CertificationError(
                    "the applied NTFS root listing is not the exact probe file",
                )
            applied = _run(
                (NTFSCAT_PATH, "-f", target_ref, PROBE_NAME),
                pass_fds=target_fds,
            ).stdout
            if applied != PROBE_BYTES:
                raise CertificationError(
                    "the applied probe file failed exact-byte read-back",
                )
            after_info = _run(
                (NTFSINFO_PATH, "-f", "-m", target_ref),
                pass_fds=target_fds,
            ).stdout
            for marker in (
                b"Volume Flags: 0x0000",
                b"Sector Size: 512",
                b"Cluster Size: 4096",
            ):
                if marker not in after_info:
                    raise CertificationError(
                        "the applied NTFS metadata is not clean and canonical",
                    )
        finally:
            os.close(target_descriptor)
        return {
            "profile": "isopropyl-wim-apply-regular-image-v1",
            "wimlib_version": version,
            "tools": tools,
            "source": {
                "size": result.source_size,
                "sha256": result.source_sha256,
                "image_index": result.image_index,
            },
            "target": {
                "kind": "sparse regular-file NTFS image",
                "size": result.target_size,
                "partition_start_sector": PARTITION_START_SECTOR,
                "volume_serial": f"{result.ntfs_volume_serial:016x}",
                "probe_name": PROBE_NAME,
                "probe_bytes": len(PROBE_BYTES),
            },
            "result": {
                "descriptor_only": result.descriptor_only,
                "source_write_excluded_by_kernel_lease": result.source_read_lease,
                "anonymous_unlinked_target": result.anonymous_target,
                "target_advisory_lock_held": result.target_advisory_lock,
                "descriptor_owner_nondumpable": True,
                "no_new_privileges": True,
                "missing_integrity_table_warning": result.missing_integrity_table,
                "applied_probe_verified_with_ntfsls": True,
                "applied_probe_exact_bytes_verified_with_ntfscat": True,
                "clean_ntfs_metadata_verified_before_and_after": True,
            },
            "scope": {
                "regular_ntfs_image_certified": True,
                "inherited_source_descriptor": True,
                "inherited_target_descriptor": True,
                "block_device_certified": False,
                "privileged_helper_certified": False,
                "windows_boot_certified": False,
                "physical_media_certified": False,
                "unprivileged_process": True,
                "uids": {
                    "real": uids[0],
                    "effective": uids[1],
                    "saved": uids[2],
                    "filesystem": uids[3],
                },
                "capabilities": {
                    name: f"0x{capabilities[name]:x}"
                    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd")
                },
                "concurrent_same_uid_adversary_certified": False,
            },
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="store_true",
        help="explicitly opt in to private regular-file WIM/NTFS construction",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("certification is opt-in; pass --run to create the private images")
    try:
        result = certify()
    except (CertificationError, WimApplyBackendError, OSError, ValueError) as error:
        print(f"certification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
