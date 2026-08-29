from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unprivileged coordinator for the isolated restore-device helper."""

import logging
import os
import select
import socket
import stat
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass

from . import restore_device_helper as protocol


PKEXEC_PATH = "/usr/bin/pkexec"
HELPER_PATH = "/usr/libexec/isopropyl-restore-device-helper"
HELPER_SCRIPT_PATH = "/usr/libexec/isopropyl/restore_device_helper.py"
POLICY_PATH = "/usr/share/polkit-1/actions/io.github.codebooker.isopropyl.restore-device.policy"
POLICY_ACTION = "io.github.codebooker.isopropyl.restore-device"
POLICY_DESCRIPTION = "Fully erase and format a removable USB or SD drive"
POLICY_MESSAGE = (
    "Authentication is required to fully erase, repartition, and format the "
    "selected removable USB or SD target"
)
STALL_TIMEOUT_SECONDS = 330.0
MAX_STDERR = 8192
_WAIT_POLL_SECONDS = 0.1
_PHASE_ORDER = ("zero-scan", "zero-readback")
_PHASE_INDEX = {phase: index for index, phase in enumerate(_PHASE_ORDER)}

logger = logging.getLogger("isopropyl")


class RestoreDeviceRunError(RuntimeError):
    pass


class RestoreDeviceRunCancelled(RestoreDeviceRunError):
    pass


class RestoreDeviceHelperUnavailable(RestoreDeviceRunError):
    pass


@dataclass(frozen=True)
class RestoreDeviceInstallation:
    pkexec: str
    helper: str
    script: str
    policy: str


@dataclass(frozen=True)
class RestoreDeviceRunResult:
    request_id: bytes
    target_major_minor: str
    partition_major_minor: str
    disk_sequence: int
    capacity: int
    partition_start_sector: int
    partition_sector_count: int
    scanned_bytes: int
    written_bytes: int
    skipped_bytes: int
    verified_bytes: int


def _trusted_file(path: str, *, executable: bool, setuid: bool = False) -> None:
    try:
        status = os.lstat(path)
    except OSError as error:
        raise RestoreDeviceHelperUnavailable(f"Missing restore integration: {path}") from error
    required = 0o500 if executable else 0o400
    if (
        not os.path.isabs(path)
        or os.path.normpath(path) != path
        or os.path.realpath(path) != path
        or not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or stat.S_IMODE(status.st_mode) & required != required
        or (setuid and not status.st_mode & stat.S_ISUID)
    ):
        raise RestoreDeviceHelperUnavailable(f"Unsafe restore integration: {path}")
    parent = os.path.dirname(path)
    while parent != "/":
        try:
            parent_status = os.stat(parent, follow_symlinks=False)
        except OSError as error:
            raise RestoreDeviceHelperUnavailable(
                f"Missing restore integration parent: {parent}",
            ) from error
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != 0
            or parent_status.st_mode & 0o022
        ):
            raise RestoreDeviceHelperUnavailable(
                f"Unsafe restore integration parent: {parent}",
            )
        parent = os.path.dirname(parent)


def _policy(path: str, helper: str) -> None:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit policy is invalid") from error
    if root.tag != "policyconfig" or root.attrib:
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit root is not exact")
    children = list(root)
    if [node.tag for node in children] != ["vendor", "vendor_url", "icon_name", "action"]:
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit structure is ambiguous")
    for node, expected in zip(
        children[:3],
        (
            "ISOpropyl",
            "https://github.com/codebooker/isopropyl",
            "io.github.codebooker.isopropyl",
        ),
        strict=True,
    ):
        if node.attrib or list(node) or (node.text or "").strip() != expected:
            raise RestoreDeviceHelperUnavailable("The restore PolicyKit identity is not exact")

    action = children[3]
    if action.attrib != {"id": POLICY_ACTION}:
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit action is not exact")
    action_children = list(action)
    if [node.tag for node in action_children] != [
        "description", "message", "defaults", "annotate", "annotate",
    ]:
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit action is ambiguous")
    description, message, defaults, *annotations = action_children
    if (
        description.attrib
        or list(description)
        or (description.text or "").strip() != POLICY_DESCRIPTION
        or message.attrib
        or list(message)
        or (message.text or "").strip() != POLICY_MESSAGE
        or defaults.attrib
    ):
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit prompt is not exact")
    default_children = list(defaults)
    expected_permissions = (
        ("allow_any", "no"),
        ("allow_inactive", "no"),
        ("allow_active", "auth_admin"),
    )
    if len(default_children) != len(expected_permissions) or any(
        node.tag != tag
        or node.attrib
        or list(node)
        or (node.text or "").strip() != value
        for node, (tag, value) in zip(default_children, expected_permissions, strict=True)
    ):
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit defaults are unsafe")
    expected_annotations = (
        ("org.freedesktop.policykit.exec.path", helper),
        ("org.freedesktop.policykit.exec.argv1", protocol.RESTORE_DEVICE_OPERATION),
    )
    if any(
        node.attrib != {"key": key}
        or list(node)
        or (node.text or "").strip() != value
        for node, (key, value) in zip(annotations, expected_annotations, strict=True)
    ):
        raise RestoreDeviceHelperUnavailable("The restore PolicyKit authorization is unsafe")


def resolve_restore_device_installation() -> RestoreDeviceInstallation:
    installation = RestoreDeviceInstallation(
        PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH, POLICY_PATH,
    )
    _trusted_file(installation.pkexec, executable=True, setuid=True)
    _trusted_file(installation.helper, executable=True)
    _trusted_file(installation.script, executable=False)
    _trusted_file(installation.policy, executable=False)
    _policy(installation.policy, installation.helper)
    return installation


class RestoreDeviceRunner:
    def __init__(
        self,
        *,
        installation: Callable[[], RestoreDeviceInstallation] = resolve_restore_device_installation,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        timeout: float = STALL_TIMEOUT_SECONDS,
    ) -> None:
        self._installation = installation
        self._popen = popen
        self._timeout = timeout
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._channel: socket.socket | None = None
        self._committed = False
        self._used = False
        self._state_lock = threading.Lock()
        self._diagnostic = bytearray()

    @property
    def committed(self) -> bool:
        with self._state_lock:
            return self._committed

    def cancel(self) -> None:
        with self._state_lock:
            self._cancelled.set()

    def _drain_stderr(self, process: subprocess.Popen[bytes]) -> None:
        stream = process.stderr
        if stream is None:
            return
        try:
            descriptor = stream.fileno()
        except (AttributeError, OSError):
            return
        while True:
            try:
                readable, _, _ = select.select((descriptor,), (), (), 0)
                if not readable:
                    return
                block = os.read(descriptor, 8192)
            except (BlockingIOError, OSError):
                return
            if not block:
                return
            remaining = MAX_STDERR + 1 - len(self._diagnostic)
            if remaining > 0:
                self._diagnostic.extend(block[:remaining])

    def _wait_committed_exit(self, process: subprocess.Popen[bytes]) -> int:
        """Retain ownership until root exits, without ever signalling it."""

        while process.poll() is None:
            self._drain_stderr(process)
            try:
                process.wait(timeout=_WAIT_POLL_SECONDS)
            except subprocess.TimeoutExpired:
                continue
        self._drain_stderr(process)
        return int(process.returncode)

    def _receive(self, channel: socket.socket, process: subprocess.Popen[bytes]) -> bytes:
        deadline = time.monotonic() + self._timeout
        while True:
            self._drain_stderr(process)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RestoreDeviceRunError("The privileged restore helper stopped responding")
            readable, _, _ = select.select((channel,), (), (), min(0.1, remaining))
            if readable:
                packet = channel.recv(protocol.MAX_PROTOCOL_PACKET + 1)
                if packet:
                    return packet
                raise RestoreDeviceRunError(
                    f"The privileged restore helper exited before a result ({process.poll()})",
                )
            if process.poll() is not None:
                raise RestoreDeviceRunError(
                    f"The privileged restore helper exited before a result ({process.returncode})",
                )

    @staticmethod
    def _decode(packet: bytes) -> tuple[object, ...]:
        try:
            return protocol.unpack_restore_server_packet(packet)
        except protocol.HelperError as error:
            raise RestoreDeviceRunError(str(error)) from error

    def run(
        self,
        request: protocol.RestoreDeviceRequest,
        *,
        confirm_commit: Callable[[], bool],
        progress: Callable[[str, int, int], None] = lambda _phase, _done, _total: None,
    ) -> RestoreDeviceRunResult:
        with self._state_lock:
            if self._used:
                raise RestoreDeviceRunError("A restore-device runner can only be used once")
            self._used = True
        if self._cancelled.is_set():
            raise RestoreDeviceRunCancelled("Restore cancelled before helper launch")
        packet = protocol.pack_restore_device_request(request)
        installation = self._installation()
        parent, child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
        )
        process: subprocess.Popen[bytes] | None = None
        prepared_seen = False
        phase_index = -1
        phase_progress: dict[str, int] = {}
        try:
            process = self._popen(
                [
                    installation.pkexec,
                    "--disable-internal-agent",
                    installation.helper,
                    protocol.RESTORE_DEVICE_OPERATION,
                ],
                stdin=child.fileno(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                shell=False,
            )
            self._process = process
            self._channel = parent
            child.close()
            if self._decode(self._receive(parent, process)) != ("ready",):
                raise RestoreDeviceRunError("The privileged restore handshake is invalid")
            if parent.send(packet) != len(packet):
                raise RestoreDeviceRunError("The restore request packet was only partly sent")
            while True:
                decoded = self._decode(self._receive(parent, process))
                if decoded[0] == "prepared":
                    if (
                        prepared_seen
                        or self.committed
                        or decoded[1] != request.request_id
                        or decoded[2] != request.plan_sha256
                    ):
                        raise RestoreDeviceRunError("The privileged restore PREPARED boundary is invalid")
                    prepared_seen = True
                    confirmed = confirm_commit() is True
                    with self._state_lock:
                        commit = confirmed and not self._cancelled.is_set()
                        decision = protocol.pack_restore_control(
                            request.request_id,
                            request.plan_sha256,
                            commit=commit,
                        )
                        if commit:
                            # From this point onward COMMIT may escape into the
                            # kernel even if send() raises asynchronously after
                            # delivery.  Never roll this conservative state
                            # back: all exception cleanup must be no-signal.
                            self._committed = True
                        if parent.send(decision) != len(decision):
                            raise RestoreDeviceRunError(
                                "The restore decision packet was only partly sent",
                            )
                    if not commit:
                        raise RestoreDeviceRunCancelled("Restore cancelled before COMMIT")
                elif decoded[0] == "progress":
                    _kind, received_id, phase, done, total = decoded
                    index = _PHASE_INDEX.get(phase) if type(phase) is str else None
                    if (
                        received_id != request.request_id
                        or not prepared_seen
                        or not self.committed
                        or index is None
                        or total != request.expected_capacity
                        or index < phase_index
                        or index > phase_index + 1
                        or (index > phase_index and phase_index >= 0
                            and phase_progress[_PHASE_ORDER[phase_index]] != request.expected_capacity)
                        or done < phase_progress.get(phase, 0)
                    ):
                        raise RestoreDeviceRunError("The restore progress stream is invalid")
                    phase_index = index
                    phase_progress[phase] = done
                    try:
                        progress(phase, done, total)
                    except Exception:
                        logger.exception("Ignoring a restore-device progress callback failure")
                elif decoded[0] == "error":
                    _kind, received_id, _code, message = decoded
                    if received_id not in {request.request_id, b"\0" * 16}:
                        raise RestoreDeviceRunError("The restore error identifier is invalid")
                    raise RestoreDeviceRunError(message or "The privileged restore failed")
                elif decoded[0] == "result":
                    if (
                        not prepared_seen
                        or not self.committed
                        or phase_progress != {
                            phase: request.expected_capacity for phase in _PHASE_ORDER
                        }
                    ):
                        raise RestoreDeviceRunError("The restore helper returned before COMMIT")
                    result = self._validate_result(request, decoded)
                    if self._wait_committed_exit(process) != 0:
                        raise RestoreDeviceRunError("The restore helper exited unsuccessfully")
                    return result
                else:
                    raise RestoreDeviceRunError("The restore helper sent an unexpected packet")
        except BaseException:
            if process is not None and process.poll() is None:
                if self.committed:
                    # Never signal across the irreversible boundary. Closing
                    # the channel makes the helper's next bounded send fail;
                    # the root transaction then performs its own verified
                    # emergency cleanup before this coordinator reaps it.
                    parent.close()
                    self._wait_committed_exit(process)
                else:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            raise
        finally:
            parent.close()
            try:
                child.close()
            except OSError:
                pass
            self._process = None
            self._channel = None

    @staticmethod
    def _validate_result(
        request: protocol.RestoreDeviceRequest,
        packet: tuple[object, ...],
    ) -> RestoreDeviceRunResult:
        (
            _kind, request_id, parent_major, parent_minor, diskseq, capacity,
            scanned, written, skipped, verified, part_major, part_minor,
            start, count, plan_sha256,
        ) = packet
        major_minor = f"{parent_major}:{parent_minor}"
        if (
            request_id != request.request_id
            or major_minor != request.expected_major_minor
            or diskseq != request.expected_disk_sequence
            or capacity != request.expected_capacity
            or scanned != capacity
            or written + skipped != capacity
            or verified != capacity
            or start != request.partition_start_sector
            or count != request.partition_sector_count
            or plan_sha256 != request.plan_sha256
        ):
            raise RestoreDeviceRunError("The privileged restore receipt is incomplete or forged")
        return RestoreDeviceRunResult(
            request_id,
            major_minor,
            f"{part_major}:{part_minor}",
            diskseq,
            capacity,
            start,
            count,
            scanned,
            written,
            skipped,
            verified,
        )
