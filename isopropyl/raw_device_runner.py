from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Authenticated unprivileged coordinator for raw-device transactions.

The coordinator accepts one already-prepared anonymous raw snapshot, performs
the witnessed mounted -> unmounted target transition, and transfers the sole
re-attested descriptor duplicate over an authenticated local ``SOCK_SEQPACKET``
channel.  It has no pathname, pipe, or ``dd`` fallback.  Cancellation is
linearized against the helper's PREPARED boundary and is permanently deferred
after COMMIT.
"""

import logging
import os
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass

from .raw_device import (
    ConfirmedRawDeviceWrite,
    RawDevicePlanCancelled,
    RawDevicePlanError,
    RawDeviceWritePlan,
    ReadyRawDeviceWrite,
    authorize_unmounted_raw_device_write,
    raw_source_evidence_from_snapshot,
    validate_confirmed_raw_device_write,
    validate_ready_raw_device_write,
)
from .raw_snapshot import (
    PreparedRawSnapshot,
    RawSnapshotCancelled,
    RawSnapshotError,
    RawSnapshotResult,
    RawSnapshotState,
)
from .syslinux_device_helper import (
    MAX_PROTOCOL_PACKET,
    RAW_FRONT_GUARD_BYTES,
    RAW_HELPER_PROFILE,
    RAW_OPERATION,
    HelperRequestError,
    pack_raw_helper_control,
    pack_raw_helper_request,
    unpack_raw_server_packet,
)
from .writer import WriterError, WriterTools, unmount_device


logger = logging.getLogger("isopropyl")

PKEXEC_PATH = "/usr/bin/pkexec"
HELPER_PATH = "/usr/libexec/isopropyl-device-helper"
HELPER_SCRIPT_PATH = "/usr/libexec/isopropyl/syslinux_device_helper.py"
POLICY_PATH = (
    "/usr/share/polkit-1/actions/"
    "io.github.codebooker.isopropyl.raw-write.policy"
)
POLICY_ACTION = "io.github.codebooker.isopropyl.write-raw-image"
POLICY_DESCRIPTION = (
    "Write a caller-supplied raw image to a removable or external USB drive"
)
POLICY_MESSAGE = (
    "Authentication is required because a caller-supplied raw image will "
    "overwrite the selected removable or external USB target"
)
MAX_DIAGNOSTIC_BYTES = 8 * 1024
HELPER_STALL_TIMEOUT_SECONDS = 300.0
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_INERT_DD_PATH = "/nonexistent/isopropyl-raw-runner-has-no-dd"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAJOR_MINOR = re.compile(r"\d+:\d+\Z")
_PHASE_ORDER = {
    "source-validation": 0,
    "writing": 1,
    "preactivation-readback": 2,
    "readback": 3,
}

Progress = Callable[[str, str, int, int], None]


class RawDeviceRunError(RuntimeError):
    """The raw transaction did not produce its exact authorized result."""


class RawDeviceRunCancelled(RawDeviceRunError):
    """The raw transaction was cancelled before COMMIT won."""


class RawDeviceHelperUnavailable(RawDeviceRunError):
    """The exact raw native-host integration is absent or unsafe."""


@dataclass(frozen=True)
class RawHelperInstallation:
    pkexec: str
    helper: str
    script: str
    policy: str


@dataclass(frozen=True)
class RawDeviceWriteResult:
    plan_sha256: str
    ready_sha256: str
    raw_snapshot_plan_sha256: str
    request_id: str
    target_path: str
    major_minor: str
    disk_sequence: int
    target_capacity: int
    source_size: int
    source_sha256: str
    written_sha256: str
    readback_sha256: str
    front_guard_bytes: int
    target_tail_sanitized: bool
    logical_sector_size: int
    helper_profile: str
    exclusive_open: bool
    cache_invalidated: bool
    mandatory_preactivation_readback: bool
    final_verification: bool
    cancellation_deferred: bool


def _trusted_file(path: str, *, executable: bool, setuid: bool = False) -> None:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RawDeviceHelperUnavailable("A privileged helper path is not canonical")
    try:
        status = os.lstat(path)
    except OSError as error:
        raise RawDeviceHelperUnavailable(
            f"Required raw host integration is not installed: {path}",
        ) from error
    required = 0o500 if executable else 0o400
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or stat.S_IMODE(status.st_mode) & required != required
        or (setuid and not status.st_mode & stat.S_ISUID)
        or os.path.realpath(path) != path
    ):
        raise RawDeviceHelperUnavailable(
            f"Privileged raw host integration has unsafe ownership or mode: {path}",
        )


def _trusted_parents(path: str) -> None:
    parent = os.path.dirname(path)
    while parent != "/":
        try:
            status = os.lstat(parent)
        except OSError as error:
            raise RawDeviceHelperUnavailable(
                "A privileged helper parent directory is unavailable",
            ) from error
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != 0
            or status.st_mode & 0o022
        ):
            raise RawDeviceHelperUnavailable(
                f"A privileged helper parent directory is unsafe: {parent}",
            )
        if parent == "/usr":
            return
        parent = os.path.dirname(parent)
    raise RawDeviceHelperUnavailable(
        "Privileged raw host integration must be installed beneath /usr",
    )


def _validate_policy() -> None:
    _trusted_file(POLICY_PATH, executable=False)
    _trusted_parents(POLICY_PATH)
    try:
        root = ET.parse(POLICY_PATH).getroot()
    except (OSError, ET.ParseError) as error:
        raise RawDeviceHelperUnavailable("The raw PolicyKit action is malformed") from error
    actions = root.findall("action") if root.tag == "policyconfig" else []
    if (
        len(actions) != 1
        or actions[0].attrib != {"id": POLICY_ACTION}
    ):
        raise RawDeviceHelperUnavailable("The raw PolicyKit action identity is invalid")
    action = actions[0]
    description_nodes = action.findall("description")
    message_nodes = action.findall("message")
    defaults_nodes = action.findall("defaults")
    annotations_nodes = action.findall("annotate")
    if (
        len(description_nodes) != 1
        or len(message_nodes) != 1
        or len(defaults_nodes) != 1
        or len(annotations_nodes) != 2
        or len(list(action)) != 5
    ):
        raise RawDeviceHelperUnavailable(
            "The raw PolicyKit action has ambiguous authorization structure",
        )
    if (
        description_nodes[0].attrib
        or message_nodes[0].attrib
        or list(description_nodes[0])
        or list(message_nodes[0])
        or (description_nodes[0].text or "").strip() != POLICY_DESCRIPTION
        or (message_nodes[0].text or "").strip() != POLICY_MESSAGE
    ):
        raise RawDeviceHelperUnavailable(
            "The raw PolicyKit authorization prompt is misleading or invalid",
        )
    default_children = list(defaults_nodes[0])
    if (
        defaults_nodes[0].attrib
        or len(default_children) != 3
        or len({child.tag for child in default_children}) != 3
        or any(child.attrib or list(child) for child in default_children)
    ):
        raise RawDeviceHelperUnavailable(
            "The raw PolicyKit action has ambiguous authorization defaults",
        )
    values = {child.tag: (child.text or "").strip() for child in default_children}
    if (
        len({item.get("key") for item in annotations_nodes}) != 2
        or any(
            item.attrib != {"key": item.get("key")} or list(item)
            for item in annotations_nodes
        )
    ):
        raise RawDeviceHelperUnavailable(
            "The raw PolicyKit action has ambiguous executable annotations",
        )
    annotations = {
        item.get("key"): (item.text or "").strip()
        for item in annotations_nodes
    }
    if (
        values != {
            "allow_any": "no",
            "allow_inactive": "no",
            "allow_active": "auth_admin",
        }
        or annotations != {
            "org.freedesktop.policykit.exec.path": HELPER_PATH,
            "org.freedesktop.policykit.exec.argv1": RAW_OPERATION,
        }
    ):
        raise RawDeviceHelperUnavailable(
            "The PolicyKit action is broader than the raw helper protocol",
        )


def resolve_raw_helper_installation() -> RawHelperInstallation:
    """Require the fixed root-owned raw integration; never search for a writer."""

    if struct.calcsize("P") != 8:
        raise RawDeviceHelperUnavailable(
            "The raw device helper requires 64-bit Linux userspace",
        )
    _trusted_file(PKEXEC_PATH, executable=True, setuid=True)
    _trusted_file(HELPER_PATH, executable=True)
    _trusted_file(HELPER_SCRIPT_PATH, executable=False)
    for path in (PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH):
        _trusted_parents(path)
    _validate_policy()
    return RawHelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )


def _resolve_unmount_tools(
    which: Callable[[str], str | None],
) -> WriterTools:
    """Resolve only the three tools reachable by the unmount workflow."""

    resolved: dict[str, str] = {}
    for name in ("pkexec", "udisksctl", "lsblk"):
        value = which(name)
        if type(value) is not str:
            raise RawDeviceHelperUnavailable(
                f"The raw unmount workflow requires trusted {name}",
            )
        normalized = os.path.normpath(value)
        if (
            not os.path.isabs(value)
            or normalized != value
            or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
            or os.path.basename(value) != name
        ):
            raise RawDeviceHelperUnavailable(
                f"Refusing untrusted raw unmount tool path: {value!r}",
            )
        resolved[name] = value
    return WriterTools(
        pkexec=resolved["pkexec"],
        dd=_INERT_DD_PATH,
        udisksctl=resolved["udisksctl"],
        lsblk=resolved["lsblk"],
    )


def _bounded_diagnostic(value: bytes) -> str:
    if len(value) > MAX_DIAGNOSTIC_BYTES:
        raise RawDeviceRunError(
            "The privileged raw helper produced too much diagnostic output",
        )
    rendered = value.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return rendered[-4_096:] or "The privileged raw device helper failed"


def _validate_prepared(
    plan: RawDeviceWritePlan,
    prepared: PreparedRawSnapshot,
) -> RawSnapshotResult:
    if type(prepared) is not PreparedRawSnapshot:
        raise RawDeviceRunError("An authentic prepared raw snapshot is required")
    result = prepared.result
    if type(result) is not RawSnapshotResult:
        raise RawDeviceRunError("The prepared raw snapshot result is invalid")
    try:
        evidence = raw_source_evidence_from_snapshot(prepared)
    except (AttributeError, RawDevicePlanError) as error:
        raise RawDeviceRunError(
            "The prepared raw snapshot has malformed source evidence",
        ) from error
    if (
        type(result.plan_sha256) is not str
        or _SHA256.fullmatch(result.plan_sha256) is None
        or result.plan_sha256 != plan.raw_snapshot_plan_sha256
        or evidence != plan.source_evidence
        or evidence.snapshot_plan_sha256 != plan.snapshot_plan_sha256
        or result.source_identity.selection_tuple
        != plan.original_source_identity
        or result.workspace_identity.device != plan.workspace_device
        or result.snapshot_identity.device != plan.workspace_device
        or result.snapshot_identity.size != plan.source_size
        or result.image_size != plan.source_size
        or result.image_sha256 != plan.source_sha256
        or result.fully_preallocated is not True
        or prepared.state is not RawSnapshotState.READY
        or result.image_size < 2 * 512
        or result.image_size % 512
    ):
        raise RawDeviceRunError(
            "The prepared raw snapshot does not match the confirmed target plan",
        )
    return result


class RawDeviceWriteRunner:
    """One-shot owner of one helper-backed raw disk transaction."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        which: Callable[[str], str | None] = lambda name: shutil.which(
            name,
            path="/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        block_stat: Callable[[str], os.stat_result] = os.stat,
        request_id: Callable[[int], bytes] = secrets.token_bytes,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._popen = popen
        self._runner = runner
        self._which = which
        self._block_stat = block_stat
        self._request_id = request_id
        self._clock = clock
        self._used = False
        self._cancelled = threading.Event()
        self._process_lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._request_sent = False
        self._commit_sent = False
        self._cancel_sent = False
        self._active_request_id = b""

    def _set_process(self, process: subprocess.Popen[bytes] | None) -> None:
        with self._process_lock:
            self._process = process

    def cancel(self) -> None:
        with self._process_lock:
            self._cancelled.set()
            process = self._process
            request_sent = self._request_sent
        if process is not None and process.poll() is None and not request_sent:
            try:
                process.terminate()
            except OSError:
                pass

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise RawDeviceRunCancelled("The raw device write was cancelled")

    @staticmethod
    def _safe_progress(
        callback: Progress,
        stage: str,
        path: str,
        done: int,
        total: int,
    ) -> None:
        try:
            callback(stage, path, done, total)
        except Exception:
            logger.exception("Ignoring a raw device progress callback failure")

    @staticmethod
    def _stop_and_reap(
        process: subprocess.Popen[bytes],
        *,
        safe_to_kill: bool,
    ) -> None:
        if process.poll() is not None:
            return
        if not safe_to_kill:
            threading.Thread(
                target=lambda: process.wait(),
                name="isopropyl-raw-helper-reaper",
                daemon=True,
            ).start()
            return
        try:
            process.terminate()
            process.wait(timeout=2)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                threading.Thread(
                    target=lambda: process.wait(),
                    name="isopropyl-raw-helper-reaper",
                    daemon=True,
                ).start()

    @staticmethod
    def _send_control(
        channel: socket.socket,
        request_id: bytes,
        *,
        commit: bool,
    ) -> None:
        try:
            decision = pack_raw_helper_control(request_id, commit=commit)
            sent = channel.send(decision, socket.MSG_DONTWAIT)
        except (HelperRequestError, OSError) as error:
            label = "commit" if commit else "cancellation"
            raise RawDeviceRunError(
                f"Could not send the pre-mutation raw {label} decision",
            ) from error
        if sent != len(decision):
            raise RawDeviceRunError(
                "The pre-mutation raw control decision was not atomic",
            )

    def _decide_prepared(self, channel: socket.socket, request_id: bytes) -> None:
        """Linearize user cancellation against the irreversible COMMIT send."""

        with self._process_lock:
            if self._commit_sent or self._cancel_sent:
                raise RawDeviceRunError(
                    "The privileged raw helper requested a repeated commit decision",
                )
            commit = not self._cancelled.is_set()
            self._send_control(channel, request_id, commit=commit)
            if commit:
                self._commit_sent = True
            else:
                self._cancel_sent = True

    def _receive_packet(
        self,
        channel: socket.socket,
        process: subprocess.Popen[bytes],
        *,
        request_sent: bool,
    ) -> bytes | None:
        deadline = self._clock() + HELPER_STALL_TIMEOUT_SECONDS
        while True:
            with self._process_lock:
                cancelled = self._cancelled.is_set()
                commit_sent = self._commit_sent
                cancel_sent = self._cancel_sent
            if cancelled and process.poll() is None:
                if not request_sent:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                elif not commit_sent and not cancel_sent:
                    with self._process_lock:
                        if not self._commit_sent and not self._cancel_sent:
                            self._send_control(
                                channel,
                                self._active_request_id,
                                commit=False,
                            )
                            self._cancel_sent = True
            readable, _, _ = select.select([channel], [], [], 0.1)
            if readable:
                packet, ancillary, flags, _address = channel.recvmsg(
                    MAX_PROTOCOL_PACKET + 1,
                    1,
                )
                if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise RawDeviceRunError(
                        "The privileged raw helper returned invalid ancillary data",
                    )
                if len(packet) > MAX_PROTOCOL_PACKET:
                    raise RawDeviceRunError(
                        "The privileged raw helper returned an oversized packet",
                    )
                return packet or None
            if process.poll() is not None:
                return None
            if self._clock() >= deadline:
                if not request_sent:
                    self._stop_and_reap(process, safe_to_kill=True)
                    raise RawDeviceRunError(
                        "The privileged raw helper did not complete its handshake in time",
                    )
                if not self._commit_sent:
                    if self._cancelled.is_set():
                        raise RawDeviceRunCancelled(
                            "The raw device write was cancelled before commit",
                        )
                    raise RawDeviceRunError(
                        "The privileged raw helper preflight stopped responding; "
                        "no write commit was sent",
                    )
                raise RawDeviceRunError(
                    "The privileged raw helper stopped reporting progress after "
                    "commit; the target state is unknown and recovery may still "
                    "be completing",
                )
            if self._cancelled.is_set() and not request_sent:
                self._stop_and_reap(process, safe_to_kill=True)

    @staticmethod
    def _decode_packet(packet: bytes) -> tuple[object, ...]:
        try:
            return unpack_raw_server_packet(packet)
        except HelperRequestError as error:
            raise RawDeviceRunError(str(error)) from error

    @staticmethod
    def _expected_phase_totals(
        plan: RawDeviceWritePlan,
    ) -> dict[str, int]:
        guard = min(RAW_FRONT_GUARD_BYTES, plan.source_size - 512)
        expected = {
            "source-validation": plan.source_size,
            "writing": plan.source_size,
            "preactivation-readback": plan.source_size - guard - 512,
        }
        if plan.final_verification_requested:
            expected["readback"] = plan.source_size
        return expected

    def _invoke_helper(
        self,
        installation: RawHelperInstallation,
        plan: RawDeviceWritePlan,
        ready: ReadyRawDeviceWrite,
        prepared: PreparedRawSnapshot,
        prepared_result: RawSnapshotResult,
        progress: Progress,
    ) -> RawDeviceWriteResult:
        request_id = self._request_id(16)
        if type(request_id) is not bytes or len(request_id) != 16:
            raise RawDeviceRunError("The raw transaction request identifier is invalid")
        self._active_request_id = request_id
        if _MAJOR_MINOR.fullmatch(ready.device.major_minor) is None:
            raise RawDeviceRunError("The post-unmount raw target identity is invalid")
        major_number, minor_number = (
            int(part) for part in ready.device.major_minor.split(":", 1)
        )
        try:
            packet = pack_raw_helper_request(
                request_id,
                major_number,
                minor_number,
                ready.disk_sequence,
                plan.target_capacity,
                plan.logical_sector_size,
                plan.source_size,
                prepared_result.image_sha256,
                final_verification=plan.final_verification_requested,
            )
        except HelperRequestError as error:
            raise RawDeviceRunError(str(error)) from error
        parent, child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
        )
        process: subprocess.Popen[bytes] | None = None
        request_sent = False
        prepared_seen = False
        mutation_started = False
        success: tuple[object, ...] | None = None
        phase_index = -1
        phase_progress: dict[str, int] = {}
        expected_totals = self._expected_phase_totals(plan)
        try:
            try:
                process = self._popen(
                    [
                        installation.pkexec,
                        "--disable-internal-agent",
                        installation.helper,
                        RAW_OPERATION,
                    ],
                    stdin=child.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    shell=False,
                )
            except OSError as error:
                raise RawDeviceRunError(
                    "Could not start the privileged raw device helper",
                ) from error
            self._set_process(process)
            child.close()
            child = None  # type: ignore[assignment]
            first = self._receive_packet(parent, process, request_sent=False)
            if first is None:
                raise RawDeviceRunError(
                    "The privileged raw helper exited before its handshake",
                )
            if self._decode_packet(first) != ("ready",):
                raise RawDeviceRunError("The privileged raw helper handshake is invalid")
            self._check_cancelled()
            prepared.transfer_to_helper(
                parent,
                packet,
                cancel_check=self._check_cancelled,
            )
            request_sent = True
            with self._process_lock:
                self._request_sent = True
            while success is None:
                response = self._receive_packet(
                    parent,
                    process,
                    request_sent=True,
                )
                if response is None:
                    break
                decoded = self._decode_packet(response)
                if not decoded or decoded[0] == "ready":
                    raise RawDeviceRunError(
                        "The privileged raw helper protocol is out of order",
                    )
                if decoded[0] == "prepared":
                    _, observed_id = decoded
                    if (
                        prepared_seen
                        or observed_id != request_id
                        or mutation_started
                        or phase_progress.get("source-validation")
                        != plan.source_size
                    ):
                        raise RawDeviceRunError(
                            "The privileged raw helper pre-mutation boundary is invalid",
                        )
                    prepared_seen = True
                    if not self._cancel_sent:
                        self._decide_prepared(parent, request_id)
                    continue
                if decoded[0] == "mutation-started":
                    _, observed_id = decoded
                    if (
                        mutation_started
                        or observed_id != request_id
                        or not prepared_seen
                        or not self._commit_sent
                        or phase_progress.get("source-validation")
                        != plan.source_size
                    ):
                        raise RawDeviceRunError(
                            "The privileged raw helper mutation boundary is invalid",
                        )
                    mutation_started = True
                    continue
                if decoded[0] == "progress":
                    _, observed_id, phase, done, total = decoded
                    if observed_id != request_id or type(phase) is not str:
                        raise RawDeviceRunError(
                            "The raw helper progress belongs to another request",
                        )
                    index = _PHASE_ORDER.get(phase)
                    if (
                        index is None
                        or phase not in expected_totals
                        or index < phase_index
                        or (phase == "source-validation" and mutation_started)
                        or (phase == "source-validation" and prepared_seen)
                        or (phase != "source-validation" and not mutation_started)
                        or total != expected_totals[phase]
                        or type(done) is not int
                        or (
                            phase in phase_progress
                            and done <= phase_progress[phase]
                        )
                        or done > total
                    ):
                        raise RawDeviceRunError(
                            "The raw helper progress sequence is invalid",
                        )
                    phase_index = index
                    phase_progress[phase] = done
                    self._safe_progress(progress, phase, "", done, total)
                    continue
                if decoded[0] != "success" or success is not None:
                    raise RawDeviceRunError("The raw helper terminal packet is invalid")
                success = decoded

            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._stop_and_reap(process, safe_to_kill=success is not None)
                raise RawDeviceRunError(
                    "The privileged raw helper did not exit after its result",
                )
            if success is not None:
                readable, _, _ = select.select([parent], [], [], 0.5)
                if not readable:
                    raise RawDeviceRunError(
                        "The privileged raw helper left its protocol channel open",
                    )
                trailing, ancillary, flags, _address = parent.recvmsg(
                    MAX_PROTOCOL_PACKET + 1,
                    1,
                )
                if trailing or ancillary or flags:
                    raise RawDeviceRunError(
                        "The privileged raw helper emitted data after its terminal result",
                    )
            diagnostic = b""
            if process.stderr is not None:
                diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
            if code or success is None:
                if (
                    self._cancelled.is_set()
                    and success is None
                    and not self._commit_sent
                    and not diagnostic
                ):
                    raise RawDeviceRunCancelled(
                        "The raw device write was cancelled before a verified result",
                    )
                raise RawDeviceRunError(_bounded_diagnostic(diagnostic))
            if diagnostic:
                raise RawDeviceRunError(
                    "The successful raw helper emitted unexpected diagnostic output",
                )
            (
                _,
                observed_id,
                observed_major,
                observed_minor,
                observed_disk_sequence,
                observed_target_size,
                observed_sector,
                observed_source_size,
                observed_guard_size,
                observed_tail_sanitized,
                observed_final_verification,
                source_sha256,
                written_sha256,
                readback_sha256,
            ) = success
            expected_guard = min(
                RAW_FRONT_GUARD_BYTES,
                plan.source_size - 512,
            )
            if (
                observed_id != request_id
                or observed_major != major_number
                or observed_minor != minor_number
                or observed_disk_sequence != ready.disk_sequence
                or observed_target_size != plan.target_capacity
                or observed_sector != plan.logical_sector_size
                or observed_source_size != plan.source_size
                or observed_guard_size != expected_guard
                or observed_tail_sanitized
                is not (plan.target_capacity != plan.source_size)
                or observed_final_verification
                is not plan.final_verification_requested
                or source_sha256 != prepared_result.image_sha256
                or written_sha256 != source_sha256
                or readback_sha256
                != (source_sha256 if plan.final_verification_requested else "")
                or not prepared_seen
                or not self._commit_sent
                or not mutation_started
                or set(phase_progress) != set(expected_totals)
                or any(
                    phase_progress[phase] != total
                    for phase, total in expected_totals.items()
                )
            ):
                raise RawDeviceRunError(
                    "The privileged raw helper result does not match the "
                    "authorized transaction",
                )
            return RawDeviceWriteResult(
                plan.plan_sha256,
                ready.ready_sha256,
                prepared_result.plan_sha256,
                request_id.hex(),
                ready.device.path,
                ready.device.major_minor,
                ready.disk_sequence,
                plan.target_capacity,
                plan.source_size,
                source_sha256,
                written_sha256,
                readback_sha256,
                observed_guard_size,
                observed_tail_sanitized,
                plan.logical_sector_size,
                RAW_HELPER_PROFILE,
                True,
                True,
                True,
                plan.final_verification_requested,
                self._cancelled.is_set(),
            )
        finally:
            self._set_process(None)
            try:
                parent.close()
            except OSError:
                pass
            if child is not None:
                try:
                    child.close()
                except OSError:
                    pass
            if process is not None and process.poll() is None:
                self._stop_and_reap(process, safe_to_kill=not request_sent)

    def run(
        self,
        plan: RawDeviceWritePlan,
        confirmation: ConfirmedRawDeviceWrite,
        prepared: PreparedRawSnapshot,
        progress: Progress = lambda _stage, _path, _done, _total: None,
    ) -> RawDeviceWriteResult:
        """Unmount, mint Ready, and consume one matching prepared snapshot."""

        if self._used:
            raise RawDeviceRunError("A raw device runner can only be used once")
        self._used = True
        self._check_cancelled()
        try:
            validate_confirmed_raw_device_write(
                plan,
                confirmation,
                cancel_check=self._check_cancelled,
            )
            installation = resolve_raw_helper_installation()
            tools = _resolve_unmount_tools(self._which)
            if tools.pkexec != installation.pkexec:
                raise RawDeviceHelperUnavailable(
                    "The writer and raw host helper resolved different PolicyKit "
                    "executables",
                )
            prepared_result = _validate_prepared(plan, prepared)
            self._check_cancelled()
            validate_confirmed_raw_device_write(
                plan,
                confirmation,
                cancel_check=self._check_cancelled,
            )
            unmount_device(
                plan.device,
                writable=True,
                tools=tools,
                runner=self._runner,
                stat_func=self._block_stat,
                cancel_check=self._check_cancelled,
            )
            ready = authorize_unmounted_raw_device_write(
                plan,
                confirmation,
                cancel_check=self._check_cancelled,
            )
            validate_ready_raw_device_write(
                plan,
                confirmation,
                ready,
                cancel_check=self._check_cancelled,
            )
            return self._invoke_helper(
                installation,
                plan,
                ready,
                prepared,
                prepared_result,
                progress,
            )
        except RawDeviceRunError:
            raise
        except RawDevicePlanCancelled as error:
            raise RawDeviceRunCancelled(str(error)) from error
        except RawSnapshotCancelled as error:
            raise RawDeviceRunCancelled(str(error)) from error
        except (RawDevicePlanError, RawSnapshotError, WriterError) as error:
            raise RawDeviceRunError(str(error)) from error
