from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unprivileged coordinator for the one-shot Syslinux device helper.

The coordinator owns preparation, the explicit post-unmount state transition,
PolicyKit activation, the local fixed-binary protocol, and strict result
validation.  It never receives the anonymous image descriptor: the prepared
owner transfers a re-attested duplicate directly to the helper using
``SCM_RIGHTS``.  The GUI does not import or expose this backend yet; emulated
and physical boot certification remains a separate release gate.
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

from .syslinux_device import (
    ConfirmedSyslinuxDeviceWrite,
    ReadySyslinuxDeviceWrite,
    SyslinuxDevicePlanCancelled,
    SyslinuxDevicePlanError,
    SyslinuxDeviceWritePlan,
    authorize_unmounted_syslinux_device_write,
    validate_confirmed_syslinux_device_write,
    validate_ready_syslinux_device_write,
)
from .syslinux_device_helper import (
    HELPER_PROFILE,
    HelperRequestError,
    MAX_PROTOCOL_PACKET,
    OPERATION,
    pack_helper_control,
    pack_helper_request,
    unpack_server_packet,
)
from .syslinux_iso_fat32 import (
    PreparedSyslinuxIsoFat32,
    SyslinuxIsoFat32Error,
    SyslinuxIsoFat32Result,
    prepare_syslinux_iso_fat32,
)
from .writer import (
    WriterError,
    resolve_writer_tools,
    unmount_device,
)


logger = logging.getLogger("isopropyl")

PKEXEC_PATH = "/usr/bin/pkexec"
HELPER_PATH = "/usr/libexec/isopropyl-device-helper"
HELPER_SCRIPT_PATH = "/usr/libexec/isopropyl/syslinux_device_helper.py"
POLICY_PATH = "/usr/share/polkit-1/actions/io.github.codebooker.isopropyl.policy"
POLICY_ACTION = "io.github.codebooker.isopropyl.write-syslinux-image"
POLICY_DESCRIPTION = "Write a caller-supplied Syslinux image to removable media"
POLICY_MESSAGE = (
    "Authentication is required to overwrite the selected removable drive "
    "with caller-supplied image data"
)
MAX_DIAGNOSTIC_BYTES = 8 * 1024
HELPER_STALL_TIMEOUT_SECONDS = 300.0
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAJOR_MINOR = re.compile(r"\d+:\d+\Z")
_PHASE_ORDER = {
    "source-validation": 0,
    "writing": 1,
    "preactivation-readback": 2,
    "readback": 3,
}

Progress = Callable[[str, str, int, int], None]


class SyslinuxDeviceRunError(RuntimeError):
    """The Syslinux device transaction did not produce a verified result."""


class SyslinuxDeviceRunCancelled(SyslinuxDeviceRunError):
    """The transaction was cancelled before mutation began."""


class SyslinuxDeviceHelperUnavailable(SyslinuxDeviceRunError):
    """The fixed native-host helper installation is absent or unsafe."""


@dataclass(frozen=True)
class HelperInstallation:
    pkexec: str
    helper: str
    script: str
    policy: str


@dataclass(frozen=True)
class SyslinuxDeviceWriteResult:
    plan_sha256: str
    ready_sha256: str
    request_id: str
    target_path: str
    major_minor: str
    disk_sequence: int
    image_size: int
    image_sha256: str
    disk_signature: int
    volume_id: int
    logical_sector_size: int
    helper_profile: str
    exclusive_open: bool
    cache_invalidated: bool
    mandatory_readback: bool
    cancellation_deferred: bool


def _trusted_file(path: str, *, executable: bool, setuid: bool = False) -> None:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise SyslinuxDeviceHelperUnavailable("A privileged helper path is not canonical")
    try:
        status = os.lstat(path)
    except OSError as error:
        raise SyslinuxDeviceHelperUnavailable(
            f"Required host integration is not installed: {path}",
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
        raise SyslinuxDeviceHelperUnavailable(
            f"Privileged host integration has unsafe ownership or mode: {path}",
        )


def _trusted_parents(path: str) -> None:
    parent = os.path.dirname(path)
    while parent != "/":
        try:
            status = os.lstat(parent)
        except OSError as error:
            raise SyslinuxDeviceHelperUnavailable(
                "A privileged helper parent directory is unavailable",
            ) from error
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != 0
            or status.st_mode & 0o022
        ):
            raise SyslinuxDeviceHelperUnavailable(
                f"A privileged helper parent directory is unsafe: {parent}",
            )
        if parent == "/usr":
            return
        parent = os.path.dirname(parent)
    raise SyslinuxDeviceHelperUnavailable(
        "Privileged host integration must be installed beneath /usr",
    )


def _validate_policy() -> None:
    _trusted_file(POLICY_PATH, executable=False)
    _trusted_parents(POLICY_PATH)
    try:
        root = ET.parse(POLICY_PATH).getroot()
    except (OSError, ET.ParseError) as error:
        raise SyslinuxDeviceHelperUnavailable("The PolicyKit action is malformed") from error
    actions = root.findall("action") if root.tag == "policyconfig" else []
    if len(actions) != 1 or actions[0].attrib != {"id": POLICY_ACTION}:
        raise SyslinuxDeviceHelperUnavailable("The PolicyKit action identity is invalid")
    action = actions[0]
    descriptions = action.findall("description")
    messages = action.findall("message")
    defaults_nodes = action.findall("defaults")
    annotations_nodes = action.findall("annotate")
    if (
        len(list(action)) != 5
        or len(descriptions) != 1
        or len(messages) != 1
        or len(defaults_nodes) != 1
        or len(annotations_nodes) != 2
    ):
        raise SyslinuxDeviceHelperUnavailable(
            "The PolicyKit action has ambiguous authorization structure",
        )
    description = descriptions[0]
    message = messages[0]
    if (
        description.attrib
        or list(description)
        or (description.text or "").strip() != POLICY_DESCRIPTION
        or message.attrib
        or list(message)
        or (message.text or "").strip() != POLICY_MESSAGE
    ):
        raise SyslinuxDeviceHelperUnavailable(
            "The PolicyKit authorization prompt is invalid",
        )
    defaults = defaults_nodes[0]
    default_children = list(defaults)
    if (
        defaults.attrib
        or len(default_children) != 3
        or {child.tag for child in default_children}
        != {"allow_any", "allow_inactive", "allow_active"}
        or any(child.attrib or list(child) for child in default_children)
    ):
        raise SyslinuxDeviceHelperUnavailable(
            "The PolicyKit action has ambiguous authorization defaults",
        )
    values = {child.tag: (child.text or "").strip() for child in default_children}
    if (
        any(set(item.attrib) != {"key"} or list(item) for item in annotations_nodes)
        or len({item.get("key") for item in annotations_nodes}) != 2
    ):
        raise SyslinuxDeviceHelperUnavailable(
            "The PolicyKit action has ambiguous executable annotations",
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
            "org.freedesktop.policykit.exec.argv1": OPERATION,
        }
    ):
        raise SyslinuxDeviceHelperUnavailable(
            "The PolicyKit action is broader than the Syslinux helper protocol",
        )


def resolve_syslinux_helper_installation() -> HelperInstallation:
    """Require the exact root-owned native-host integration; never use PATH."""

    if struct.calcsize("P") != 8:
        raise SyslinuxDeviceHelperUnavailable(
            "The Syslinux device helper requires 64-bit Linux userspace",
        )
    _trusted_file(PKEXEC_PATH, executable=True, setuid=True)
    _trusted_file(HELPER_PATH, executable=True)
    _trusted_file(HELPER_SCRIPT_PATH, executable=False)
    for path in (PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH):
        _trusted_parents(path)
    _validate_policy()
    return HelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )


def _bounded_diagnostic(value: bytes) -> str:
    if len(value) > MAX_DIAGNOSTIC_BYTES:
        raise SyslinuxDeviceRunError("The privileged helper produced too much diagnostic output")
    rendered = value.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return rendered[-4_096:] or "The privileged Syslinux device helper failed"


def _validate_prepared(
    plan: SyslinuxDeviceWritePlan,
    prepared: PreparedSyslinuxIsoFat32,
) -> SyslinuxIsoFat32Result:
    if type(prepared) is not PreparedSyslinuxIsoFat32:
        raise SyslinuxDeviceRunError("The composite builder returned an invalid image owner")
    result = prepared.result
    if (
        type(result) is not SyslinuxIsoFat32Result
        or result.plan_sha256 != plan.composite_plan.plan_sha256
        or result.private_plan_sha256 != plan.private_plan_sha256
        or result.version != plan.composite_plan.version
        or result.disk_signature != plan.disk_signature
        or result.volume_id != plan.volume_id
        or result.image_size != plan.image_size
        or type(result.final_image_sha256) is not str
        or _SHA256.fullmatch(result.final_image_sha256) is None
        or result.final_image_sha256 == result.unpatched_image_sha256
    ):
        raise SyslinuxDeviceRunError(
            "The prepared image does not match the confirmed target plan",
        )
    return result


class SyslinuxDeviceWriteRunner:
    """One-shot unprivileged owner of one helper-backed disk transaction."""

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

    @property
    def committed(self) -> bool:
        """Whether the helper has crossed the irreversible COMMIT boundary."""

        with self._process_lock:
            return self._commit_sent

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
            raise SyslinuxDeviceRunCancelled("The Syslinux device write was cancelled")

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
            logger.exception("Ignoring a Syslinux device progress callback failure")

    @staticmethod
    def _stop_and_reap(process: subprocess.Popen[bytes], *, safe_to_kill: bool) -> None:
        if process.poll() is not None:
            return
        if not safe_to_kill:
            threading.Thread(
                target=lambda: process.wait(),
                name="isopropyl-helper-reaper",
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
                    name="isopropyl-helper-reaper",
                    daemon=True,
                ).start()

    @staticmethod
    def _send_control(channel: socket.socket, request_id: bytes, *, commit: bool) -> None:
        try:
            decision = pack_helper_control(request_id, commit=commit)
            sent = channel.send(decision, socket.MSG_DONTWAIT)
        except (HelperRequestError, OSError) as error:
            label = "commit" if commit else "cancellation"
            raise SyslinuxDeviceRunError(
                f"Could not send the pre-mutation {label} decision",
            ) from error
        if sent != len(decision):
            raise SyslinuxDeviceRunError(
                "The pre-mutation control decision was not atomic",
            )

    def _decide_prepared(self, channel: socket.socket, request_id: bytes) -> None:
        """Linearize user cancellation against the irreversible COMMIT send."""

        with self._process_lock:
            if self._commit_sent or self._cancel_sent:
                raise SyslinuxDeviceRunError(
                    "The privileged helper requested a repeated commit decision",
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
                    raise SyslinuxDeviceRunError(
                        "The privileged helper returned invalid ancillary data",
                    )
                if len(packet) > MAX_PROTOCOL_PACKET:
                    raise SyslinuxDeviceRunError(
                        "The privileged helper returned an oversized packet",
                    )
                return packet or None
            if process.poll() is not None:
                return None
            if self._clock() >= deadline:
                if not request_sent:
                    self._stop_and_reap(process, safe_to_kill=True)
                    raise SyslinuxDeviceRunError(
                        "The privileged helper did not complete its handshake in time",
                    )
                if not self._commit_sent:
                    if self._cancelled.is_set():
                        raise SyslinuxDeviceRunCancelled(
                            "The Syslinux device write was cancelled before commit",
                        )
                    raise SyslinuxDeviceRunError(
                        "The privileged helper preflight stopped responding; no write commit "
                        "was sent",
                    )
                raise SyslinuxDeviceRunError(
                    "The privileged helper stopped reporting progress after commit; the "
                    "target state is unknown and recovery may still be completing",
                )
            # Before the request is transferred, killing a stuck authentication
            # process cannot interrupt target mutation.
            if self._cancelled.is_set() and not request_sent:
                self._stop_and_reap(process, safe_to_kill=True)

    @staticmethod
    def _decode_packet(packet: bytes) -> tuple[object, ...]:
        try:
            return unpack_server_packet(packet)
        except HelperRequestError as error:
            raise SyslinuxDeviceRunError(str(error)) from error

    def _invoke_helper(
        self,
        installation: HelperInstallation,
        plan: SyslinuxDeviceWritePlan,
        ready: ReadySyslinuxDeviceWrite,
        prepared: PreparedSyslinuxIsoFat32,
        prepared_result: SyslinuxIsoFat32Result,
        progress: Progress,
    ) -> SyslinuxDeviceWriteResult:
        request_id = self._request_id(16)
        if type(request_id) is not bytes or len(request_id) != 16:
            raise SyslinuxDeviceRunError("The transaction request identifier is invalid")
        self._active_request_id = request_id
        if _MAJOR_MINOR.fullmatch(ready.device.major_minor) is None:
            raise SyslinuxDeviceRunError("The post-unmount target identity is invalid")
        major_number, minor_number = (
            int(part) for part in ready.device.major_minor.split(":", 1)
        )
        packet = pack_helper_request(
            request_id,
            major_number,
            minor_number,
            ready.disk_sequence,
            plan.image_size,
            plan.logical_sector_size,
            plan.disk_signature,
            plan.volume_id,
            prepared_result.final_image_sha256,
        )
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
        try:
            try:
                process = self._popen(
                    [
                        installation.pkexec,
                        "--disable-internal-agent",
                        installation.helper,
                        OPERATION,
                    ],
                    stdin=child.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    shell=False,
                )
            except OSError as error:
                raise SyslinuxDeviceRunError(
                    "Could not start the privileged Syslinux device helper",
                ) from error
            self._set_process(process)
            child.close()
            child = None  # type: ignore[assignment]
            first = self._receive_packet(parent, process, request_sent=False)
            if first is None:
                raise SyslinuxDeviceRunError("The privileged helper exited before its handshake")
            if self._decode_packet(first) != ("ready",):
                raise SyslinuxDeviceRunError("The privileged helper handshake is invalid")
            self._check_cancelled()
            prepared._send_to_privileged_helper(
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
                    raise SyslinuxDeviceRunError("The privileged helper protocol is out of order")
                if decoded[0] == "prepared":
                    _, observed_id = decoded
                    if (
                        prepared_seen
                        or observed_id != request_id
                        or mutation_started
                        or phase_progress.get("source-validation") != plan.image_size
                    ):
                        raise SyslinuxDeviceRunError(
                            "The privileged helper pre-mutation boundary is invalid",
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
                        or phase_progress.get("source-validation") != plan.image_size
                    ):
                        raise SyslinuxDeviceRunError(
                            "The privileged helper mutation boundary is invalid",
                        )
                    mutation_started = True
                    continue
                if decoded[0] == "progress":
                    _, observed_id, phase, done, total = decoded
                    if observed_id != request_id or type(phase) is not str:
                        raise SyslinuxDeviceRunError("The helper progress belongs to another request")
                    index = _PHASE_ORDER.get(phase)
                    expected_total = (
                        plan.image_size - 512
                        if phase == "preactivation-readback"
                        else plan.image_size
                    )
                    if (
                        index is None
                        or index < phase_index
                        or (phase == "source-validation" and mutation_started)
                        or (phase != "source-validation" and not mutation_started)
                        or total != expected_total
                        or type(done) is not int
                        or done < phase_progress.get(phase, 0)
                        or done > total
                    ):
                        raise SyslinuxDeviceRunError("The helper progress sequence is invalid")
                    phase_index = index
                    phase_progress[phase] = done
                    self._safe_progress(progress, phase, "", done, total)
                    continue
                if decoded[0] != "success" or success is not None:
                    raise SyslinuxDeviceRunError("The helper terminal packet is invalid")
                success = decoded

            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._stop_and_reap(process, safe_to_kill=success is not None)
                raise SyslinuxDeviceRunError("The privileged helper did not exit after its result")
            if success is not None:
                readable, _, _ = select.select([parent], [], [], 0.5)
                if not readable:
                    raise SyslinuxDeviceRunError(
                        "The privileged helper left its protocol channel open",
                    )
                trailing, ancillary, flags, _address = parent.recvmsg(
                    MAX_PROTOCOL_PACKET + 1,
                    1,
                )
                if trailing or ancillary or flags:
                    raise SyslinuxDeviceRunError(
                        "The privileged helper emitted data after its terminal result",
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
                    raise SyslinuxDeviceRunCancelled(
                        "The Syslinux device write was cancelled before a verified result",
                    )
                raise SyslinuxDeviceRunError(_bounded_diagnostic(diagnostic))
            if diagnostic:
                raise SyslinuxDeviceRunError(
                    "The successful helper emitted unexpected diagnostic output",
                )
            (
                _,
                observed_id,
                observed_major,
                observed_minor,
                observed_disk_sequence,
                observed_size,
                observed_sector,
                observed_disk_signature,
                observed_volume_id,
                source_sha256,
                written_sha256,
                readback_sha256,
            ) = success
            if (
                observed_id != request_id
                or observed_major != major_number
                or observed_minor != minor_number
                or observed_disk_sequence != ready.disk_sequence
                or observed_size != plan.image_size
                or observed_sector != plan.logical_sector_size
                or observed_disk_signature != plan.disk_signature
                or observed_volume_id != plan.volume_id
                or source_sha256 != prepared_result.final_image_sha256
                or written_sha256 != source_sha256
                or readback_sha256 != source_sha256
                or not prepared_seen
                or not self._commit_sent
                or not mutation_started
                or set(phase_progress) != set(_PHASE_ORDER)
                or any(
                    phase_progress[phase]
                    != (plan.image_size - 512 if phase == "preactivation-readback" else plan.image_size)
                    for phase in _PHASE_ORDER
                )
            ):
                raise SyslinuxDeviceRunError(
                    "The privileged helper result does not match the authorized transaction",
                )
            return SyslinuxDeviceWriteResult(
                plan.plan_sha256,
                ready.ready_sha256,
                request_id.hex(),
                ready.device.path,
                ready.device.major_minor,
                ready.disk_sequence,
                plan.image_size,
                source_sha256,
                plan.disk_signature,
                plan.volume_id,
                plan.logical_sector_size,
                HELPER_PROFILE,
                True,
                True,
                True,
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
                # Never SIGKILL an unknown post-request state.  The helper
                # ignores ordinary termination only after mutation starts and
                # will finish its durability/read-back path independently.
                self._stop_and_reap(process, safe_to_kill=not request_sent)

    def run(
        self,
        plan: SyslinuxDeviceWritePlan,
        confirmation: ConfirmedSyslinuxDeviceWrite,
        progress: Progress = lambda _stage, _path, _done, _total: None,
    ) -> SyslinuxDeviceWriteResult:
        if self._used:
            raise SyslinuxDeviceRunError("A Syslinux device runner can only be used once")
        self._used = True
        self._check_cancelled()
        try:
            validate_confirmed_syslinux_device_write(
                plan,
                confirmation,
                cancel_check=self._check_cancelled,
            )
            installation = resolve_syslinux_helper_installation()
            tools = resolve_writer_tools(self._which)
            if tools.pkexec != installation.pkexec:
                raise SyslinuxDeviceHelperUnavailable(
                    "The writer and host helper resolved different PolicyKit executables",
                )
            self._check_cancelled()
            with prepare_syslinux_iso_fat32(
                plan.composite_plan,
                cancel_check=self._check_cancelled,
                progress=lambda stage, path, done, total: self._safe_progress(
                    progress,
                    stage,
                    path,
                    done,
                    total,
                ),
            ) as prepared:
                prepared_result = _validate_prepared(plan, prepared)
                validate_confirmed_syslinux_device_write(
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
                ready = authorize_unmounted_syslinux_device_write(
                    plan,
                    confirmation,
                    cancel_check=self._check_cancelled,
                )
                validate_ready_syslinux_device_write(
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
        except SyslinuxDeviceRunError:
            raise
        except SyslinuxDevicePlanCancelled as error:
            raise SyslinuxDeviceRunCancelled(str(error)) from error
        except (SyslinuxDevicePlanError, SyslinuxIsoFat32Error, WriterError) as error:
            raise SyslinuxDeviceRunError(str(error)) from error
