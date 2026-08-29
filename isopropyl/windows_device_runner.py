from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backend-only coordinator for authenticated Windows image device writes."""

import re
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .syslinux_device_helper import (
    WINDOWS_HELPER_PROFILE,
    WINDOWS_OPERATION,
    HelperRequestError,
    pack_windows_helper_control,
    pack_windows_helper_request,
    unpack_windows_server_packet,
)
from .syslinux_device_runner import (
    HELPER_PATH,
    HELPER_SCRIPT_PATH,
    PKEXEC_PATH,
    SyslinuxDeviceHelperUnavailable,
    SyslinuxDeviceRunCancelled,
    SyslinuxDeviceRunError,
    SyslinuxDeviceWriteRunner,
    _trusted_file,
    _trusted_parents,
)
from .windows_device import (
    ConfirmedWindowsDeviceWrite,
    ReadyWindowsDeviceWrite,
    WindowsDevicePlanCancelled,
    WindowsDevicePlanError,
    WindowsDeviceWritePlan,
    authorize_unmounted_windows_device_write,
    validate_confirmed_windows_device_write,
    validate_ready_windows_device_write,
)
from .windows_iso_fat32 import (
    PreparedWindowsIsoFat32,
    WindowsIsoFat32Error,
    WindowsIsoFat32Result,
    prepare_windows_iso_fat32,
)
from .writer import WriterError, resolve_writer_tools, unmount_device


POLICY_PATH = "/usr/share/polkit-1/actions/io.github.codebooker.isopropyl.windows-write.policy"
POLICY_ACTION = "io.github.codebooker.isopropyl.write-windows-image"
POLICY_DESCRIPTION = "Write a prepared Windows BIOS and UEFI image to removable media"
POLICY_MESSAGE = (
    "Authentication is required to overwrite the selected removable drive "
    "with the prepared Windows image"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class WindowsDeviceRunError(RuntimeError):
    pass


class WindowsDeviceRunCancelled(WindowsDeviceRunError):
    pass


class WindowsDeviceHelperUnavailable(WindowsDeviceRunError):
    pass


@dataclass(frozen=True)
class WindowsHelperInstallation:
    pkexec: str
    helper: str
    script: str
    policy: str


@dataclass(frozen=True)
class WindowsDeviceWriteResult:
    plan_sha256: str
    ready_sha256: str
    composite_plan_sha256: str
    pbr_plan_sha256: str
    request_id: str
    target_path: str
    major_minor: str
    disk_sequence: int
    image_size: int
    image_sha256: str
    disk_signature: int
    volume_id: int
    logical_sector_size: int
    image_profile: str
    helper_profile: str
    exclusive_open: bool
    cache_invalidated: bool
    mandatory_readback: bool
    cancellation_deferred: bool


def _validate_policy() -> None:
    try:
        _trusted_file(POLICY_PATH, executable=False)
        _trusted_parents(POLICY_PATH)
        root = ET.parse(POLICY_PATH).getroot()
    except (OSError, ET.ParseError, SyslinuxDeviceHelperUnavailable) as error:
        raise WindowsDeviceHelperUnavailable("The Windows PolicyKit action is unavailable") from error
    actions = root.findall("action") if root.tag == "policyconfig" else []
    if len(actions) != 1 or actions[0].attrib != {"id": POLICY_ACTION}:
        raise WindowsDeviceHelperUnavailable("The Windows PolicyKit action identity is invalid")
    action = actions[0]
    descriptions = action.findall("description")
    messages = action.findall("message")
    defaults = action.findall("defaults")
    annotations = action.findall("annotate")
    if (
        len(list(action)) != 5 or len(descriptions) != 1 or len(messages) != 1
        or len(defaults) != 1 or len(annotations) != 2
        or descriptions[0].attrib or list(descriptions[0])
        or messages[0].attrib or list(messages[0])
        or (descriptions[0].text or "").strip() != POLICY_DESCRIPTION
        or (messages[0].text or "").strip() != POLICY_MESSAGE
    ):
        raise WindowsDeviceHelperUnavailable("The Windows PolicyKit prompt is invalid")
    children = list(defaults[0])
    values = {item.tag: (item.text or "").strip() for item in children}
    annotation_values = {item.get("key"): (item.text or "").strip() for item in annotations}
    if (
        defaults[0].attrib or len(children) != 3
        or any(item.attrib or list(item) for item in children)
        or values != {
            "allow_any": "no", "allow_inactive": "no", "allow_active": "auth_admin",
        }
        or any(set(item.attrib) != {"key"} or list(item) for item in annotations)
        or annotation_values != {
            "org.freedesktop.policykit.exec.path": HELPER_PATH,
            "org.freedesktop.policykit.exec.argv1": WINDOWS_OPERATION,
        }
    ):
        raise WindowsDeviceHelperUnavailable("The Windows PolicyKit authority is too broad")


def resolve_windows_helper_installation() -> WindowsHelperInstallation:
    if struct.calcsize("P") != 8:
        raise WindowsDeviceHelperUnavailable("The Windows helper requires 64-bit Linux")
    try:
        _trusted_file(PKEXEC_PATH, executable=True, setuid=True)
        _trusted_file(HELPER_PATH, executable=True)
        _trusted_file(HELPER_SCRIPT_PATH, executable=False)
        for path in (PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH):
            _trusted_parents(path)
    except SyslinuxDeviceHelperUnavailable as error:
        raise WindowsDeviceHelperUnavailable(str(error)) from error
    _validate_policy()
    return WindowsHelperInstallation(PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH, POLICY_PATH)


def _validate_prepared(
    plan: WindowsDeviceWritePlan,
    prepared: PreparedWindowsIsoFat32,
) -> WindowsIsoFat32Result:
    if type(prepared) is not PreparedWindowsIsoFat32:
        raise WindowsDeviceRunError("The Windows builder returned an invalid image owner")
    result = prepared.result
    if (
        type(result) is not WindowsIsoFat32Result
        or result.plan_sha256 != plan.composite_plan_sha256
        or result.private_plan_sha256 != plan.private_plan_sha256
        or result.source_manifest_sha256 != plan.source_manifest_sha256
        or result.disk_signature != plan.disk_signature
        or result.volume_id != plan.volume_id
        or result.image_size != plan.image_size
        or type(result.pbr_plan_sha256) is not str
        or _SHA256.fullmatch(result.pbr_plan_sha256) is None
        or type(result.final_image_sha256) is not str
        or _SHA256.fullmatch(result.final_image_sha256) is None
        or result.final_image_sha256 == result.unpatched_image_sha256
    ):
        raise WindowsDeviceRunError("The prepared image does not match the Windows target plan")
    return result


class WindowsDeviceWriteRunner(SyslinuxDeviceWriteRunner):
    """One-shot Windows specialization of the reviewed descriptor broker."""

    _operation = WINDOWS_OPERATION

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise WindowsDeviceRunCancelled("The Windows device write was cancelled")

    @staticmethod
    def _send_control(channel, request_id: bytes, *, commit: bool) -> None:
        try:
            decision = pack_windows_helper_control(request_id, commit=commit)
            sent = channel.send(decision, socket.MSG_DONTWAIT)
        except (HelperRequestError, OSError) as error:
            raise WindowsDeviceRunError("Could not send the Windows commit decision") from error
        if sent != len(decision):
            raise WindowsDeviceRunError("The Windows commit decision was not atomic")

    @staticmethod
    def _decode_packet(packet: bytes) -> tuple[object, ...]:
        try:
            return unpack_windows_server_packet(packet)
        except HelperRequestError as error:
            raise WindowsDeviceRunError(str(error)) from error

    @staticmethod
    def _pack_request(*args: object) -> bytes:
        return pack_windows_helper_request(*args)  # type: ignore[arg-type]

    @staticmethod
    def _build_result(
        plan: WindowsDeviceWritePlan,
        ready: ReadyWindowsDeviceWrite,
        request_id: bytes,
        source_sha256: str,
        cancellation_deferred: bool,
    ) -> WindowsDeviceWriteResult:
        # The PBR witness is recovered from the prepared result by run() and
        # installed immediately after the inherited verified transaction.
        return WindowsDeviceWriteResult(
            plan.plan_sha256, ready.ready_sha256, plan.composite_plan_sha256, "",
            request_id.hex(), ready.device.path, ready.device.major_minor,
            ready.disk_sequence, plan.image_size, source_sha256,
            plan.disk_signature, plan.volume_id, plan.logical_sector_size,
            plan.image_profile, WINDOWS_HELPER_PROFILE, True, True, True,
            cancellation_deferred,
        )

    def run(
        self,
        plan: WindowsDeviceWritePlan,
        confirmation: ConfirmedWindowsDeviceWrite,
        progress=lambda _stage, _path, _done, _total: None,
    ) -> WindowsDeviceWriteResult:
        if self._used:
            raise WindowsDeviceRunError("A Windows device runner can only be used once")
        self._used = True
        self._check_cancelled()
        try:
            validate_confirmed_windows_device_write(
                plan, confirmation, cancel_check=self._check_cancelled,
            )
            installation = resolve_windows_helper_installation()
            tools = resolve_writer_tools(self._which)
            if tools.pkexec != installation.pkexec:
                raise WindowsDeviceHelperUnavailable("PolicyKit executable identity disagrees")
            with prepare_windows_iso_fat32(
                plan.composite_plan,
                cancel_check=self._check_cancelled,
                progress=lambda stage, path, done, total: self._safe_progress(
                    progress, stage, path, done, total,
                ),
            ) as prepared:
                prepared_result = _validate_prepared(plan, prepared)
                validate_confirmed_windows_device_write(
                    plan, confirmation, cancel_check=self._check_cancelled,
                )
                unmount_device(
                    plan.device, writable=True, tools=tools,
                    runner=self._runner, stat_func=self._block_stat,
                    cancel_check=self._check_cancelled,
                )
                ready = authorize_unmounted_windows_device_write(
                    plan, confirmation, cancel_check=self._check_cancelled,
                )
                validate_ready_windows_device_write(
                    plan, confirmation, ready, cancel_check=self._check_cancelled,
                )
                result = self._invoke_helper(
                    installation, plan, ready, prepared, prepared_result, progress,
                )
                if type(result) is not WindowsDeviceWriteResult:
                    raise WindowsDeviceRunError("The Windows helper result type is invalid")
                return WindowsDeviceWriteResult(
                    result.plan_sha256, result.ready_sha256,
                    result.composite_plan_sha256, prepared_result.pbr_plan_sha256,
                    result.request_id, result.target_path, result.major_minor,
                    result.disk_sequence, result.image_size, result.image_sha256,
                    result.disk_signature, result.volume_id,
                    result.logical_sector_size, result.image_profile,
                    result.helper_profile, result.exclusive_open,
                    result.cache_invalidated, result.mandatory_readback,
                    result.cancellation_deferred,
                )
        except WindowsDeviceRunError:
            raise
        except WindowsDevicePlanCancelled as error:
            raise WindowsDeviceRunCancelled(str(error)) from error
        except WindowsDevicePlanError as error:
            raise WindowsDeviceRunError(str(error)) from error
        except WindowsIsoFat32Error as error:
            raise WindowsDeviceRunError(str(error)) from error
        except WriterError as error:
            raise WindowsDeviceRunError(str(error)) from error
        except SyslinuxDeviceRunCancelled as error:
            raise WindowsDeviceRunCancelled(str(error)) from error
        except SyslinuxDeviceRunError as error:
            raise WindowsDeviceRunError(str(error)) from error
