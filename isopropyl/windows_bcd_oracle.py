# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Canonical evidence envelope for Windows-generated UEFI BCD stores.

This module does not edit a registry hive and does not certify an observation as
Windows-generated merely because it parses.  It gives the future Windows oracle
capture and Linux hivex validator one strict, bounded interchange format.  No
fixture is currently trusted by the application, and no caller may use this
module to remove the Windows To Go execution blockers.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from .windows_bcd import (
    BCD_BOOTMGR_DEVICE_ELEMENT,
    BCD_OSLOADER_DEVICE_ELEMENT,
    BCD_OSLOADER_OSDEVICE_ELEMENT,
    BCD_RECOVERY_ENABLED_ELEMENT,
    BcdError,
    decode_candidate_qualified_partition,
    encode_candidate_gpt_qualified_partition,
)

BCD_ORACLE_SCHEMA = "io.github.codebooker.isopropyl/windows-bcd-oracle/v1"
BCD_ORACLE_MAX_BYTES = 1024 * 1024
BCD_ORACLE_MAX_OBJECTS = 128
BCD_ORACLE_MAX_ELEMENTS = 2048
BCD_ORACLE_MAX_RAW_ELEMENT_BYTES = 4096
BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
BCD_ORACLE_ARCHITECTURE = "amd64"
BCD_ORACLE_FIRMWARE = "UEFI"
BCD_ORACLE_LOGICAL_SECTOR_SIZE = 512
BCD_ORACLE_ESP_TYPE_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
BCD_ORACLE_MSR_TYPE_GUID = uuid.UUID("e3c9e316-0b5c-4db8-817d-f92df00215ae")
BCD_ORACLE_WINDOWS_TYPE_GUID = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
BCD_ORACLE_ESP_START_LBA = 2048
BCD_ORACLE_ESP_SECTORS = 260 * 1024 * 1024 // BCD_ORACLE_LOGICAL_SECTOR_SIZE
BCD_ORACLE_MSR_SECTORS = 128 * 1024 * 1024 // BCD_ORACLE_LOGICAL_SECTOR_SIZE
BCD_REG_SZ = 1
BCD_REG_BINARY = 3
BCD_REG_DWORD = 4
BCD_REG_MULTI_SZ = 7

BCD_BOOT_MANAGER_ID = uuid.UUID("9dea862c-5cdd-4e70-acc1-f32b344d4795")
BCD_BOOT_MANAGER_OBJECT_TYPE = 0x10100002
BCD_WINDOWS_OS_LOADER_OBJECT_TYPE = 0x10200003
BCD_OBJECT_TYPE_INHERITED = 0x20000000
BCD_OBJECT_TYPE_MASK = 0xF0000000

BCD_LIBRARY_PATH_ELEMENT = 0x12000002
BCD_LIBRARY_INHERIT_ELEMENT = 0x14000006
BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT = 0x24000001
BCD_BOOTMGR_DEFAULT_ELEMENT = 0x23000003
BCD_OSLOADER_SYSTEM_ROOT_ELEMENT = 0x22000002

BCD_BOOT_MANAGER_PATH = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
BCD_OS_LOADER_PATH = "\\Windows\\system32\\winload.efi"
BCD_SYSTEM_ROOT = "\\Windows"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,9})(?:\.(?:0|[1-9][0-9]{0,9})){3}\Z")
_HEX8 = re.compile(r"[0-9a-f]{8}\Z")
_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
_VARIANTS = ("baseline", "disk-guid", "esp-guid", "windows-guid")


@dataclass(frozen=True)
class BcdOracleProvenance:
    profile: str
    host_windows_build: int
    source_windows_build: int
    architecture: str
    source_architecture: str
    source_iso_sha256: str
    source_wim_sha256: str
    source_wim_index: int
    source_edition: str
    bootex_selected: bool
    efi_boot_directory_precreated: bool
    bcdboot_version: str
    bcdedit_version: str
    bcdboot_path: str
    bcdedit_path: str
    bcdboot_executable_sha256: str
    bcdedit_executable_sha256: str
    template_sha256: str
    store_sha256: str
    capture_tool_sha256: str
    template_size: int
    store_size: int
    capture_tool_size: int
    bcdboot_argv: tuple[str, ...]
    bcdboot_exit_code: int
    bcdboot_stdout_sha256: str
    bcdboot_stderr_sha256: str
    bcdboot_stdout_hex: str
    bcdboot_stderr_hex: str
    bcdedit_set_recovery_argv: tuple[str, ...]
    bcdedit_set_recovery_exit_code: int
    bcdedit_set_recovery_stdout_sha256: str
    bcdedit_set_recovery_stderr_sha256: str
    bcdedit_set_recovery_stdout_hex: str
    bcdedit_set_recovery_stderr_hex: str
    bcdedit_argv: tuple[str, ...]
    bcdedit_exit_code: int
    bcdedit_stdout_sha256: str
    bcdedit_stderr_sha256: str
    bcdedit_stdout_hex: str
    bcdedit_stderr_hex: str


@dataclass(frozen=True)
class BcdOracleLayout:
    disk_guid: uuid.UUID
    esp_partition_guid: uuid.UUID
    msr_partition_guid: uuid.UUID
    windows_partition_guid: uuid.UUID
    disk_size_bytes: int
    esp_partition_number: int
    esp_start_lba: int
    esp_sector_count: int
    esp_type_guid: uuid.UUID
    msr_partition_number: int
    msr_start_lba: int
    msr_sector_count: int
    msr_type_guid: uuid.UUID
    windows_partition_number: int
    windows_start_lba: int
    windows_sector_count: int
    windows_type_guid: uuid.UUID
    esp_drive: str
    windows_drive: str
    disposable_virtual_disk_claim: bool
    fresh_store_before_bcdboot: bool
    logical_sector_size: int
    firmware: str


@dataclass(frozen=True)
class BcdOracleElement:
    element_type: int
    registry_type: int
    binary_hex: str | None = None
    string_value: str | None = None
    multi_string_value: tuple[str, ...] | None = None


@dataclass(frozen=True)
class BcdOracleObject:
    object_id: uuid.UUID
    object_type: int
    object_type_registry_type: int
    elements: tuple[BcdOracleElement, ...]


@dataclass(frozen=True)
class BcdOracleFixture:
    variant: str
    provenance: BcdOracleProvenance
    layout: BcdOracleLayout
    objects: tuple[BcdOracleObject, ...]
    root_key_name: str
    root_key_name_registry_type: int
    root_system: int | None
    root_system_registry_type: int | None
    root_treat_as_system: int | None
    root_treat_as_system_registry_type: int | None
    root_guid_cache_hex: str | None
    root_guid_cache_registry_type: int | None
    schema: str = BCD_ORACLE_SCHEMA
    windows_generated_claim: bool = True
    hive_bytes_included: bool = False
    authorizes_linux_writes: bool = False


def _uint(value: object, maximum: int, label: str, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < int(nonzero) or value > maximum:
        qualifier = "non-zero " if nonzero else ""
        raise BcdError(f"The BCD oracle {label} must be a {qualifier}unsigned integer")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise BcdError(f"The BCD oracle {label} must be a non-zero lowercase SHA-256")
    return value


def _version(value: object, label: str) -> str:
    if type(value) is not str or _VERSION.fullmatch(value) is None:
        raise BcdError(f"The BCD oracle {label} is not a canonical four-part version")
    if any(int(part) > 0xFFFFFFFF for part in value.split(".")):
        raise BcdError(f"The BCD oracle {label} contains an oversized component")
    return value


def _version_parts(value: str) -> tuple[int, int, int, int]:
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _guid(value: object, label: str) -> uuid.UUID:
    if type(value) is not uuid.UUID or value.int == 0:
        raise BcdError(f"The BCD oracle {label} must be a non-zero UUID")
    return value


def _hex(
    value: object,
    label: str,
    *,
    exact_bytes: int | None = None,
    nonempty: bool = False,
) -> str:
    if (
        type(value) is not str
        or _LOWER_HEX.fullmatch(value) is None
        or (nonempty and not value)
        or len(value) > BCD_ORACLE_MAX_RAW_ELEMENT_BYTES * 2
        or (exact_bytes is not None and len(value) != exact_bytes * 2)
    ):
        size = f" exactly {exact_bytes} bytes of" if exact_bytes is not None else " bounded"
        raise BcdError(f"The BCD oracle {label} must be{size} lowercase hexadecimal")
    return value


def _argv(value: object, label: str) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or not 1 <= len(value) <= 16
        or any(
            type(argument) is not str
            or not argument
            or len(argument) > 260
            or "\0" in argument
            or "\r" in argument
            or "\n" in argument
            for argument in value
        )
    ):
        raise BcdError(f"The BCD oracle {label} argv is invalid")
    return value


def _windows_executable_path(value: object, executable: str) -> str:
    path = _text(value, f"{executable} path", maximum=260)
    if (
        re.fullmatch(r"[A-Za-z]:\\[^\r\n\0]+", path) is None
        or any(part in {"", ".", ".."} for part in path[3:].split("\\"))
        or not path.casefold().endswith("\\" + executable.casefold())
    ):
        raise BcdError(f"The BCD oracle {executable} path is not a resolved Windows path")
    return path


def _command_output(value: object, digest: str, label: str) -> str:
    if (
        type(value) is not str
        or _LOWER_HEX.fullmatch(value) is None
        or len(value) > BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES * 2
    ):
        raise BcdError(f"The BCD oracle {label} is not bounded lowercase hexadecimal")
    if hashlib.sha256(bytes.fromhex(value)).hexdigest() != digest:
        raise BcdError(f"The BCD oracle {label} contradicts its SHA-256")
    return value


def _required_element(
    observed: dict[int, BcdOracleElement],
    element_type: int,
    label: str,
) -> BcdOracleElement:
    element = observed.get(element_type)
    if element is None:
        raise BcdError(f"The BCD oracle {label} element is absent")
    return element


def _registry_type_for_format(element_format: int) -> int:
    if element_format in {1, 5, 6, 7}:
        return BCD_REG_BINARY
    if element_format in {2, 3}:
        return BCD_REG_SZ
    if element_format == 4:
        return BCD_REG_MULTI_SZ
    raise BcdError("The BCD oracle element has an unknown data format")


def _bcd_guid_text(value: uuid.UUID) -> str:
    return "{" + str(value) + "}"


def _parse_bcd_guid_value(value: object, label: str) -> uuid.UUID:
    if type(value) is not str or len(value) != 38 or not value.startswith("{") or not value.endswith("}"):
        raise BcdError(f"The BCD oracle {label} is not a canonical braced UUID")
    try:
        parsed = uuid.UUID(value[1:-1])
    except ValueError as error:
        raise BcdError(f"The BCD oracle {label} is not a UUID") from error
    if parsed.int == 0 or value != _bcd_guid_text(parsed):
        raise BcdError(f"The BCD oracle {label} UUID is not canonical")
    return parsed


def _validate_provenance(provenance: BcdOracleProvenance) -> None:
    if type(provenance) is not BcdOracleProvenance:
        raise BcdError("A BcdOracleProvenance is required")
    if provenance.profile != "uefi-amd64-offline-no-bootex-v1":
        raise BcdError("The BCD oracle profile is unsupported")
    host_build = _uint(provenance.host_windows_build, 0xFFFFFFFF, "host build", nonzero=True)
    _uint(provenance.source_windows_build, 0xFFFFFFFF, "source build", nonzero=True)
    if provenance.architecture != BCD_ORACLE_ARCHITECTURE:
        raise BcdError("The first BCD oracle profile requires amd64")
    if provenance.source_architecture != BCD_ORACLE_ARCHITECTURE:
        raise BcdError("The BCD oracle source image must be amd64")
    _digest(provenance.source_iso_sha256, "source ISO digest")
    _digest(provenance.source_wim_sha256, "source WIM digest")
    _uint(provenance.source_wim_index, 1024, "source WIM index", nonzero=True)
    _text(provenance.source_edition, "source edition", maximum=256)
    if (
        provenance.bootex_selected is not False
        or provenance.efi_boot_directory_precreated is not True
    ):
        raise BcdError("The BCD oracle BCDBoot branch preconditions are outside profile")
    bcdboot_version = _version(provenance.bcdboot_version, "BCDBoot version")
    _version(provenance.bcdedit_version, "BCDEdit version")
    bcdboot_path = _windows_executable_path(provenance.bcdboot_path, "bcdboot.exe")
    bcdedit_path = _windows_executable_path(provenance.bcdedit_path, "bcdedit.exe")
    _digest(provenance.bcdboot_executable_sha256, "BCDBoot executable digest")
    _digest(provenance.bcdedit_executable_sha256, "BCDEdit executable digest")
    _digest(provenance.template_sha256, "BCD template digest")
    _digest(provenance.store_sha256, "BCD store digest")
    _digest(provenance.capture_tool_sha256, "capture-tool digest")
    _uint(provenance.template_size, 1 << 40, "BCD template size", nonzero=True)
    _uint(provenance.store_size, 1 << 40, "BCD store size", nonzero=True)
    _uint(provenance.capture_tool_size, 1 << 40, "capture-tool size", nonzero=True)
    for digest, label in (
        (provenance.bcdboot_stdout_sha256, "BCDBoot stdout digest"),
        (provenance.bcdboot_stderr_sha256, "BCDBoot stderr digest"),
        (provenance.bcdedit_set_recovery_stdout_sha256, "BCDEdit recovery stdout digest"),
        (provenance.bcdedit_set_recovery_stderr_sha256, "BCDEdit recovery stderr digest"),
        (provenance.bcdedit_stdout_sha256, "BCDEdit enum stdout digest"),
        (provenance.bcdedit_stderr_sha256, "BCDEdit enum stderr digest"),
    ):
        _digest(digest, label)
    for output, digest, label in (
        (provenance.bcdboot_stdout_hex, provenance.bcdboot_stdout_sha256, "BCDBoot stdout"),
        (provenance.bcdboot_stderr_hex, provenance.bcdboot_stderr_sha256, "BCDBoot stderr"),
        (
            provenance.bcdedit_set_recovery_stdout_hex,
            provenance.bcdedit_set_recovery_stdout_sha256,
            "BCDEdit recovery stdout",
        ),
        (
            provenance.bcdedit_set_recovery_stderr_hex,
            provenance.bcdedit_set_recovery_stderr_sha256,
            "BCDEdit recovery stderr",
        ),
        (provenance.bcdedit_stdout_hex, provenance.bcdedit_stdout_sha256, "BCDEdit enum stdout"),
        (provenance.bcdedit_stderr_hex, provenance.bcdedit_stderr_sha256, "BCDEdit enum stderr"),
    ):
        _command_output(output, digest, label)
    for exit_code, label in (
        (provenance.bcdboot_exit_code, "BCDBoot"),
        (provenance.bcdedit_set_recovery_exit_code, "BCDEdit recovery"),
        (provenance.bcdedit_exit_code, "BCDEdit enum"),
    ):
        if type(exit_code) is not int or exit_code != 0:
            raise BcdError(f"The BCD oracle {label} command did not succeed")
    if host_build < 26100 or _version_parts(bcdboot_version) < (10, 0, 26100, 8037):
        raise BcdError("The frozen /offline profile requires Windows build 26100.8037 or newer")
    bcdboot = _argv(provenance.bcdboot_argv, "BCDBoot")
    bcdedit_set_recovery = _argv(
        provenance.bcdedit_set_recovery_argv,
        "BCDEdit recovery",
    )
    bcdedit = _argv(provenance.bcdedit_argv, "BCDEdit")
    if bcdboot[0].casefold() != bcdboot_path.casefold() or tuple(
        argument.casefold() for argument in bcdboot[1:]
    ) != (
        "w:\\windows",
        "/v",
        "/offline",
        "/f",
        "uefi",
        "/s",
        "s:",
    ):
        raise BcdError("The BCD oracle BCDBoot command is outside the frozen profile")
    if bcdedit_set_recovery[0].casefold() != bcdedit_path.casefold() or tuple(
        argument.casefold() for argument in bcdedit_set_recovery[1:]
    ) != (
        "/store",
        "s:\\efi\\microsoft\\boot\\bcd",
        "/set",
        "{default}",
        "recoveryenabled",
        "no",
    ):
        raise BcdError("The BCD oracle recovery command is outside the frozen profile")
    if bcdedit[0].casefold() != bcdedit_path.casefold() or tuple(
        argument.casefold() for argument in bcdedit[1:]
    ) != (
        "/store",
        "s:\\efi\\microsoft\\boot\\bcd",
        "/enum",
        "all",
        "/v",
    ):
        raise BcdError("The BCD oracle BCDEdit command is outside the frozen profile")


def _validate_layout(layout: BcdOracleLayout) -> None:
    if type(layout) is not BcdOracleLayout:
        raise BcdError("A BcdOracleLayout is required")
    identities = (
        _guid(layout.disk_guid, "disk GUID"),
        _guid(layout.esp_partition_guid, "ESP partition GUID"),
        _guid(layout.msr_partition_guid, "MSR partition GUID"),
        _guid(layout.windows_partition_guid, "Windows partition GUID"),
    )
    if len(set(identities)) != len(identities):
        raise BcdError("BCD oracle disk and partition GUIDs must be distinct")
    if (
        layout.logical_sector_size != BCD_ORACLE_LOGICAL_SECTOR_SIZE
        or layout.firmware != BCD_ORACLE_FIRMWARE
    ):
        raise BcdError("The first BCD oracle profile requires UEFI and 512-byte sectors")
    disk_size = _uint(layout.disk_size_bytes, (1 << 64) - 1, "disk size", nonzero=True)
    if disk_size % BCD_ORACLE_LOGICAL_SECTOR_SIZE:
        raise BcdError("The BCD oracle disk size is not sector aligned")
    for value, label in (
        (layout.esp_partition_number, "ESP partition number"),
        (layout.esp_start_lba, "ESP start LBA"),
        (layout.esp_sector_count, "ESP sector count"),
        (layout.msr_partition_number, "MSR partition number"),
        (layout.msr_start_lba, "MSR start LBA"),
        (layout.msr_sector_count, "MSR sector count"),
        (layout.windows_partition_number, "Windows partition number"),
        (layout.windows_start_lba, "Windows start LBA"),
        (layout.windows_sector_count, "Windows sector count"),
    ):
        _uint(value, (1 << 64) - 1, label, nonzero=True)
    total_sectors = disk_size // BCD_ORACLE_LOGICAL_SECTOR_SIZE
    expected_aligned_end = ((total_sectors - 33) // 2048) * 2048
    expected_windows_sectors = expected_aligned_end - layout.windows_start_lba
    if (
        layout.esp_partition_number != 1
        or layout.msr_partition_number != 2
        or layout.windows_partition_number != 3
        or layout.esp_start_lba != BCD_ORACLE_ESP_START_LBA
        or layout.esp_sector_count != BCD_ORACLE_ESP_SECTORS
        or layout.msr_start_lba
        != BCD_ORACLE_ESP_START_LBA + BCD_ORACLE_ESP_SECTORS
        or layout.msr_sector_count != BCD_ORACLE_MSR_SECTORS
        or layout.windows_start_lba
        != layout.msr_start_lba + BCD_ORACLE_MSR_SECTORS
        or layout.windows_sector_count != expected_windows_sectors
        or layout.windows_sector_count <= 0
    ):
        raise BcdError("The BCD oracle layout is not the frozen Rufus-compatible GPT geometry")
    if (
        layout.esp_type_guid != BCD_ORACLE_ESP_TYPE_GUID
        or layout.msr_type_guid != BCD_ORACLE_MSR_TYPE_GUID
        or layout.windows_type_guid != BCD_ORACLE_WINDOWS_TYPE_GUID
    ):
        raise BcdError("The BCD oracle GPT partition types are outside the frozen profile")
    if (
        _text(layout.esp_drive, "ESP drive", maximum=2).casefold() != "s:"
        or _text(layout.windows_drive, "Windows drive", maximum=2).casefold() != "w:"
        or layout.disposable_virtual_disk_claim is not True
        or layout.fresh_store_before_bcdboot is not True
    ):
        raise BcdError("The BCD oracle drive binding or disposable-media precondition is invalid")


def _validate_element(element: BcdOracleElement) -> None:
    if type(element) is not BcdOracleElement:
        raise BcdError("A BcdOracleElement is required")
    _uint(element.element_type, 0xFFFFFFFF, "element type", nonzero=True)
    _uint(element.registry_type, 0xFFFFFFFF, "registry value type")
    expected_format = (element.element_type >> 24) & 0xF
    expected_registry_type = _registry_type_for_format(expected_format)
    registry_type = _uint(
        element.registry_type,
        0xFFFFFFFF,
        "element registry type",
    )
    if registry_type != expected_registry_type:
        raise BcdError("The BCD oracle registry kind contradicts the element format")
    present = sum(
        value is not None
        for value in (
            element.binary_hex,
            element.string_value,
            element.multi_string_value,
        )
    )
    if present != 1:
        raise BcdError("A BCD oracle element must carry exactly one typed value")
    if expected_format == 1:
        _hex(element.binary_hex, "device element", nonempty=True)
    elif expected_format == 2:
        _text(element.string_value, "string element", maximum=1024)
    elif expected_format == 3:
        _parse_bcd_guid_value(element.string_value, "object element")
    elif expected_format == 4:
        values = element.multi_string_value
        if (
            type(values) is not tuple
            or not 1 <= len(values) <= BCD_ORACLE_MAX_OBJECTS
        ):
            raise BcdError("The BCD oracle object-list element is invalid")
        parsed = tuple(_parse_bcd_guid_value(value, "object-list member") for value in values)
        if len(set(parsed)) != len(parsed):
            raise BcdError("The BCD oracle object-list element contains duplicates")
    elif expected_format == 5:
        payload = _hex(element.binary_hex, "integer element", nonempty=True)
        if not 1 <= len(payload) // 2 <= 8:
            raise BcdError("The BCD oracle integer element is not 1 to 8 bytes")
    elif expected_format == 6:
        if _hex(element.binary_hex, "boolean element", exact_bytes=1) not in {"00", "01"}:
            raise BcdError("The BCD oracle boolean element is not canonical")
    else:
        payload = _hex(element.binary_hex, "integer-list element", nonempty=True)
        if len(payload) % 16 != 0:
            raise BcdError("The BCD oracle integer-list element is not 64-bit aligned")


def _object_references(item: BcdOracleObject) -> tuple[uuid.UUID, ...]:
    derived_references: set[uuid.UUID] = set()
    for element in item.elements:
        element_format = (element.element_type >> 24) & 0xF
        if element_format == 3:
            derived_references.add(
                _parse_bcd_guid_value(element.string_value, "object reference"),
            )
        elif element_format == 4:
            derived_references.update(
                _parse_bcd_guid_value(value, "object-list reference")
                for value in element.multi_string_value or ()
            )
    return tuple(sorted(derived_references, key=lambda value: value.hex))


def _validate_object(item: BcdOracleObject) -> None:
    if type(item) is not BcdOracleObject:
        raise BcdError("A BcdOracleObject is required")
    _guid(item.object_id, "object ID")
    _uint(item.object_type, 0xFFFFFFFF, "object type", nonzero=True)
    if _uint(
        item.object_type_registry_type,
        0xFFFFFFFF,
        "object Type registry type",
    ) != BCD_REG_DWORD:
        raise BcdError("BCD object Description/Type must be captured as REG_DWORD")
    if type(item.elements) is not tuple or not 0 <= len(item.elements) <= 128:
        raise BcdError("A BCD oracle object has an invalid element count")
    for element in item.elements:
        _validate_element(element)
    element_types = tuple(element.element_type for element in item.elements)
    if element_types != tuple(sorted(set(element_types))):
        raise BcdError("BCD oracle object elements must be unique and sorted by type")
    references = _object_references(item)
    if item.object_id in references:
        raise BcdError("A BCD oracle object must not reference itself")


def validate_bcd_oracle_fixture(fixture: BcdOracleFixture) -> None:
    """Validate a bounded evidence claim without promoting it to trusted truth."""

    if type(fixture) is not BcdOracleFixture:
        raise BcdError("A BcdOracleFixture is required")
    if fixture.schema != BCD_ORACLE_SCHEMA or fixture.variant not in _VARIANTS:
        raise BcdError("The BCD oracle schema or differential variant is unsupported")
    if (
        fixture.windows_generated_claim is not True
        or fixture.hive_bytes_included is not False
        or fixture.authorizes_linux_writes is not False
    ):
        raise BcdError("The BCD oracle evidence scope was broadened")
    if (
        _uint(
            fixture.root_key_name_registry_type,
            0xFFFFFFFF,
            "root KeyName registry type",
        )
        != BCD_REG_SZ
        or _text(fixture.root_key_name, "root Description/KeyName", maximum=256)
        != fixture.root_key_name
    ):
        raise BcdError("The BCD oracle root KeyName registry evidence is invalid")
    if (fixture.root_system is None) != (fixture.root_system_registry_type is None):
        raise BcdError("The BCD oracle root System presence is inconsistent")
    if fixture.root_system is not None and (
        _uint(
            fixture.root_system_registry_type,
            0xFFFFFFFF,
            "root System registry type",
        )
        != BCD_REG_DWORD
        or _uint(fixture.root_system, 0xFFFFFFFF, "root Description/System") != 1
    ):
        raise BcdError("The BCD oracle root System registry evidence is invalid")
    if (fixture.root_treat_as_system is None) != (
        fixture.root_treat_as_system_registry_type is None
    ):
        raise BcdError("The BCD oracle root TreatAsSystem presence is inconsistent")
    if fixture.root_treat_as_system is not None and (
        _uint(
            fixture.root_treat_as_system_registry_type,
            0xFFFFFFFF,
            "root TreatAsSystem registry type",
        )
        != BCD_REG_DWORD
        or _uint(
            fixture.root_treat_as_system,
            0xFFFFFFFF,
            "root Description/TreatAsSystem",
        )
        != 1
    ):
        raise BcdError("The BCD oracle root TreatAsSystem registry evidence is invalid")
    if (fixture.root_guid_cache_hex is None) != (
        fixture.root_guid_cache_registry_type is None
    ):
        raise BcdError("The BCD oracle root GuidCache presence is inconsistent")
    if fixture.root_guid_cache_hex is not None and (
        _uint(
            fixture.root_guid_cache_registry_type,
            0xFFFFFFFF,
            "root GuidCache registry type",
        )
        != BCD_REG_BINARY
        or not _hex(
            fixture.root_guid_cache_hex,
            "root Description/GuidCache",
            nonempty=True,
        )
    ):
        raise BcdError("The BCD oracle root GuidCache registry evidence is invalid")
    _validate_provenance(fixture.provenance)
    _validate_layout(fixture.layout)
    if (
        type(fixture.objects) is not tuple
        or not 2 <= len(fixture.objects) <= BCD_ORACLE_MAX_OBJECTS
    ):
        raise BcdError("The BCD oracle object count is outside policy")
    for item in fixture.objects:
        _validate_object(item)
    object_ids = tuple(item.object_id for item in fixture.objects)
    if object_ids != tuple(sorted(set(object_ids), key=lambda value: value.hex)):
        raise BcdError("BCD oracle objects must have unique, sorted IDs")
    if sum(len(item.elements) for item in fixture.objects) > BCD_ORACLE_MAX_ELEMENTS:
        raise BcdError("The BCD oracle contains too many elements")
    by_id = {item.object_id: item for item in fixture.objects}
    for item in fixture.objects:
        if any(reference not in by_id for reference in _object_references(item)):
            raise BcdError("The BCD oracle contains a dangling object reference")

    manager_object = by_id.get(BCD_BOOT_MANAGER_ID)
    if manager_object is None or manager_object.object_type != BCD_BOOT_MANAGER_OBJECT_TYPE:
        raise BcdError("The BCD oracle Windows Boot Manager object is absent or mistyped")
    manager_elements = {element.element_type: element for element in manager_object.elements}
    for element_type, label in (
        (BCD_BOOTMGR_DEVICE_ELEMENT, "boot-manager device"),
        (BCD_LIBRARY_PATH_ELEMENT, "boot-manager path"),
        (BCD_BOOTMGR_DEFAULT_ELEMENT, "boot-manager default"),
        (BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT, "boot-manager display order"),
    ):
        _required_element(manager_elements, element_type, label)
    loader_id = _parse_bcd_guid_value(
        manager_elements[BCD_BOOTMGR_DEFAULT_ELEMENT].string_value,
        "default loader",
    )
    display_order = tuple(
        _parse_bcd_guid_value(value, "display-order loader")
        for value in (
            manager_elements[BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT].multi_string_value or ()
        )
    )
    if (
        display_order != (loader_id,)
        or loader_id not in _object_references(manager_object)
    ):
        raise BcdError("The BCD oracle default/display-order loader is ambiguous")
    loader_object = by_id.get(loader_id)
    if loader_object is None or loader_object.object_type != BCD_WINDOWS_OS_LOADER_OBJECT_TYPE:
        raise BcdError("The selected BCD OS loader object is absent or mistyped")
    loader_elements = {element.element_type: element for element in loader_object.elements}
    for element_type, label in (
        (BCD_OSLOADER_DEVICE_ELEMENT, "OS-loader device"),
        (BCD_LIBRARY_PATH_ELEMENT, "OS-loader path"),
        (BCD_LIBRARY_INHERIT_ELEMENT, "OS-loader inherit"),
        (BCD_RECOVERY_ENABLED_ELEMENT, "OS-loader recovery policy"),
        (BCD_OSLOADER_OSDEVICE_ELEMENT, "OS-loader OS device"),
        (BCD_OSLOADER_SYSTEM_ROOT_ELEMENT, "OS-loader system root"),
    ):
        _required_element(loader_elements, element_type, label)

    manager_device = _hex(
        manager_elements[BCD_BOOTMGR_DEVICE_ELEMENT].binary_hex,
        "boot-manager device",
        exact_bytes=88,
    )
    loader_device = _hex(
        loader_elements[BCD_OSLOADER_DEVICE_ELEMENT].binary_hex,
        "OS-loader device",
        exact_bytes=88,
    )
    loader_osdevice = _hex(
        loader_elements[BCD_OSLOADER_OSDEVICE_ELEMENT].binary_hex,
        "OS-loader OS device",
        exact_bytes=88,
    )
    expected_esp = encode_candidate_gpt_qualified_partition(
        fixture.layout.disk_guid,
        fixture.layout.esp_partition_guid,
    ).hex()
    expected_windows = encode_candidate_gpt_qualified_partition(
        fixture.layout.disk_guid,
        fixture.layout.windows_partition_guid,
    ).hex()
    if manager_device != expected_esp:
        raise BcdError("The Windows-generated boot-manager device contradicts GPT identity")
    if loader_device != expected_windows or loader_osdevice != expected_windows:
        raise BcdError("The Windows-generated OS-loader devices contradict GPT identity")
    for payload in (manager_device, loader_device, loader_osdevice):
        if decode_candidate_qualified_partition(bytes.fromhex(payload)).scheme.value != "gpt":
            raise BcdError("The BCD oracle device is not a GPT qualified partition")
    manager_path = _text(
        manager_elements[BCD_LIBRARY_PATH_ELEMENT].string_value,
        "boot-manager path",
        maximum=1024,
    )
    loader_path = _text(
        loader_elements[BCD_LIBRARY_PATH_ELEMENT].string_value,
        "OS-loader path",
        maximum=1024,
    )
    system_root = _text(
        loader_elements[BCD_OSLOADER_SYSTEM_ROOT_ELEMENT].string_value,
        "system root",
        maximum=1024,
    )
    if manager_path.casefold() != BCD_BOOT_MANAGER_PATH.casefold():
        raise BcdError("The BCD oracle boot-manager EFI path is unexpected")
    if loader_path.casefold() != BCD_OS_LOADER_PATH.casefold():
        raise BcdError("The BCD oracle OS-loader EFI path is unexpected")
    if system_root.casefold() != BCD_SYSTEM_ROOT.casefold():
        raise BcdError("The BCD oracle system root is unexpected")
    inherit = tuple(
        _parse_bcd_guid_value(value, "inherited object")
        for value in loader_elements[BCD_LIBRARY_INHERIT_ELEMENT].multi_string_value or ()
    )
    if (
        not inherit
        or any(reference not in _object_references(loader_object) for reference in inherit)
        or any(
            by_id[reference].object_type & BCD_OBJECT_TYPE_MASK != BCD_OBJECT_TYPE_INHERITED
            for reference in inherit
        )
    ):
        raise BcdError("The BCD oracle OS-loader inheritance graph is invalid")
    recovery_raw = loader_elements[BCD_RECOVERY_ENABLED_ELEMENT].binary_hex
    if recovery_raw != "00":
        raise BcdError("The BCD oracle must prove recoveryenabled is false")
    if len(_canonical_document_bytes(fixture)) > BCD_ORACLE_MAX_BYTES:
        raise BcdError("The BCD oracle canonical JSON exceeds the size policy")


def _selected_loader_id(fixture: BcdOracleFixture) -> uuid.UUID:
    manager = next(
        item for item in fixture.objects if item.object_id == BCD_BOOT_MANAGER_ID
    )
    elements = {element.element_type: element for element in manager.elements}
    return _parse_bcd_guid_value(
        elements[BCD_BOOTMGR_DEFAULT_ELEMENT].string_value,
        "default loader",
    )


def _provenance_cohort_key(provenance: BcdOracleProvenance) -> tuple[object, ...]:
    return (
        provenance.profile,
        provenance.host_windows_build,
        provenance.source_windows_build,
        provenance.architecture,
        provenance.source_architecture,
        provenance.source_iso_sha256,
        provenance.source_wim_sha256,
        provenance.source_wim_index,
        provenance.source_edition,
        provenance.bootex_selected,
        provenance.efi_boot_directory_precreated,
        provenance.bcdboot_version,
        provenance.bcdedit_version,
        provenance.bcdboot_path,
        provenance.bcdedit_path,
        provenance.bcdboot_executable_sha256,
        provenance.bcdedit_executable_sha256,
        provenance.template_sha256,
        provenance.capture_tool_sha256,
        provenance.template_size,
        provenance.capture_tool_size,
        provenance.bcdboot_argv,
        provenance.bcdboot_exit_code,
        provenance.bcdedit_set_recovery_argv,
        provenance.bcdedit_set_recovery_exit_code,
        provenance.bcdedit_argv,
        provenance.bcdedit_exit_code,
    )


def _layout_cohort_key(layout: BcdOracleLayout) -> tuple[object, ...]:
    return (
        layout.msr_partition_guid,
        layout.disk_size_bytes,
        layout.esp_partition_number,
        layout.esp_start_lba,
        layout.esp_sector_count,
        layout.esp_type_guid,
        layout.msr_partition_number,
        layout.msr_start_lba,
        layout.msr_sector_count,
        layout.msr_type_guid,
        layout.windows_partition_number,
        layout.windows_start_lba,
        layout.windows_sector_count,
        layout.windows_type_guid,
        layout.esp_drive.casefold(),
        layout.windows_drive.casefold(),
        layout.disposable_virtual_disk_claim,
        layout.fresh_store_before_bcdboot,
        layout.logical_sector_size,
        layout.firmware,
    )


def _normalized_semantic_projection(
    fixture: BcdOracleFixture,
    baseline_loader_id: uuid.UUID,
) -> tuple[tuple[object, ...], ...]:
    current_loader_id = _selected_loader_id(fixture)

    def normalize_guid(value: uuid.UUID) -> uuid.UUID:
        return baseline_loader_id if value == current_loader_id else value

    objects: list[tuple[object, ...]] = []
    normalized_ids: set[uuid.UUID] = set()
    for item in fixture.objects:
        normalized_id = normalize_guid(item.object_id)
        if normalized_id in normalized_ids:
            raise BcdError("BCD differential loader normalization collides with another object")
        normalized_ids.add(normalized_id)
        elements: list[tuple[object, ...]] = []
        for element in item.elements:
            element_format = (element.element_type >> 24) & 0xF
            if element_format == 1:
                is_manager_device = (
                    item.object_id == BCD_BOOT_MANAGER_ID
                    and element.element_type == BCD_BOOTMGR_DEVICE_ELEMENT
                )
                is_loader_device = (
                    item.object_id == current_loader_id
                    and element.element_type
                    in {BCD_OSLOADER_DEVICE_ELEMENT, BCD_OSLOADER_OSDEVICE_ELEMENT}
                )
                if is_manager_device or is_loader_device:
                    payload = bytes.fromhex(element.binary_hex or "")
                    decoded = decode_candidate_qualified_partition(payload)
                    if (
                        decoded.scheme.value != "gpt"
                        or decoded.disk_guid != fixture.layout.disk_guid
                    ):
                        raise BcdError(
                            "A differential BCD role device is not bound to the cohort GPT disk",
                        )
                    expected_partition = (
                        fixture.layout.esp_partition_guid
                        if is_manager_device
                        else fixture.layout.windows_partition_guid
                    )
                    if decoded.partition_guid != expected_partition or payload != (
                        encode_candidate_gpt_qualified_partition(
                            fixture.layout.disk_guid,
                            expected_partition,
                        )
                    ):
                        raise BcdError("A differential BCD role device is not byte-canonical")
                    role = "GPT:ESP" if is_manager_device else "GPT:Windows"
                    value: object = ("device", role)
                else:
                    payload = bytes.fromhex(element.binary_hex or "")
                    try:
                        decoded = decode_candidate_qualified_partition(payload)
                    except BcdError:
                        value = ("device-opaque", element.binary_hex)
                    else:
                        if (
                            decoded.scheme.value == "gpt"
                            and decoded.disk_guid == fixture.layout.disk_guid
                            and decoded.partition_guid
                            in {
                                fixture.layout.esp_partition_guid,
                                fixture.layout.windows_partition_guid,
                            }
                            and payload
                            == encode_candidate_gpt_qualified_partition(
                                fixture.layout.disk_guid,
                                decoded.partition_guid,
                            )
                        ):
                            role = (
                                "GPT:ESP"
                                if decoded.partition_guid
                                == fixture.layout.esp_partition_guid
                                else "GPT:Windows"
                            )
                            value = ("device", role)
                        else:
                            value = ("device-opaque", element.binary_hex)
            elif element_format == 3:
                value = (
                    "object",
                    normalize_guid(
                        _parse_bcd_guid_value(element.string_value, "object element"),
                    ).hex,
                )
            elif element_format == 4:
                value = (
                    "object-list",
                    tuple(
                        normalize_guid(
                            _parse_bcd_guid_value(member, "object-list member"),
                        ).hex
                        for member in element.multi_string_value or ()
                    ),
                )
            elif element.binary_hex is not None:
                value = ("binary", element.binary_hex)
            else:
                value = ("string", element.string_value)
            elements.append(
                (
                    element.element_type,
                    element.registry_type,
                    value,
                ),
            )
        objects.append(
            (
                normalized_id.hex,
                item.object_type,
                item.object_type_registry_type,
                tuple(elements),
            ),
        )
    return tuple(sorted(objects, key=lambda value: value[0]))


def validate_bcd_oracle_differential_set(
    fixtures: tuple[BcdOracleFixture, ...],
) -> None:
    """Prove a four-run, one-GUID-at-a-time Windows BCD differential cohort."""

    if type(fixtures) is not tuple or len(fixtures) != len(_VARIANTS):
        raise BcdError("A BCD oracle differential set requires exactly four fixtures")
    if tuple(fixture.variant for fixture in fixtures) != _VARIANTS:
        raise BcdError("BCD oracle differential fixtures are missing or out of order")
    for fixture in fixtures:
        validate_bcd_oracle_fixture(fixture)
    baseline, disk_variant, esp_variant, windows_variant = fixtures
    cohort_key = _provenance_cohort_key(baseline.provenance)
    if any(
        _provenance_cohort_key(fixture.provenance) != cohort_key
        for fixture in fixtures[1:]
    ):
        raise BcdError("BCD oracle differential provenance drifted between runs")
    if len({fixture.provenance.store_sha256 for fixture in fixtures}) != len(fixtures):
        raise BcdError("BCD oracle differential store digests must be pairwise distinct")
    scope = (
        baseline.schema,
        baseline.windows_generated_claim,
        baseline.hive_bytes_included,
        baseline.authorizes_linux_writes,
    )
    if any(
        (
            fixture.schema,
            fixture.windows_generated_claim,
            fixture.hive_bytes_included,
            fixture.authorizes_linux_writes,
        )
        != scope
        for fixture in fixtures[1:]
    ):
        raise BcdError("BCD oracle differential evidence scope drifted between runs")
    root_description = (
        baseline.root_key_name,
        baseline.root_key_name_registry_type,
        baseline.root_system,
        baseline.root_system_registry_type,
        baseline.root_treat_as_system,
        baseline.root_treat_as_system_registry_type,
        baseline.root_guid_cache_hex,
        baseline.root_guid_cache_registry_type,
    )
    if any(
        (
            fixture.root_key_name,
            fixture.root_key_name_registry_type,
            fixture.root_system,
            fixture.root_system_registry_type,
            fixture.root_treat_as_system,
            fixture.root_treat_as_system_registry_type,
            fixture.root_guid_cache_hex,
            fixture.root_guid_cache_registry_type,
        )
        != root_description
        for fixture in fixtures[1:]
    ):
        raise BcdError("BCD oracle differential root metadata drifted between runs")
    if any(
        _layout_cohort_key(fixture.layout) != _layout_cohort_key(baseline.layout)
        for fixture in fixtures[1:]
    ):
        raise BcdError("BCD oracle differential platform profile drifted between runs")
    baseline_ids = (
        baseline.layout.disk_guid,
        baseline.layout.esp_partition_guid,
        baseline.layout.windows_partition_guid,
    )
    disk_ids = (
        disk_variant.layout.disk_guid,
        disk_variant.layout.esp_partition_guid,
        disk_variant.layout.windows_partition_guid,
    )
    esp_ids = (
        esp_variant.layout.disk_guid,
        esp_variant.layout.esp_partition_guid,
        esp_variant.layout.windows_partition_guid,
    )
    windows_ids = (
        windows_variant.layout.disk_guid,
        windows_variant.layout.esp_partition_guid,
        windows_variant.layout.windows_partition_guid,
    )
    if (
        disk_ids[1:] != baseline_ids[1:]
        or disk_ids[0] == baseline_ids[0]
        or (esp_ids[0], esp_ids[2]) != (baseline_ids[0], baseline_ids[2])
        or esp_ids[1] == baseline_ids[1]
        or windows_ids[:2] != baseline_ids[:2]
        or windows_ids[2] == baseline_ids[2]
    ):
        raise BcdError("BCD oracle differential layouts are not one-factor mutations")
    introduced_ids = {
        *baseline_ids,
        disk_ids[0],
        esp_ids[1],
        windows_ids[2],
    }
    if len(introduced_ids) != 6:
        raise BcdError("BCD oracle differential GUID identities collide")
    baseline_loader_id = _selected_loader_id(baseline)
    projection = _normalized_semantic_projection(baseline, baseline_loader_id)
    for fixture in fixtures[1:]:
        if _normalized_semantic_projection(fixture, baseline_loader_id) != projection:
            raise BcdError("BCD oracle differential semantics changed outside the intended GUID")


def _uuid_text(value: uuid.UUID) -> str:
    return "{" + str(value) + "}"


def _fixture_document(fixture: BcdOracleFixture) -> dict[str, Any]:
    return {
        "layout": {
            "disk_guid": str(fixture.layout.disk_guid),
            "disk_size_bytes": fixture.layout.disk_size_bytes,
            "disposable_virtual_disk_claim": fixture.layout.disposable_virtual_disk_claim,
            "esp_drive": fixture.layout.esp_drive,
            "esp_partition_number": fixture.layout.esp_partition_number,
            "esp_partition_guid": str(fixture.layout.esp_partition_guid),
            "esp_sector_count": fixture.layout.esp_sector_count,
            "esp_start_lba": fixture.layout.esp_start_lba,
            "esp_type_guid": str(fixture.layout.esp_type_guid),
            "firmware": fixture.layout.firmware,
            "fresh_store_before_bcdboot": fixture.layout.fresh_store_before_bcdboot,
            "logical_sector_size": fixture.layout.logical_sector_size,
            "msr_partition_guid": str(fixture.layout.msr_partition_guid),
            "msr_partition_number": fixture.layout.msr_partition_number,
            "msr_sector_count": fixture.layout.msr_sector_count,
            "msr_start_lba": fixture.layout.msr_start_lba,
            "msr_type_guid": str(fixture.layout.msr_type_guid),
            "windows_drive": fixture.layout.windows_drive,
            "windows_partition_guid": str(fixture.layout.windows_partition_guid),
            "windows_partition_number": fixture.layout.windows_partition_number,
            "windows_sector_count": fixture.layout.windows_sector_count,
            "windows_start_lba": fixture.layout.windows_start_lba,
            "windows_type_guid": str(fixture.layout.windows_type_guid),
        },
        "objects": [
            {
                "elements": [
                    {
                        "binary_hex": element.binary_hex,
                        "element_type": f"{element.element_type:08x}",
                        "multi_string_value": (
                            list(element.multi_string_value)
                            if element.multi_string_value is not None
                            else None
                        ),
                        "registry_type": element.registry_type,
                        "string_value": element.string_value,
                    }
                    for element in item.elements
                ],
                "object_id": _uuid_text(item.object_id),
                "object_type": f"{item.object_type:08x}",
                "object_type_registry_type": item.object_type_registry_type,
            }
            for item in fixture.objects
        ],
        "provenance": {
            "architecture": fixture.provenance.architecture,
            "bootex_selected": fixture.provenance.bootex_selected,
            "bcdboot_argv": list(fixture.provenance.bcdboot_argv),
            "bcdboot_executable_sha256": fixture.provenance.bcdboot_executable_sha256,
            "bcdboot_exit_code": fixture.provenance.bcdboot_exit_code,
            "bcdboot_path": fixture.provenance.bcdboot_path,
            "bcdboot_stderr_hex": fixture.provenance.bcdboot_stderr_hex,
            "bcdboot_stderr_sha256": fixture.provenance.bcdboot_stderr_sha256,
            "bcdboot_stdout_hex": fixture.provenance.bcdboot_stdout_hex,
            "bcdboot_stdout_sha256": fixture.provenance.bcdboot_stdout_sha256,
            "bcdboot_version": fixture.provenance.bcdboot_version,
            "bcdedit_executable_sha256": fixture.provenance.bcdedit_executable_sha256,
            "bcdedit_exit_code": fixture.provenance.bcdedit_exit_code,
            "bcdedit_path": fixture.provenance.bcdedit_path,
            "bcdedit_stderr_hex": fixture.provenance.bcdedit_stderr_hex,
            "bcdedit_stderr_sha256": fixture.provenance.bcdedit_stderr_sha256,
            "bcdedit_stdout_hex": fixture.provenance.bcdedit_stdout_hex,
            "bcdedit_stdout_sha256": fixture.provenance.bcdedit_stdout_sha256,
            "bcdedit_set_recovery_argv": list(
                fixture.provenance.bcdedit_set_recovery_argv
            ),
            "bcdedit_set_recovery_exit_code": (
                fixture.provenance.bcdedit_set_recovery_exit_code
            ),
            "bcdedit_set_recovery_stderr_sha256": (
                fixture.provenance.bcdedit_set_recovery_stderr_sha256
            ),
            "bcdedit_set_recovery_stderr_hex": (
                fixture.provenance.bcdedit_set_recovery_stderr_hex
            ),
            "bcdedit_set_recovery_stdout_sha256": (
                fixture.provenance.bcdedit_set_recovery_stdout_sha256
            ),
            "bcdedit_set_recovery_stdout_hex": (
                fixture.provenance.bcdedit_set_recovery_stdout_hex
            ),
            "bcdedit_argv": list(fixture.provenance.bcdedit_argv),
            "bcdedit_version": fixture.provenance.bcdedit_version,
            "capture_tool_sha256": fixture.provenance.capture_tool_sha256,
            "capture_tool_size": fixture.provenance.capture_tool_size,
            "efi_boot_directory_precreated": (
                fixture.provenance.efi_boot_directory_precreated
            ),
            "host_windows_build": fixture.provenance.host_windows_build,
            "profile": fixture.provenance.profile,
            "source_architecture": fixture.provenance.source_architecture,
            "source_edition": fixture.provenance.source_edition,
            "source_iso_sha256": fixture.provenance.source_iso_sha256,
            "source_wim_index": fixture.provenance.source_wim_index,
            "source_wim_sha256": fixture.provenance.source_wim_sha256,
            "source_windows_build": fixture.provenance.source_windows_build,
            "store_sha256": fixture.provenance.store_sha256,
            "store_size": fixture.provenance.store_size,
            "template_sha256": fixture.provenance.template_sha256,
            "template_size": fixture.provenance.template_size,
        },
        "root_description": {
            "guid_cache_hex": fixture.root_guid_cache_hex,
            "guid_cache_registry_type": fixture.root_guid_cache_registry_type,
            "key_name": fixture.root_key_name,
            "key_name_registry_type": fixture.root_key_name_registry_type,
            "system": fixture.root_system,
            "system_registry_type": fixture.root_system_registry_type,
            "treat_as_system": fixture.root_treat_as_system,
            "treat_as_system_registry_type": (
                fixture.root_treat_as_system_registry_type
            ),
        },
        "schema": fixture.schema,
        "scope": {
            "authorizes_linux_writes": fixture.authorizes_linux_writes,
            "hive_bytes_included": fixture.hive_bytes_included,
            "windows_generated_claim": fixture.windows_generated_claim,
        },
        "variant": fixture.variant,
    }


def _canonical_document_bytes(fixture: BcdOracleFixture) -> bytes:
    return (
        json.dumps(
            _fixture_document(fixture),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def canonical_bcd_oracle_bytes(fixture: BcdOracleFixture) -> bytes:
    validate_bcd_oracle_fixture(fixture)
    payload = _canonical_document_bytes(fixture)
    if len(payload) > BCD_ORACLE_MAX_BYTES:
        raise BcdError("The BCD oracle canonical JSON exceeds the size policy")
    return payload


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise BcdError(f"The BCD oracle JSON repeats key {key!r}")
        output[key] = value
    return output


def _mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise BcdError(f"The BCD oracle {label} fields are not exact")
    return value


def _list(value: object, maximum: int, label: str, *, minimum: int = 0) -> list[Any]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise BcdError(f"The BCD oracle {label} list is invalid")
    return value


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\0" in value:
        raise BcdError(f"The BCD oracle {label} text is invalid")
    try:
        value.encode("utf-16-le", errors="strict")
    except UnicodeEncodeError as error:
        raise BcdError(f"The BCD oracle {label} contains invalid Unicode") from error
    return value


def _parse_guid(value: object, label: str, *, braced: bool) -> uuid.UUID:
    text = _text(value, label, maximum=38)
    if braced != (text.startswith("{") and text.endswith("}")):
        raise BcdError(f"The BCD oracle {label} GUID form is not canonical")
    body = text[1:-1] if braced else text
    try:
        parsed = uuid.UUID(body)
    except ValueError as error:
        raise BcdError(f"The BCD oracle {label} is not a UUID") from error
    if parsed.int == 0 or body != str(parsed):
        raise BcdError(f"The BCD oracle {label} UUID is not canonical")
    return parsed


def parse_bcd_oracle_bytes(payload: bytes) -> BcdOracleFixture:
    """Parse only exact canonical v1 JSON with duplicate-key rejection."""

    if type(payload) is not bytes or not 1 <= len(payload) <= BCD_ORACLE_MAX_BYTES:
        raise BcdError("The BCD oracle JSON size is outside policy")
    try:
        document = json.loads(payload.decode("ascii"), object_pairs_hook=_pairs)
    except BcdError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise BcdError("The BCD oracle is not strict ASCII JSON") from error
    root = _mapping(
        document,
        {"layout", "objects", "provenance", "root_description", "schema", "scope", "variant"},
        "root",
    )
    provenance_data = _mapping(
        root["provenance"],
        {
            "architecture", "bootex_selected", "bcdboot_argv", "bcdboot_version", "bcdedit_argv",
            "bcdboot_executable_sha256", "bcdboot_exit_code",
            "bcdboot_path", "bcdboot_stderr_hex", "bcdboot_stderr_sha256",
            "bcdboot_stdout_hex", "bcdboot_stdout_sha256",
            "bcdedit_executable_sha256", "bcdedit_exit_code",
            "bcdedit_path", "bcdedit_stderr_hex", "bcdedit_stderr_sha256",
            "bcdedit_stdout_hex", "bcdedit_stdout_sha256",
            "bcdedit_set_recovery_argv",
            "bcdedit_set_recovery_exit_code",
            "bcdedit_set_recovery_stderr_hex",
            "bcdedit_set_recovery_stderr_sha256",
            "bcdedit_set_recovery_stdout_hex",
            "bcdedit_set_recovery_stdout_sha256",
            "bcdedit_version", "capture_tool_sha256", "host_windows_build",
            "capture_tool_size", "efi_boot_directory_precreated", "profile",
            "source_architecture", "source_edition", "source_iso_sha256",
            "source_wim_index", "source_wim_sha256", "source_windows_build", "store_sha256",
            "store_size", "template_sha256", "template_size",
        },
        "provenance",
    )
    provenance = BcdOracleProvenance(
        profile=provenance_data["profile"],
        host_windows_build=provenance_data["host_windows_build"],
        source_windows_build=provenance_data["source_windows_build"],
        architecture=provenance_data["architecture"],
        source_architecture=provenance_data["source_architecture"],
        source_iso_sha256=provenance_data["source_iso_sha256"],
        source_wim_sha256=provenance_data["source_wim_sha256"],
        source_wim_index=provenance_data["source_wim_index"],
        source_edition=provenance_data["source_edition"],
        bootex_selected=provenance_data["bootex_selected"],
        efi_boot_directory_precreated=provenance_data[
            "efi_boot_directory_precreated"
        ],
        bcdboot_version=provenance_data["bcdboot_version"],
        bcdedit_version=provenance_data["bcdedit_version"],
        bcdboot_path=provenance_data["bcdboot_path"],
        bcdedit_path=provenance_data["bcdedit_path"],
        bcdboot_executable_sha256=provenance_data["bcdboot_executable_sha256"],
        bcdedit_executable_sha256=provenance_data["bcdedit_executable_sha256"],
        template_sha256=provenance_data["template_sha256"],
        store_sha256=provenance_data["store_sha256"],
        capture_tool_sha256=provenance_data["capture_tool_sha256"],
        template_size=provenance_data["template_size"],
        store_size=provenance_data["store_size"],
        capture_tool_size=provenance_data["capture_tool_size"],
        bcdboot_argv=tuple(_list(provenance_data["bcdboot_argv"], 16, "BCDBoot argv", minimum=1)),
        bcdboot_exit_code=provenance_data["bcdboot_exit_code"],
        bcdboot_stdout_sha256=provenance_data["bcdboot_stdout_sha256"],
        bcdboot_stderr_sha256=provenance_data["bcdboot_stderr_sha256"],
        bcdboot_stdout_hex=provenance_data["bcdboot_stdout_hex"],
        bcdboot_stderr_hex=provenance_data["bcdboot_stderr_hex"],
        bcdedit_set_recovery_argv=tuple(
            _list(
                provenance_data["bcdedit_set_recovery_argv"],
                16,
                "BCDEdit recovery argv",
                minimum=1,
            )
        ),
        bcdedit_set_recovery_exit_code=provenance_data[
            "bcdedit_set_recovery_exit_code"
        ],
        bcdedit_set_recovery_stdout_sha256=provenance_data[
            "bcdedit_set_recovery_stdout_sha256"
        ],
        bcdedit_set_recovery_stderr_sha256=provenance_data[
            "bcdedit_set_recovery_stderr_sha256"
        ],
        bcdedit_set_recovery_stdout_hex=provenance_data[
            "bcdedit_set_recovery_stdout_hex"
        ],
        bcdedit_set_recovery_stderr_hex=provenance_data[
            "bcdedit_set_recovery_stderr_hex"
        ],
        bcdedit_argv=tuple(_list(provenance_data["bcdedit_argv"], 16, "BCDEdit argv", minimum=1)),
        bcdedit_exit_code=provenance_data["bcdedit_exit_code"],
        bcdedit_stdout_sha256=provenance_data["bcdedit_stdout_sha256"],
        bcdedit_stderr_sha256=provenance_data["bcdedit_stderr_sha256"],
        bcdedit_stdout_hex=provenance_data["bcdedit_stdout_hex"],
        bcdedit_stderr_hex=provenance_data["bcdedit_stderr_hex"],
    )
    layout_data = _mapping(
        root["layout"],
        {
            "disk_guid", "disk_size_bytes", "disposable_virtual_disk_claim",
            "esp_drive", "esp_partition_guid", "esp_partition_number",
            "esp_sector_count", "esp_start_lba", "esp_type_guid", "firmware",
            "fresh_store_before_bcdboot", "logical_sector_size",
            "msr_partition_guid", "msr_partition_number", "msr_sector_count",
            "msr_start_lba", "msr_type_guid", "windows_drive",
            "windows_partition_guid", "windows_partition_number",
            "windows_sector_count", "windows_start_lba", "windows_type_guid",
        },
        "layout",
    )
    layout = BcdOracleLayout(
        disk_guid=_parse_guid(layout_data["disk_guid"], "disk", braced=False),
        esp_partition_guid=_parse_guid(layout_data["esp_partition_guid"], "ESP partition", braced=False),
        msr_partition_guid=_parse_guid(layout_data["msr_partition_guid"], "MSR partition", braced=False),
        windows_partition_guid=_parse_guid(layout_data["windows_partition_guid"], "Windows partition", braced=False),
        disk_size_bytes=layout_data["disk_size_bytes"],
        esp_partition_number=layout_data["esp_partition_number"],
        esp_start_lba=layout_data["esp_start_lba"],
        esp_sector_count=layout_data["esp_sector_count"],
        esp_type_guid=_parse_guid(layout_data["esp_type_guid"], "ESP type", braced=False),
        msr_partition_number=layout_data["msr_partition_number"],
        msr_start_lba=layout_data["msr_start_lba"],
        msr_sector_count=layout_data["msr_sector_count"],
        msr_type_guid=_parse_guid(layout_data["msr_type_guid"], "MSR type", braced=False),
        windows_partition_number=layout_data["windows_partition_number"],
        windows_start_lba=layout_data["windows_start_lba"],
        windows_sector_count=layout_data["windows_sector_count"],
        windows_type_guid=_parse_guid(layout_data["windows_type_guid"], "Windows type", braced=False),
        esp_drive=layout_data["esp_drive"],
        windows_drive=layout_data["windows_drive"],
        disposable_virtual_disk_claim=layout_data["disposable_virtual_disk_claim"],
        fresh_store_before_bcdboot=layout_data["fresh_store_before_bcdboot"],
        logical_sector_size=layout_data["logical_sector_size"],
        firmware=layout_data["firmware"],
    )
    objects: list[BcdOracleObject] = []
    for object_data_raw in _list(root["objects"], BCD_ORACLE_MAX_OBJECTS, "objects", minimum=2):
        object_data = _mapping(
            object_data_raw,
            {"elements", "object_id", "object_type", "object_type_registry_type"},
            "object",
        )
        object_type_text = object_data["object_type"]
        if type(object_type_text) is not str or _HEX8.fullmatch(object_type_text) is None:
            raise BcdError("The BCD oracle object type is not canonical hexadecimal")
        elements: list[BcdOracleElement] = []
        for element_data_raw in _list(object_data["elements"], 128, "elements"):
            element_data = _mapping(
                element_data_raw,
                {
                    "binary_hex",
                    "element_type",
                    "multi_string_value",
                    "registry_type",
                    "string_value",
                },
                "element",
            )
            element_type_text = element_data["element_type"]
            if type(element_type_text) is not str or _HEX8.fullmatch(element_type_text) is None:
                raise BcdError("The BCD oracle element type is not canonical hexadecimal")
            binary_hex = element_data["binary_hex"]
            if binary_hex is not None:
                _hex(binary_hex, "binary element")
            string_value = element_data["string_value"]
            if string_value is not None:
                _text(string_value, "string element", maximum=1024)
            multi_string_raw = element_data["multi_string_value"]
            multi_string_value = None
            if multi_string_raw is not None:
                multi_string_value = tuple(
                    _text(value, "multi-string member", maximum=1024)
                    for value in _list(
                        multi_string_raw,
                        BCD_ORACLE_MAX_OBJECTS,
                        "multi-string",
                    )
                )
            elements.append(
                BcdOracleElement(
                    int(element_type_text, 16),
                    element_data["registry_type"],
                    binary_hex,
                    string_value,
                    multi_string_value,
                ),
            )
        objects.append(
            BcdOracleObject(
                _parse_guid(object_data["object_id"], "object", braced=True),
                int(object_type_text, 16),
                object_data["object_type_registry_type"],
                tuple(elements),
            ),
        )
    scope = _mapping(
        root["scope"],
        {"authorizes_linux_writes", "hive_bytes_included", "windows_generated_claim"},
        "scope",
    )
    root_description = _mapping(
        root["root_description"],
        {
            "guid_cache_hex", "guid_cache_registry_type", "key_name",
            "key_name_registry_type", "system", "system_registry_type",
            "treat_as_system", "treat_as_system_registry_type",
        },
        "root description",
    )
    fixture = BcdOracleFixture(
        variant=root["variant"],
        provenance=provenance,
        layout=layout,
        objects=tuple(objects),
        root_key_name=root_description["key_name"],
        root_key_name_registry_type=root_description["key_name_registry_type"],
        root_system=root_description["system"],
        root_system_registry_type=root_description["system_registry_type"],
        root_treat_as_system=root_description["treat_as_system"],
        root_treat_as_system_registry_type=root_description[
            "treat_as_system_registry_type"
        ],
        root_guid_cache_hex=root_description["guid_cache_hex"],
        root_guid_cache_registry_type=root_description["guid_cache_registry_type"],
        schema=root["schema"],
        windows_generated_claim=scope["windows_generated_claim"],
        hive_bytes_included=scope["hive_bytes_included"],
        authorizes_linux_writes=scope["authorizes_linux_writes"],
    )
    validate_bcd_oracle_fixture(fixture)
    if canonical_bcd_oracle_bytes(fixture) != payload:
        raise BcdError("The BCD oracle JSON is not byte-canonical")
    return fixture
