# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Strict import core for non-canonical Windows BCD capture evidence.

The RAW document carries only platform, artifact, and command claims.  It must
not carry a registry-tree interpretation: objects and root values are derived
on Linux from the captured hive through :mod:`isopropyl.windows_bcd_hivex`.
This module performs no filesystem access and publishes no files.
"""

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from .windows_bcd import BcdError
from .windows_bcd_hivex import BCD_HIVE_MAX_BYTES, BcdHiveObservation
from .windows_bcd_oracle import (
    BCD_ORACLE_ARCHITECTURE,
    BCD_ORACLE_ESP_SECTORS,
    BCD_ORACLE_ESP_START_LBA,
    BCD_ORACLE_ESP_TYPE_GUID,
    BCD_ORACLE_FIRMWARE,
    BCD_ORACLE_LOGICAL_SECTOR_SIZE,
    BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES,
    BCD_ORACLE_MSR_SECTORS,
    BCD_ORACLE_MSR_TYPE_GUID,
    BCD_ORACLE_WINDOWS_TYPE_GUID,
    BcdOracleFixture,
    BcdOracleLayout,
    BcdOracleProvenance,
    canonical_bcd_oracle_bytes,
    parse_bcd_oracle_bytes,
    validate_bcd_oracle_differential_set,
    validate_bcd_oracle_fixture,
)


RAW_BCD_CAPTURE_SCHEMA = "io.github.codebooker.isopropyl/windows-bcd-raw-capture/v1"
RAW_BCD_CAPTURE_PROFILE = "uefi-amd64-offline-no-bootex-v1"
RAW_BCD_CAPTURE_VARIANTS = ("baseline", "disk-guid", "esp-guid", "windows-guid")
RAW_BCD_CAPTURE_MAX_BYTES = 4 * 1024 * 1024
RAW_BCD_CAPTURE_MAX_DEPTH = 16
RAW_TEMPLATE_MAX_BYTES = 16 * 1024 * 1024
RAW_COLLECTOR_MAX_BYTES = 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,9})(?:\.(?:0|[1-9][0-9]{0,9})){3}\Z")


@dataclass(frozen=True)
class RawArtifactClaim:
    size: int
    sha256: str


@dataclass(frozen=True)
class VerifiedArtifactReceipt:
    size: int
    sha256: str


@dataclass(frozen=True)
class RawToolClaim:
    path: str
    version: str
    executable_sha256: str


@dataclass(frozen=True)
class RawCommandCapture:
    argv: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class RawVariantCapture:
    variant: str
    disk_guid: uuid.UUID
    esp_partition_guid: uuid.UUID
    windows_partition_guid: uuid.UUID
    store: RawArtifactClaim
    bcdboot: RawCommandCapture
    bcdedit_set_recovery: RawCommandCapture
    bcdedit_enum: RawCommandCapture


@dataclass(frozen=True)
class RawBcdCaptureBundle:
    schema: str
    host_windows_build: int
    source_windows_build: int
    source_iso_sha256: str
    source_wim_sha256: str
    source_wim_index: int
    source_edition: str
    disk_size_bytes: int
    msr_partition_guid: uuid.UUID
    bcdboot: RawToolClaim
    bcdedit: RawToolClaim
    template: RawArtifactClaim
    collector: RawArtifactClaim
    captures: tuple[RawVariantCapture, ...]


@dataclass(frozen=True)
class _DerivedCommand:
    argv: tuple[str, ...]
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_hex: str
    stderr_hex: str


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BcdError(f"The RAW BCD capture JSON repeats key {key!r}")
        result[key] = value
    return result


def _reject_json_number(value: str) -> None:
    raise BcdError(f"The RAW BCD capture contains unsupported number {value!r}")


def _mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise BcdError(f"The RAW BCD capture {label} fields are not exact")
    return value


def _uint(
    value: object,
    maximum: int,
    label: str,
    *,
    minimum: int = 0,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BcdError(f"The RAW BCD capture {label} is outside policy")
    return value


def _text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value)
        or len(value) > maximum
        or "\0" in value
        or "\r" in value
        or "\n" in value
    ):
        raise BcdError(f"The RAW BCD capture {label} text is invalid")
    try:
        value.encode("utf-16-le", errors="strict")
    except UnicodeEncodeError as error:
        raise BcdError(f"The RAW BCD capture {label} contains invalid Unicode") from error
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise BcdError(f"The RAW BCD capture {label} is not a canonical SHA-256")
    return value


def _guid(value: object, label: str) -> uuid.UUID:
    text = _text(value, label, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as error:
        raise BcdError(f"The RAW BCD capture {label} is not a UUID") from error
    if parsed.int == 0 or text != str(parsed):
        raise BcdError(f"The RAW BCD capture {label} UUID is not canonical")
    return parsed


def _artifact(value: object, label: str, maximum: int) -> RawArtifactClaim:
    data = _mapping(value, {"sha256", "size"}, label)
    return RawArtifactClaim(
        _uint(data["size"], maximum, f"{label} size", minimum=1),
        _digest(data["sha256"], f"{label} digest"),
    )


def _tool(value: object, label: str) -> RawToolClaim:
    data = _mapping(value, {"executable_sha256", "path", "version"}, label)
    path = _text(data["path"], f"{label} path", maximum=260)
    version = _text(data["version"], f"{label} version", maximum=64)
    if _VERSION.fullmatch(version) is None or any(
        int(component) > 0xFFFFFFFF for component in version.split(".")
    ):
        raise BcdError(f"The RAW BCD capture {label} version is invalid")
    return RawToolClaim(
        path,
        version,
        _digest(data["executable_sha256"], f"{label} executable digest"),
    )


def _base64(value: object, label: str) -> bytes:
    if type(value) is not str or len(value) > (
        (BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES + 2) // 3 * 4
    ):
        raise BcdError(f"The RAW BCD capture {label} is not bounded base64")
    try:
        encoded = value.encode("ascii", errors="strict")
        payload = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise BcdError(f"The RAW BCD capture {label} is not canonical base64") from error
    if (
        len(payload) > BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES
        or base64.b64encode(payload).decode("ascii") != value
    ):
        raise BcdError(f"The RAW BCD capture {label} is not canonical base64")
    return payload


def _command(value: object, label: str) -> RawCommandCapture:
    data = _mapping(
        value,
        {"argv", "exit_code", "stderr_base64", "stdout_base64"},
        label,
    )
    argv_raw = data["argv"]
    if type(argv_raw) is not list or not 1 <= len(argv_raw) <= 16:
        raise BcdError(f"The RAW BCD capture {label} argv is invalid")
    argv = tuple(
        _text(argument, f"{label} argument", maximum=260)
        for argument in argv_raw
    )
    exit_code = _uint(data["exit_code"], 0, f"{label} exit code")
    return RawCommandCapture(
        argv,
        exit_code,
        _base64(data["stdout_base64"], f"{label} stdout"),
        _base64(data["stderr_base64"], f"{label} stderr"),
    )


def _capture(value: object) -> RawVariantCapture:
    data = _mapping(
        value,
        {
            "commands",
            "disk_guid",
            "esp_partition_guid",
            "store",
            "variant",
            "windows_partition_guid",
        },
        "capture",
    )
    variant = _text(data["variant"], "variant", maximum=32)
    if variant not in RAW_BCD_CAPTURE_VARIANTS:
        raise BcdError("The RAW BCD capture variant is unsupported")
    commands = _mapping(
        data["commands"],
        {"bcdboot", "bcdedit_enum", "bcdedit_set_recovery"},
        f"{variant} commands",
    )
    enumeration = _command(commands["bcdedit_enum"], f"{variant} BCDEdit enum")
    if not enumeration.stdout:
        raise BcdError(f"The RAW BCD capture {variant} BCDEdit enum stdout is empty")
    return RawVariantCapture(
        variant,
        _guid(data["disk_guid"], f"{variant} disk"),
        _guid(data["esp_partition_guid"], f"{variant} ESP partition"),
        _guid(data["windows_partition_guid"], f"{variant} Windows partition"),
        _artifact(data["store"], f"{variant} store", BCD_HIVE_MAX_BYTES),
        _command(commands["bcdboot"], f"{variant} BCDBoot"),
        _command(
            commands["bcdedit_set_recovery"],
            f"{variant} BCDEdit recovery",
        ),
        enumeration,
    )


def _require_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > RAW_BCD_CAPTURE_MAX_DEPTH:
                raise BcdError("The RAW BCD capture JSON is nested too deeply")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise BcdError("The RAW BCD capture JSON structure is invalid")


def parse_raw_bcd_capture_bytes(payload: bytes) -> RawBcdCaptureBundle:
    """Parse a bounded, non-canonical RAW capture document.

    Whitespace and object ordering are irrelevant.  Duplicate or unknown fields,
    non-integral JSON numbers, non-canonical claims, and registry-tree fields are
    rejected.
    """

    if type(payload) is not bytes or not 1 <= len(payload) <= RAW_BCD_CAPTURE_MAX_BYTES:
        raise BcdError("The RAW BCD capture document size or type is invalid")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise BcdError("The RAW BCD capture document must not contain a UTF-8 BOM")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise BcdError("The RAW BCD capture document is not UTF-8") from error
    _require_json_depth(text)
    try:
        root_raw = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except BcdError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise BcdError("The RAW BCD capture document is not strict JSON") from error
    root = _mapping(root_raw, {"captures", "profile", "schema"}, "root")
    if root["schema"] != RAW_BCD_CAPTURE_SCHEMA:
        raise BcdError("The RAW BCD capture schema is unsupported")
    profile = _mapping(
        root["profile"],
        {
            "bcdboot",
            "bcdedit",
            "collector",
            "disk_size_bytes",
            "host_windows_build",
            "msr_partition_guid",
            "source_edition",
            "source_iso_sha256",
            "source_wim_index",
            "source_wim_sha256",
            "source_windows_build",
            "template",
        },
        "profile",
    )
    captures_raw = root["captures"]
    if type(captures_raw) is not list or len(captures_raw) != len(RAW_BCD_CAPTURE_VARIANTS):
        raise BcdError("The RAW BCD capture requires exactly four variants")
    captures = tuple(_capture(value) for value in captures_raw)
    by_variant = {capture.variant: capture for capture in captures}
    if set(by_variant) != set(RAW_BCD_CAPTURE_VARIANTS) or len(by_variant) != len(captures):
        raise BcdError("The RAW BCD capture variants are missing or duplicated")
    ordered = tuple(by_variant[variant] for variant in RAW_BCD_CAPTURE_VARIANTS)
    return RawBcdCaptureBundle(
        RAW_BCD_CAPTURE_SCHEMA,
        _uint(
            profile["host_windows_build"],
            0xFFFFFFFF,
            "host Windows build",
            minimum=1,
        ),
        _uint(
            profile["source_windows_build"],
            0xFFFFFFFF,
            "source Windows build",
            minimum=1,
        ),
        _digest(profile["source_iso_sha256"], "source ISO digest"),
        _digest(profile["source_wim_sha256"], "source WIM digest"),
        _uint(profile["source_wim_index"], 1024, "source WIM index", minimum=1),
        _text(profile["source_edition"], "source edition", maximum=256),
        _uint(
            profile["disk_size_bytes"],
            (1 << 64) - 1,
            "disk size",
            minimum=1,
        ),
        _guid(profile["msr_partition_guid"], "MSR partition"),
        _tool(profile["bcdboot"], "BCDBoot"),
        _tool(profile["bcdedit"], "BCDEdit"),
        _artifact(profile["template"], "template", RAW_TEMPLATE_MAX_BYTES),
        _artifact(profile["collector"], "collector", RAW_COLLECTOR_MAX_BYTES),
        ordered,
    )


def _receipt(value: object, expected: RawArtifactClaim, label: str) -> None:
    if type(value) is not VerifiedArtifactReceipt:
        raise BcdError(f"The verified {label} receipt is missing")
    if (
        type(value.size) is not int
        or type(value.sha256) is not str
        or value.size != expected.size
        or value.sha256 != expected.sha256
    ):
        raise BcdError(f"The verified {label} receipt contradicts the RAW claim")


def _validate_artifact_model(
    value: object,
    label: str,
    maximum: int,
) -> RawArtifactClaim:
    if type(value) is not RawArtifactClaim:
        raise BcdError(f"The parsed RAW BCD capture {label} model is invalid")
    _uint(value.size, maximum, f"{label} size", minimum=1)
    _digest(value.sha256, f"{label} digest")
    return value


def _validate_tool_model(value: object, label: str) -> RawToolClaim:
    if type(value) is not RawToolClaim:
        raise BcdError(f"The parsed RAW BCD capture {label} model is invalid")
    _text(value.path, f"{label} path", maximum=260)
    version = _text(value.version, f"{label} version", maximum=64)
    if _VERSION.fullmatch(version) is None or any(
        int(component) > 0xFFFFFFFF for component in version.split(".")
    ):
        raise BcdError(f"The RAW BCD capture {label} version is invalid")
    _digest(value.executable_sha256, f"{label} executable digest")
    return value


def _validate_command_model(value: object, label: str) -> RawCommandCapture:
    if type(value) is not RawCommandCapture:
        raise BcdError(f"The parsed RAW BCD capture {label} command is invalid")
    if type(value.argv) is not tuple or not 1 <= len(value.argv) <= 16:
        raise BcdError(f"The RAW BCD capture {label} argv is invalid")
    for argument in value.argv:
        _text(argument, f"{label} argument", maximum=260)
    _uint(value.exit_code, 0, f"{label} exit code")
    for stream, stream_label in ((value.stdout, "stdout"), (value.stderr, "stderr")):
        if type(stream) is not bytes or len(stream) > BCD_ORACLE_MAX_COMMAND_OUTPUT_BYTES:
            raise BcdError(f"The parsed RAW BCD capture {label} {stream_label} is invalid")
    return value


def _validate_capture_model(value: object, expected_variant: str) -> RawVariantCapture:
    if type(value) is not RawVariantCapture or value.variant != expected_variant:
        raise BcdError("The parsed RAW BCD capture variants are invalid")
    _guid(str(value.disk_guid) if type(value.disk_guid) is uuid.UUID else value.disk_guid, f"{expected_variant} disk")
    _guid(
        str(value.esp_partition_guid)
        if type(value.esp_partition_guid) is uuid.UUID
        else value.esp_partition_guid,
        f"{expected_variant} ESP partition",
    )
    _guid(
        str(value.windows_partition_guid)
        if type(value.windows_partition_guid) is uuid.UUID
        else value.windows_partition_guid,
        f"{expected_variant} Windows partition",
    )
    _validate_artifact_model(value.store, f"{expected_variant} store", BCD_HIVE_MAX_BYTES)
    _validate_command_model(value.bcdboot, f"{expected_variant} BCDBoot")
    _validate_command_model(
        value.bcdedit_set_recovery,
        f"{expected_variant} BCDEdit recovery",
    )
    enumeration = _validate_command_model(
        value.bcdedit_enum,
        f"{expected_variant} BCDEdit enum",
    )
    if not enumeration.stdout:
        raise BcdError(f"The RAW BCD capture {expected_variant} BCDEdit enum stdout is empty")
    return value


def _validate_bundle_model(value: object) -> RawBcdCaptureBundle:
    """Revalidate a public frozen model before crossing the derivation boundary."""

    if type(value) is not RawBcdCaptureBundle or value.schema != RAW_BCD_CAPTURE_SCHEMA:
        raise BcdError("A parsed RAW BCD capture bundle is required")
    _uint(value.host_windows_build, 0xFFFFFFFF, "host Windows build", minimum=1)
    _uint(value.source_windows_build, 0xFFFFFFFF, "source Windows build", minimum=1)
    _digest(value.source_iso_sha256, "source ISO digest")
    _digest(value.source_wim_sha256, "source WIM digest")
    _uint(value.source_wim_index, 1024, "source WIM index", minimum=1)
    _text(value.source_edition, "source edition", maximum=256)
    _uint(value.disk_size_bytes, (1 << 64) - 1, "disk size", minimum=1)
    _guid(
        str(value.msr_partition_guid)
        if type(value.msr_partition_guid) is uuid.UUID
        else value.msr_partition_guid,
        "MSR partition",
    )
    _validate_tool_model(value.bcdboot, "BCDBoot")
    _validate_tool_model(value.bcdedit, "BCDEdit")
    _validate_artifact_model(value.template, "template", RAW_TEMPLATE_MAX_BYTES)
    _validate_artifact_model(value.collector, "collector", RAW_COLLECTOR_MAX_BYTES)
    if type(value.captures) is not tuple or len(value.captures) != len(
        RAW_BCD_CAPTURE_VARIANTS
    ):
        raise BcdError("A parsed RAW BCD capture bundle is required")
    for capture, expected_variant in zip(value.captures, RAW_BCD_CAPTURE_VARIANTS):
        _validate_capture_model(capture, expected_variant)
    return value


def _command_fields(command: RawCommandCapture) -> _DerivedCommand:
    return _DerivedCommand(
        command.argv,
        command.exit_code,
        hashlib.sha256(command.stdout).hexdigest(),
        hashlib.sha256(command.stderr).hexdigest(),
        command.stdout.hex(),
        command.stderr.hex(),
    )


def _layout(bundle: RawBcdCaptureBundle, capture: RawVariantCapture) -> BcdOracleLayout:
    msr_start = BCD_ORACLE_ESP_START_LBA + BCD_ORACLE_ESP_SECTORS
    windows_start = msr_start + BCD_ORACLE_MSR_SECTORS
    total_sectors = bundle.disk_size_bytes // BCD_ORACLE_LOGICAL_SECTOR_SIZE
    aligned_end = ((total_sectors - 33) // 2048) * 2048
    return BcdOracleLayout(
        disk_guid=capture.disk_guid,
        esp_partition_guid=capture.esp_partition_guid,
        msr_partition_guid=bundle.msr_partition_guid,
        windows_partition_guid=capture.windows_partition_guid,
        disk_size_bytes=bundle.disk_size_bytes,
        esp_partition_number=1,
        esp_start_lba=BCD_ORACLE_ESP_START_LBA,
        esp_sector_count=BCD_ORACLE_ESP_SECTORS,
        esp_type_guid=BCD_ORACLE_ESP_TYPE_GUID,
        msr_partition_number=2,
        msr_start_lba=msr_start,
        msr_sector_count=BCD_ORACLE_MSR_SECTORS,
        msr_type_guid=BCD_ORACLE_MSR_TYPE_GUID,
        windows_partition_number=3,
        windows_start_lba=windows_start,
        windows_sector_count=aligned_end - windows_start,
        windows_type_guid=BCD_ORACLE_WINDOWS_TYPE_GUID,
        esp_drive="S:",
        windows_drive="W:",
        disposable_virtual_disk_claim=True,
        fresh_store_before_bcdboot=True,
        logical_sector_size=BCD_ORACLE_LOGICAL_SECTOR_SIZE,
        firmware=BCD_ORACLE_FIRMWARE,
    )


def _fixture(
    bundle: RawBcdCaptureBundle,
    capture: RawVariantCapture,
    observation: BcdHiveObservation,
    collector: VerifiedArtifactReceipt,
    template: VerifiedArtifactReceipt,
) -> BcdOracleFixture:
    if type(observation) is not BcdHiveObservation:
        raise BcdError(f"The {capture.variant} BCD hive observation is invalid")
    if (
        type(observation.store_size) is not int
        or type(observation.store_sha256) is not str
        or observation.store_size != capture.store.size
        or observation.store_sha256 != capture.store.sha256
    ):
        raise BcdError(f"The {capture.variant} BCD hive contradicts its RAW store claim")
    bcdboot = _command_fields(capture.bcdboot)
    recovery = _command_fields(capture.bcdedit_set_recovery)
    enumeration = _command_fields(capture.bcdedit_enum)
    provenance = BcdOracleProvenance(
        profile=RAW_BCD_CAPTURE_PROFILE,
        host_windows_build=bundle.host_windows_build,
        source_windows_build=bundle.source_windows_build,
        architecture=BCD_ORACLE_ARCHITECTURE,
        source_architecture=BCD_ORACLE_ARCHITECTURE,
        source_iso_sha256=bundle.source_iso_sha256,
        source_wim_sha256=bundle.source_wim_sha256,
        source_wim_index=bundle.source_wim_index,
        source_edition=bundle.source_edition,
        bootex_selected=False,
        efi_boot_directory_precreated=True,
        bcdboot_version=bundle.bcdboot.version,
        bcdedit_version=bundle.bcdedit.version,
        bcdboot_path=bundle.bcdboot.path,
        bcdedit_path=bundle.bcdedit.path,
        bcdboot_executable_sha256=bundle.bcdboot.executable_sha256,
        bcdedit_executable_sha256=bundle.bcdedit.executable_sha256,
        template_sha256=template.sha256,
        store_sha256=observation.store_sha256,
        capture_tool_sha256=collector.sha256,
        template_size=template.size,
        store_size=observation.store_size,
        capture_tool_size=collector.size,
        bcdboot_argv=bcdboot.argv,
        bcdboot_exit_code=bcdboot.exit_code,
        bcdboot_stdout_sha256=bcdboot.stdout_sha256,
        bcdboot_stderr_sha256=bcdboot.stderr_sha256,
        bcdboot_stdout_hex=bcdboot.stdout_hex,
        bcdboot_stderr_hex=bcdboot.stderr_hex,
        bcdedit_set_recovery_argv=recovery.argv,
        bcdedit_set_recovery_exit_code=recovery.exit_code,
        bcdedit_set_recovery_stdout_sha256=recovery.stdout_sha256,
        bcdedit_set_recovery_stderr_sha256=recovery.stderr_sha256,
        bcdedit_set_recovery_stdout_hex=recovery.stdout_hex,
        bcdedit_set_recovery_stderr_hex=recovery.stderr_hex,
        bcdedit_argv=enumeration.argv,
        bcdedit_exit_code=enumeration.exit_code,
        bcdedit_stdout_sha256=enumeration.stdout_sha256,
        bcdedit_stderr_sha256=enumeration.stderr_sha256,
        bcdedit_stdout_hex=enumeration.stdout_hex,
        bcdedit_stderr_hex=enumeration.stderr_hex,
    )
    fixture = BcdOracleFixture(
        variant=capture.variant,
        provenance=provenance,
        layout=_layout(bundle, capture),
        objects=observation.objects,
        root_key_name=observation.root_key_name,
        root_key_name_registry_type=observation.root_key_name_registry_type,
        root_system=observation.root_system,
        root_system_registry_type=observation.root_system_registry_type,
        root_treat_as_system=observation.root_treat_as_system,
        root_treat_as_system_registry_type=observation.root_treat_as_system_registry_type,
        root_guid_cache_hex=observation.root_guid_cache_hex,
        root_guid_cache_registry_type=observation.root_guid_cache_registry_type,
    )
    validate_bcd_oracle_fixture(fixture)
    canonical = canonical_bcd_oracle_bytes(fixture)
    reparsed = parse_bcd_oracle_bytes(canonical)
    if reparsed != fixture:
        raise BcdError("The derived BCD oracle fixture did not round-trip canonically")
    return reparsed


def derive_bcd_oracle_fixtures(
    bundle: RawBcdCaptureBundle,
    observations: Mapping[str, BcdHiveObservation],
    *,
    collector_receipt: VerifiedArtifactReceipt,
    template_receipt: VerifiedArtifactReceipt,
) -> tuple[BcdOracleFixture, ...]:
    """Derive and validate a canonical four-fixture cohort from hive evidence."""

    bundle = _validate_bundle_model(bundle)
    if not isinstance(observations, Mapping) or set(observations) != set(
        RAW_BCD_CAPTURE_VARIANTS
    ):
        raise BcdError("Exactly four named BCD hive observations are required")
    _receipt(collector_receipt, bundle.collector, "collector")
    _receipt(template_receipt, bundle.template, "template")
    fixtures = tuple(
        _fixture(
            bundle,
            capture,
            observations[capture.variant],
            collector_receipt,
            template_receipt,
        )
        for capture in bundle.captures
    )
    validate_bcd_oracle_differential_set(fixtures)
    return fixtures
