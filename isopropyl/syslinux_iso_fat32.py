from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Witnessed ISO staging -> anonymous patched Syslinux FAT32 composition.

This module is intentionally backend-only.  It consumes one authenticated,
already-published ISO staging result, builds an anonymous regular-file image,
patches it through the descriptor-only Syslinux transaction, and exposes only a
patched, independently attested byte stream.  It imports no GUI, device,
formatter, mount, or privileged writer backend.
"""

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .bootloaders import BoundBootBundle
from .iso_staging import (
    IsoStagingPlan,
    IsoStagingResult,
    IsoStagingSafetyError,
    validate_published_syslinux_staging,
)
from .iso import BootStrategy, FileSystem
from .private_fat32 import (
    AnonymousFat32Image,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32File,
    PrivateFat32Plan,
    PrivateFat32State,
    build_private_fat32_plan,
    patch_private_fat32_syslinux,
    validate_private_fat32_plan,
)
from .staging_tree import StagingTreeManifest
from .syslinux import (
    SyslinuxPatchError,
    bind_syslinux_bundle,
    make_empty_adv,
)
from .syslinux_staging import (
    StageDisposition,
    SyslinuxStageFile,
    SyslinuxStagingError,
    SyslinuxStagingPlan,
    bind_syslinux_c32_bundle,
)
from .syslinux_transaction import (
    SyslinuxRegularFileTransactionResult,
)


_PLAN_PROFILE = "io.github.codebooker.isopropyl/syslinux-iso-fat32-plan/v1"
_PLAN_WITNESS = object()
_OWNER_WITNESS = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SyslinuxIsoFat32Error(RuntimeError):
    """A witnessed Syslinux ISO image could not be prepared safely."""


class SyslinuxIsoFat32Cancelled(SyslinuxIsoFat32Error):
    """Preparation was cancelled before a patched image could be returned."""


@dataclass(frozen=True)
class _CompositePlanReceipt:
    token: object
    plan: object
    iso_plan: object
    staging_result: object
    private_plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class SyslinuxIsoFat32Plan:
    """One exact published tree and its anonymous FAT32 construction plan."""

    iso_plan: IsoStagingPlan = field(repr=False, compare=False)
    staging_result: IsoStagingResult = field(repr=False, compare=False)
    private_plan: PrivateFat32Plan = field(repr=False)
    source_manifest_sha256: str
    c32_bundle_sha256: str
    payload_bundle_sha256: str
    version: str
    dependency_key: str
    config_directory: str
    root_ldlinux_size: int
    root_ldlinux_sha256: str
    plan_sha256: str
    _receipt: _CompositePlanReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class SyslinuxIsoFat32Result:
    """Complete before/after attestation for one patched anonymous image."""

    plan_sha256: str
    private_plan_sha256: str
    transaction_plan_sha256: str
    version: str
    disk_signature: int
    volume_id: int
    image_size: int
    unpatched_image_sha256: str
    final_image_sha256: str
    unpatched_manifest_sha256: str
    final_manifest_sha256: str
    unpatched_ldlinux_sha256: str
    patched_ldlinux_sha256: str
    files_verified: int
    directories_verified: int
    bytes_verified: int


CancelCheck = Callable[[], None]
Progress = Callable[[str, str, int, int], None]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _require_compatible_source_layout(iso_plan: IsoStagingPlan) -> None:
    layout = iso_plan.write_plan.layout
    if (
        layout is None
        or layout.main_filesystem is not FileSystem.FAT32
        or layout.partition_count != 1
        or layout.boot_partition_filesystem is not None
        or layout.boot_strategy is not BootStrategy.IMAGE_NATIVE
        or iso_plan.write_plan.transformations
    ):
        raise SyslinuxIsoFat32Error(
            "The initial composite profile requires a native single-partition "
            "FAT32 source plan",
        )


def _bundle_digest(bundle: BoundBootBundle) -> str:
    if type(bundle) is not BoundBootBundle:
        raise SyslinuxIsoFat32Error("An exact bound Syslinux bundle is required")
    try:
        encoded = json.dumps(
            {
                "family": bundle.family,
                "version": bundle.version,
                "purpose": bundle.purpose,
                "license": bundle.license,
                "provenance_url": bundle.provenance_url,
                "artifacts": [
                    {
                        "name": item.name,
                        "size": len(item.data),
                        "sha256": item.sha256,
                    }
                    for item in bundle.artifacts
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise SyslinuxIsoFat32Error(
            "The Syslinux bundle metadata is invalid",
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _plan_digest(plan: SyslinuxIsoFat32Plan) -> str:
    staging = plan.iso_plan.syslinux_staging
    if type(staging) is not SyslinuxStagingPlan:
        return ""
    try:
        encoded = json.dumps(
            {
                "profile": _PLAN_PROFILE,
                "iso": {
                    "destination": str(plan.staging_result.destination),
                    "image_identity": plan.staging_result.image_identity,
                    "catalog_sha256": plan.staging_result.catalog_digest,
                    "tree_manifest_sha256": plan.source_manifest_sha256,
                    "directories": plan.staging_result.directories,
                    "files": plan.staging_result.files,
                    "bytes": plan.staging_result.bytes_staged,
                },
                "syslinux": {
                    "version": plan.version,
                    "dependency_key": plan.dependency_key,
                    "bootloader_path": staging.bootloader_path,
                    "config_path": staging.config_path,
                    "config_directory": plan.config_directory,
                    "source_catalog_sha256": staging.source_catalog_sha256,
                    "analysis_sha256": staging.analysis_sha256,
                    "source_members_sha256": staging.source_members_sha256,
                    "config_sha256": staging.config_sha256,
                    "root_ldlinux_size": plan.root_ldlinux_size,
                    "root_ldlinux_sha256": plan.root_ldlinux_sha256,
                    "c32_bundle_sha256": plan.c32_bundle_sha256,
                    "payload_bundle_sha256": plan.payload_bundle_sha256,
                },
                "fat32": {
                    "plan_sha256": plan.private_plan.plan_sha256,
                    "image_size": plan.private_plan.geometry.image_size,
                    "disk_signature": plan.private_plan.disk_signature,
                    "volume_id": plan.private_plan.volume_id,
                },
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _private_files(plan: PrivateFat32Plan) -> dict[str, PrivateFat32File]:
    return {item.source.path: item for item in plan.files}


def _plan_snapshot(plan: SyslinuxIsoFat32Plan) -> tuple[object, ...]:
    return (
        plan.source_manifest_sha256,
        plan.c32_bundle_sha256,
        plan.payload_bundle_sha256,
        plan.version,
        plan.dependency_key,
        plan.config_directory,
        plan.root_ldlinux_size,
        plan.root_ldlinux_sha256,
        plan.plan_sha256,
    )


def _require_private_file(
    files: dict[str, PrivateFat32File],
    staged: SyslinuxStageFile,
    label: str,
) -> PrivateFat32File:
    item = files.get(staged.path)
    if (
        item is None
        or item.source.size != len(staged.data)
        or not hmac.compare_digest(item.sha256, staged.sha256)
        or not hmac.compare_digest(
            hashlib.sha256(staged.data).hexdigest(),
            staged.sha256,
        )
    ):
        raise SyslinuxIsoFat32Error(
            f"The private FAT32 plan does not bind the exact {label}",
        )
    return item


def _validate_relationships(
    plan: SyslinuxIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
) -> StagingTreeManifest:
    if type(plan) is not SyslinuxIsoFat32Plan:
        raise SyslinuxIsoFat32Error(
            "An authentic Syslinux ISO FAT32 plan is required",
        )
    receipt = plan._receipt
    if (
        type(receipt) is not _CompositePlanReceipt
        or receipt.token is not _PLAN_WITNESS
        or receipt.plan is not plan
        or receipt.iso_plan is not plan.iso_plan
        or receipt.staging_result is not plan.staging_result
        or receipt.private_plan is not plan.private_plan
        or receipt.snapshot != _plan_snapshot(plan)
    ):
        raise SyslinuxIsoFat32Error(
            "The Syslinux ISO FAT32 plan receipt is missing or no longer authoritative",
        )
    for name, digest in (
        ("source manifest", plan.source_manifest_sha256),
        ("C32 bundle", plan.c32_bundle_sha256),
        ("payload bundle", plan.payload_bundle_sha256),
        ("root loader", plan.root_ldlinux_sha256),
        ("plan", plan.plan_sha256),
    ):
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise SyslinuxIsoFat32Error(f"The {name} digest is invalid")
    try:
        manifest = validate_published_syslinux_staging(
            plan.iso_plan,
            plan.staging_result,
            cancel_check=cancel_check,
        )
    except IsoStagingSafetyError as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    _require_compatible_source_layout(plan.iso_plan)
    staging = plan.iso_plan.syslinux_staging
    c32_bundle = plan.iso_plan.syslinux_c32_bundle
    payload_bundle = plan.iso_plan.syslinux_payload_bundle
    if (
        type(staging) is not SyslinuxStagingPlan
        or type(c32_bundle) is not BoundBootBundle
        or type(payload_bundle) is not BoundBootBundle
    ):
        raise SyslinuxIsoFat32Error("The Syslinux ISO binding is incomplete")
    try:
        c32 = bind_syslinux_c32_bundle(c32_bundle)
        payloads = bind_syslinux_bundle(payload_bundle)
    except (SyslinuxStagingError, SyslinuxPatchError) as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    expected_unpatched = payloads.ldlinux_sys + make_empty_adv()
    expected_unpatched_sha256 = hashlib.sha256(expected_unpatched).hexdigest()
    if (
        plan.version != staging.version
        or plan.version != c32.version
        or plan.version != payloads.version
        or plan.dependency_key != staging.dependency_key
        or plan.dependency_key != f"syslinux:{plan.version}"
        or plan.config_directory != staging.config_directory
        or plan.root_ldlinux_size != len(expected_unpatched)
        or plan.root_ldlinux_size != len(staging.root_ldlinux_sys.data)
        or plan.root_ldlinux_sha256 != expected_unpatched_sha256
        or plan.root_ldlinux_sha256 != staging.root_ldlinux_sys.sha256
        or staging.root_ldlinux_sys.path != "ldlinux.sys"
        or staging.root_ldlinux_sys.disposition is not StageDisposition.CREATE
        or not hmac.compare_digest(staging.root_ldlinux_sys.data, expected_unpatched)
        or staging.ldlinux_c32.data != c32.data
        or staging.ldlinux_c32.sha256 != c32.sha256
        or plan.source_manifest_sha256 != manifest.manifest_sha256
        or plan.c32_bundle_sha256 != _bundle_digest(c32_bundle)
        or plan.payload_bundle_sha256 != _bundle_digest(payload_bundle)
    ):
        raise SyslinuxIsoFat32Error(
            "The Syslinux ISO, bundle, loader, and configuration bindings disagree",
        )

    try:
        validate_private_fat32_plan(
            plan.private_plan,
            cancel_check=cancel_check,
        )
    except PrivateFat32Error as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    private = plan.private_plan
    if (
        private.source_root != str(plan.staging_result.destination)
        or tuple(item.source for item in private.directories)
        != manifest.source_directories
        or tuple(item.source for item in private.files) != manifest.source_files
        or private.total_content_bytes != manifest.total_bytes
        or private.total_content_bytes != plan.staging_result.bytes_staged
        or len(private.directories) != plan.staging_result.directories
        or len(private.files) != plan.staging_result.files
        or private.root_ldlinux_size != plan.root_ldlinux_size
        or private.root_ldlinux_sha256 != plan.root_ldlinux_sha256
    ):
        raise SyslinuxIsoFat32Error(
            "The private FAT32 plan belongs to another published staging tree",
        )
    private_files = _private_files(private)
    _require_private_file(
        private_files,
        staging.root_ldlinux_sys,
        "root ldlinux.sys",
    )
    _require_private_file(private_files, staging.ldlinux_c32, "ldlinux.c32")
    if staging.root_redirect is not None:
        if staging.root_redirect.disposition is not StageDisposition.CREATE:
            raise SyslinuxIsoFat32Error("The root Syslinux redirect is not exclusive")
        _require_private_file(
            private_files,
            staging.root_redirect,
            "root Syslinux redirect",
        )
    config = private_files.get(staging.config_path)
    if (
        config is None
        or not hmac.compare_digest(config.sha256, staging.config_sha256)
    ):
        raise SyslinuxIsoFat32Error(
            "The private FAT32 plan does not bind the selected Syslinux configuration",
        )
    if not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256):
        raise SyslinuxIsoFat32Error(
            "The Syslinux ISO FAT32 plan is forged or inconsistent",
        )
    _check_cancelled(cancel_check)
    return manifest


def build_syslinux_iso_fat32_plan(
    iso_plan: IsoStagingPlan,
    staging_result: IsoStagingResult,
    workspace: Path | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> SyslinuxIsoFat32Plan:
    """Bind one authenticated published ISO tree to an anonymous FAT32 plan."""

    try:
        manifest = validate_published_syslinux_staging(
            iso_plan,
            staging_result,
            cancel_check=cancel_check,
        )
    except IsoStagingSafetyError as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    _require_compatible_source_layout(iso_plan)
    staging = iso_plan.syslinux_staging
    c32_bundle = iso_plan.syslinux_c32_bundle
    payload_bundle = iso_plan.syslinux_payload_bundle
    if (
        type(staging) is not SyslinuxStagingPlan
        or type(c32_bundle) is not BoundBootBundle
        or type(payload_bundle) is not BoundBootBundle
    ):
        raise SyslinuxIsoFat32Error("The Syslinux ISO binding is incomplete")
    try:
        bind_syslinux_c32_bundle(c32_bundle)
        payloads = bind_syslinux_bundle(payload_bundle)
        private_plan = build_private_fat32_plan(
            staging_result.destination,
            workspace,
            image_size=image_size,
            expected_root_ldlinux=payloads.ldlinux_sys + make_empty_adv(),
            cancel_check=cancel_check,
        )
    except (PrivateFat32Error, SyslinuxStagingError, SyslinuxPatchError) as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    candidate = SyslinuxIsoFat32Plan(
        iso_plan,
        staging_result,
        private_plan,
        manifest.manifest_sha256,
        _bundle_digest(c32_bundle),
        _bundle_digest(payload_bundle),
        staging.version,
        staging.dependency_key,
        staging.config_directory,
        len(staging.root_ldlinux_sys.data),
        staging.root_ldlinux_sys.sha256,
        "",
    )
    plan = SyslinuxIsoFat32Plan(
        iso_plan,
        staging_result,
        private_plan,
        candidate.source_manifest_sha256,
        candidate.c32_bundle_sha256,
        candidate.payload_bundle_sha256,
        candidate.version,
        candidate.dependency_key,
        candidate.config_directory,
        candidate.root_ldlinux_size,
        candidate.root_ldlinux_sha256,
        _plan_digest(candidate),
    )
    object.__setattr__(
        plan,
        "_receipt",
        _CompositePlanReceipt(
            _PLAN_WITNESS,
            plan,
            iso_plan,
            staging_result,
            private_plan,
            _plan_snapshot(plan),
        ),
    )
    _validate_relationships(plan, cancel_check=cancel_check)
    return plan


def validate_syslinux_iso_fat32_plan(
    plan: SyslinuxIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Rehash every live source and revalidate all composite bindings."""

    _validate_relationships(plan, cancel_check=cancel_check)


class PreparedSyslinuxIsoFat32:
    """Exclusive owner of one patched, attested anonymous FAT32 image."""

    __slots__ = ("_image", "_result", "_witness")

    def __init__(
        self,
        image: AnonymousFat32Image,
        result: SyslinuxIsoFat32Result,
        witness: object,
    ) -> None:
        if (
            witness is not _OWNER_WITNESS
            or type(image) is not AnonymousFat32Image
            or image.state is not PrivateFat32State.PATCHED_ATTESTED
            or type(result) is not SyslinuxIsoFat32Result
        ):
            raise SyslinuxIsoFat32Error("Prepared images are executor-owned")
        self._image: AnonymousFat32Image | None = image
        self._result = result
        self._witness = witness

    @property
    def result(self) -> SyslinuxIsoFat32Result:
        if self._witness is not _OWNER_WITNESS:
            raise SyslinuxIsoFat32Error("The prepared image owner is invalid")
        return self._result

    def chunks(self, chunk_bytes: int = 4 * 1024 * 1024) -> Iterator[bytes]:
        if self._witness is not _OWNER_WITNESS or self._image is None:
            raise SyslinuxIsoFat32Error("The prepared image is closed")
        return self._image.chunks(chunk_bytes)

    def close(self) -> None:
        image = self._image
        self._image = None
        if image is not None:
            image.close()

    def __enter__(self) -> PreparedSyslinuxIsoFat32:
        if self._image is None:
            raise SyslinuxIsoFat32Error("The prepared image is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def prepare_syslinux_iso_fat32(
    plan: SyslinuxIsoFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
    progress: Progress = lambda _stage, _path, _done, _total: None,
) -> PreparedSyslinuxIsoFat32:
    """Build, patch, and return only a patched-attested anonymous image owner."""

    _validate_relationships(plan, cancel_check=cancel_check)
    staging = plan.iso_plan.syslinux_staging
    payload_bundle = plan.iso_plan.syslinux_payload_bundle
    if type(staging) is not SyslinuxStagingPlan or type(payload_bundle) is not BoundBootBundle:
        raise SyslinuxIsoFat32Error("The Syslinux execution binding is incomplete")
    try:
        payloads = bind_syslinux_bundle(payload_bundle)
    except SyslinuxPatchError as error:
        raise SyslinuxIsoFat32Error(str(error)) from error
    expected_unpatched = payloads.ldlinux_sys + make_empty_adv()
    image: AnonymousFat32Image | None = None
    try:
        def builder_progress(
            stage: str,
            path: str,
            done: int,
            total: int,
        ) -> None:
            progress(
                "FAT32 image built" if stage == "Complete" else stage,
                path,
                done,
                total,
            )

        image = PrivateFat32Builder().execute(
            plan.private_plan,
            cancel_check=cancel_check,
            progress=builder_progress,
        )
        if (
            type(image) is not AnonymousFat32Image
            or image.state is not PrivateFat32State.UNPATCHED_ATTESTED
            or image.plan is not plan.private_plan
            or image.result.plan_sha256 != plan.private_plan.plan_sha256
            or image.result.image_sha256 == ""
        ):
            raise SyslinuxIsoFat32Error(
                "The private FAT32 builder returned an invalid image",
            )
        _check_cancelled(cancel_check)
        progress(
            "Patching Syslinux",
            "ldlinux.sys",
            plan.private_plan.total_content_bytes,
            plan.private_plan.total_content_bytes,
        )
        transaction_result = patch_private_fat32_syslinux(
            image,
            payload_bundle,
            config_directory=staging.config_directory,
            expected_unpatched=expected_unpatched,
            cancel_check=cancel_check,
        )
        if (
            type(transaction_result) is not SyslinuxRegularFileTransactionResult
            or image.state is not PrivateFat32State.PATCHED_ATTESTED
            or image.transaction_result is not transaction_result
            or image.inspection.manifest_sha256 == image.result.manifest_sha256
            or not hmac.compare_digest(
                transaction_result.final_image_sha256,
                image.transaction_result.final_image_sha256,
            )
        ):
            raise SyslinuxIsoFat32Error(
                "The patched Syslinux image result is inconsistent",
            )
        result = SyslinuxIsoFat32Result(
            plan.plan_sha256,
            plan.private_plan.plan_sha256,
            transaction_result.plan_sha256,
            plan.version,
            plan.private_plan.disk_signature,
            plan.private_plan.volume_id,
            plan.private_plan.geometry.image_size,
            image.result.image_sha256,
            transaction_result.final_image_sha256,
            image.result.manifest_sha256,
            image.inspection.manifest_sha256,
            plan.root_ldlinux_sha256,
            transaction_result.patched_ldlinux_sha256,
            image.result.files_verified,
            image.result.directories_verified,
            image.result.bytes_verified,
        )
        try:
            progress(
                "Complete",
                "",
                plan.private_plan.total_content_bytes,
                plan.private_plan.total_content_bytes,
            )
        except Exception:
            pass
        owner = PreparedSyslinuxIsoFat32(image, result, _OWNER_WITNESS)
        image = None
        return owner
    except SyslinuxIsoFat32Cancelled:
        raise
    except BaseException as error:
        if isinstance(error, SyslinuxIsoFat32Error):
            raise
        if isinstance(error, PrivateFat32Error):
            raise SyslinuxIsoFat32Error(str(error)) from error
        raise
    finally:
        if type(image) is AnonymousFat32Image:
            image.close()
