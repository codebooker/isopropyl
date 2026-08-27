from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from .images import ImageInspection, ImageMember, MAX_IMAGE_MEMBERS


CATALOG_VERSION = 1
MAX_CATALOG_BYTES = 64 * 1024
MAX_POLICY_COUNT = 32
MAX_POLICY_ID_BYTES = 64
MAX_DISTRIBUTION_BYTES = 96
MAX_REASON_BYTES = 512
MAX_SOURCE_DESCRIPTION_BYTES = 256
MAX_POLICY_PATH_BYTES = 1024

_POLICY_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_MATCH_KINDS = frozenset({
    "exact_file",
    "direct_child_file",
    "direct_named_file_in_root_fragment",
})
_MEMBER_KINDS = frozenset({"file", "directory", "symlink"})
_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz",
)


class DistroPolicyError(ValueError):
    """Base class for invalid bundled policy data or inspection evidence."""


class DistroPolicyCatalogError(DistroPolicyError):
    """The bundled compatibility-policy catalog is malformed or unsupported."""


class DistroPolicyEvidenceError(DistroPolicyError):
    """A supposedly complete member catalog cannot be matched safely."""


@dataclass(frozen=True)
class DistroIsoPolicy:
    policy_id: str
    distribution: str
    reason: str
    source_url: str
    source_description: str
    match_kind: str
    path: str
    fragment: str = ""
    filename: str = ""


@dataclass(frozen=True)
class DistroIsoExclusion:
    """Evidence that filesystem-aware ISO reconstruction must be excluded.

    This deliberately carries no write-mode value. Callers may use a match only
    to remove their extracted-ISO capability; it cannot enable or recommend DD.
    """

    policy_id: str
    distribution: str
    reason: str
    source_url: str
    source_description: str


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DistroPolicyCatalogError(
                f"Compatibility-policy catalog repeats field {key!r}"
            )
        result[key] = value
    return result


def _exact_object(
    value: object, expected: set[str], label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise DistroPolicyCatalogError(
            f"{label} has unknown or missing fields"
        )
    return value


def _bounded_text(value: object, maximum: int, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise DistroPolicyCatalogError(f"{label} must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise DistroPolicyCatalogError(f"{label} is not valid Unicode") from error
    if len(encoded) > maximum:
        raise DistroPolicyCatalogError(f"{label} is too long")
    if any(ord(character) < 0x20 for character in value):
        raise DistroPolicyCatalogError(f"{label} contains control characters")
    return value


def _canonical_policy_path(value: object, label: str) -> str:
    path = _bounded_text(value, MAX_POLICY_PATH_BYTES, label)
    if path != unicodedata.normalize("NFC", path.translate(_ASCII_LOWER)):
        raise DistroPolicyCatalogError(
            f"{label} must use canonical lowercase NFC spelling"
        )
    if (
        path.startswith("/") or path.endswith("/") or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise DistroPolicyCatalogError(f"{label} is not a safe relative path")
    return path


def _https_source(value: object) -> str:
    source = _bounded_text(value, 2048, "Policy source URL")
    try:
        parsed = urlsplit(source)
        port = parsed.port
    except ValueError as error:
        raise DistroPolicyCatalogError("Policy source URL is invalid") from error
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 443) or not parsed.path.startswith("/")
        or parsed.query or source != source.strip()
    ):
        raise DistroPolicyCatalogError("Policy source URL must be safe HTTPS")
    return source


def _parse_match(value: object, label: str) -> tuple[str, str, str, str]:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise DistroPolicyCatalogError(f"{label} match is invalid")
    kind = value["kind"]
    if kind not in _MATCH_KINDS:
        raise DistroPolicyCatalogError(f"{label} match kind is unsupported")
    expected = {
        "exact_file": {"kind", "path"},
        "direct_child_file": {"kind", "root"},
        "direct_named_file_in_root_fragment": {
            "kind", "root_prefix", "fragment", "filename",
        },
    }[kind]
    match = _exact_object(value, expected, f"{label} match")
    if kind == "direct_named_file_in_root_fragment":
        path = _canonical_policy_path(
            match["root_prefix"], f"{label} root prefix",
        )
        fragment = _canonical_policy_path(
            match["fragment"], f"{label} fragment",
        )
        filename = _canonical_policy_path(
            match["filename"], f"{label} filename",
        )
        if "/" in path or "/" in fragment or "/" in filename:
            raise DistroPolicyCatalogError(
                f"{label} match parts must each be one path component"
            )
        return kind, path, fragment, filename
    if kind == "direct_child_file":
        path = _canonical_policy_path(match["root"], f"{label} root")
        if "/" in path:
            raise DistroPolicyCatalogError(
                f"{label} root must be one top-level component"
            )
        return kind, path, "", ""
    path = _canonical_policy_path(match["path"], f"{label} path")
    return kind, path, "", ""


def _catalog_bytes(path: Path | None) -> bytes:
    try:
        source = (
            resources.files("isopropyl").joinpath(
                "data/distro-write-policies-v1.json"
            )
            if path is None else path
        )
        with source.open("rb") as stream:
            data = stream.read(MAX_CATALOG_BYTES + 1)
    except OSError as error:
        raise DistroPolicyCatalogError(
            f"Could not read compatibility-policy catalog: {error}"
        ) from error
    if len(data) > MAX_CATALOG_BYTES:
        raise DistroPolicyCatalogError(
            "Compatibility-policy catalog exceeds its size limit"
        )
    return data


def load_distro_iso_policies(
    path: Path | None = None,
) -> tuple[DistroIsoPolicy, ...]:
    """Strictly load the bundled, network-inactive exclusion-policy catalog."""

    try:
        root = json.loads(
            _catalog_bytes(path).decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except DistroPolicyCatalogError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DistroPolicyCatalogError(
            "Compatibility-policy catalog is not valid UTF-8 JSON"
        ) from error
    root = _exact_object(root, {"catalog_version", "policies"}, "Catalog")
    if (
        type(root["catalog_version"]) is not int
        or root["catalog_version"] != CATALOG_VERSION
    ):
        raise DistroPolicyCatalogError(
            "Unsupported compatibility-policy catalog version"
        )
    raw_policies = root["policies"]
    if (
        type(raw_policies) is not list or not raw_policies
        or len(raw_policies) > MAX_POLICY_COUNT
    ):
        raise DistroPolicyCatalogError(
            "Compatibility-policy catalog has an invalid policy count"
        )

    policies: list[DistroIsoPolicy] = []
    identifiers: set[str] = set()
    matches: set[tuple[str, str, str, str]] = set()
    fields = {
        "id", "distribution", "reason", "source_url", "source_description",
        "match",
    }
    for index, raw_policy in enumerate(raw_policies):
        label = f"Policy {index + 1}"
        item = _exact_object(raw_policy, fields, label)
        policy_id = _bounded_text(item["id"], MAX_POLICY_ID_BYTES, f"{label} ID")
        if not _POLICY_ID.fullmatch(policy_id):
            raise DistroPolicyCatalogError(f"{label} ID is not canonical")
        if policy_id in identifiers:
            raise DistroPolicyCatalogError("Compatibility-policy IDs are duplicated")
        distribution = _bounded_text(
            item["distribution"], MAX_DISTRIBUTION_BYTES, f"{label} distribution",
        )
        reason = _bounded_text(item["reason"], MAX_REASON_BYTES, f"{label} reason")
        source_url = _https_source(item["source_url"])
        source_description = _bounded_text(
            item["source_description"], MAX_SOURCE_DESCRIPTION_BYTES,
            f"{label} source description",
        )
        kind, policy_path, fragment, filename = _parse_match(
            item["match"], label,
        )
        match_key = kind, policy_path, fragment, filename
        if match_key in matches:
            raise DistroPolicyCatalogError(
                "Compatibility-policy match predicates are duplicated"
            )
        identifiers.add(policy_id)
        matches.add(match_key)
        policies.append(DistroIsoPolicy(
            policy_id, distribution, reason, source_url, source_description,
            kind, policy_path, fragment, filename,
        ))
    return tuple(policies)


@lru_cache(maxsize=1)
def _bundled_policies() -> tuple[DistroIsoPolicy, ...]:
    return load_distro_iso_policies()


def _canonical_member_path(path: str) -> str:
    if type(path) is not str or not path or "\x00" in path:
        raise DistroPolicyEvidenceError("Image member path is not valid text")
    try:
        encoded = path.encode("utf-8")
    except UnicodeError as error:
        raise DistroPolicyEvidenceError(
            "Image member path is not valid Unicode"
        ) from error
    if len(encoded) > MAX_POLICY_PATH_BYTES:
        raise DistroPolicyEvidenceError("Image member path is too long")
    if path.startswith("/") or path.endswith("/") or "\\" in path:
        raise DistroPolicyEvidenceError("Image member path is not safely relative")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise DistroPolicyEvidenceError("Image member path is not canonical")
    normalized = tuple(
        unicodedata.normalize("NFC", part.translate(_ASCII_LOWER))
        for part in parts
    )
    if any(
        not part or any(ord(character) < 0x20 for character in part)
        for part in normalized
    ):
        raise DistroPolicyEvidenceError("Image member path contains unsafe characters")
    return "/".join(normalized)


def _normalized_members(
    members: tuple[ImageMember, ...],
) -> tuple[tuple[str, str], ...]:
    if type(members) is not tuple:
        raise DistroPolicyEvidenceError("Image members must be an immutable tuple")
    if len(members) > MAX_IMAGE_MEMBERS:
        raise DistroPolicyEvidenceError("Image member catalog exceeds its bound")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for member in members:
        if (
            type(member) is not ImageMember or type(member.kind) is not str
            or type(member.size) is not int or member.size < 0
            or type(member.link_target) is not str
            or (
                member.modified_ns is not None
                and (
                    type(member.modified_ns) is not int
                    or member.modified_ns < 0
                )
            )
        ):
            raise DistroPolicyEvidenceError("Image member has an invalid type")
        if member.kind not in _MEMBER_KINDS:
            raise DistroPolicyEvidenceError("Image member kind is unsupported")
        if (
            (member.kind == "symlink" and not member.link_target)
            or (member.kind != "symlink" and member.link_target)
        ):
            raise DistroPolicyEvidenceError(
                "Image member kind and link target are inconsistent"
            )
        path = _canonical_member_path(member.path)
        if path in seen:
            raise DistroPolicyEvidenceError(
                "Image member catalog has a case-insensitive path collision"
            )
        seen.add(path)
        if member.kind != "symlink":
            normalized.append((path, member.kind))
    return tuple(normalized)


def _policy_matches(
    policy: DistroIsoPolicy, members: tuple[tuple[str, str], ...],
) -> bool:
    if policy.match_kind == "exact_file":
        return any(
            path == policy.path and kind == "file" for path, kind in members
        )
    if policy.match_kind == "direct_child_file":
        return any(
            kind == "file" and path.count("/") == 1
            and path.partition("/")[0] == policy.path
            for path, kind in members
        )
    if policy.match_kind == "direct_named_file_in_root_fragment":
        for path, kind in members:
            root, separator, filename = path.partition("/")
            if (
                kind == "file" and separator and "/" not in filename
                and root.startswith(policy.path)
                and policy.fragment in root
                and filename == policy.filename
            ):
                return True
        return False
    raise DistroPolicyEvidenceError("Loaded policy has an invalid match kind")


def _validate_supplied_policies(
    policies: tuple[DistroIsoPolicy, ...],
) -> None:
    identifiers: set[str] = set()
    predicates: set[tuple[str, str, str, str]] = set()
    try:
        for index, policy in enumerate(policies):
            label = f"Policy {index + 1}"
            policy_id = _bounded_text(
                policy.policy_id, MAX_POLICY_ID_BYTES, f"{label} ID",
            )
            if not _POLICY_ID.fullmatch(policy_id):
                raise DistroPolicyCatalogError(f"{label} ID is not canonical")
            _bounded_text(
                policy.distribution, MAX_DISTRIBUTION_BYTES,
                f"{label} distribution",
            )
            _bounded_text(policy.reason, MAX_REASON_BYTES, f"{label} reason")
            _https_source(policy.source_url)
            _bounded_text(
                policy.source_description, MAX_SOURCE_DESCRIPTION_BYTES,
                f"{label} source description",
            )
            if (
                type(policy.match_kind) is not str
                or policy.match_kind not in _MATCH_KINDS
            ):
                raise DistroPolicyCatalogError(
                    f"{label} match kind is unsupported"
                )
            path = _canonical_policy_path(policy.path, f"{label} path")
            fragment = policy.fragment
            filename = policy.filename
            if policy.match_kind == "exact_file":
                if fragment != "" or filename != "":
                    raise DistroPolicyCatalogError(
                        f"{label} exact-file fields are inconsistent"
                    )
            elif policy.match_kind == "direct_child_file":
                if "/" in path or fragment != "" or filename != "":
                    raise DistroPolicyCatalogError(
                        f"{label} direct-child fields are inconsistent"
                    )
            else:
                fragment = _canonical_policy_path(
                    fragment, f"{label} fragment",
                )
                filename = _canonical_policy_path(
                    filename, f"{label} filename",
                )
                if "/" in path or "/" in fragment or "/" in filename:
                    raise DistroPolicyCatalogError(
                        f"{label} match parts must be path components"
                    )
            predicate = policy.match_kind, path, fragment, filename
            if policy_id in identifiers or predicate in predicates:
                raise DistroPolicyCatalogError(
                    "Supplied compatibility policies are duplicated"
                )
            identifiers.add(policy_id)
            predicates.add(predicate)
    except DistroPolicyCatalogError as error:
        raise DistroPolicyEvidenceError(
            f"Supplied policy data is invalid: {error}"
        ) from error


def match_distro_member_exclusion(
    members: tuple[ImageMember, ...],
    policies: tuple[DistroIsoPolicy, ...] | None = None,
) -> DistroIsoExclusion | None:
    """Match an explicitly supplied immutable original-image member catalog.

    Staging and execution callers should pass only their identity-bound base ISO
    catalog. There is no overlay parameter, ambient catalog, or filename input,
    so additive entries are never included implicitly.
    """

    selected = _bundled_policies() if policies is None else policies
    if (
        type(selected) is not tuple or not selected
        or len(selected) > MAX_POLICY_COUNT
        or any(type(policy) is not DistroIsoPolicy for policy in selected)
    ):
        raise DistroPolicyEvidenceError("Policy set is not a bounded immutable tuple")
    if policies is not None:
        _validate_supplied_policies(selected)
    normalized = _normalized_members(members)
    for policy in selected:
        if _policy_matches(policy, normalized):
            return DistroIsoExclusion(
                policy.policy_id, policy.distribution, policy.reason,
                policy.source_url, policy.source_description,
            )
    return None


def match_distro_iso_exclusion(
    inspection: ImageInspection,
    policies: tuple[DistroIsoPolicy, ...] | None = None,
) -> DistroIsoExclusion | None:
    """Return a matched ISO-mode exclusion from complete original-image evidence.

    No filename, overlay entry, or target fact is accepted by this API. A result
    can only justify subtracting filesystem-aware ISO mode from choices already
    established elsewhere.
    """

    if type(inspection) is not ImageInspection:
        raise DistroPolicyEvidenceError("Policy matching requires ImageInspection")
    if (
        inspection.contents_scanned is not True
        or (
            inspection.is_iso9660 is not True
            and inspection.kind != "Optical ISO"
        )
    ):
        return None
    return match_distro_member_exclusion(inspection.members, policies)
