from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Read-only boot payload identity inspection.

This module deliberately keeps two different concepts separate:

* a host program such as ``7z`` is only an archive reader;
* GRUB/Syslinux files inside an image are boot payloads whose identity may
  become a future bootloader dependency.

Nothing here invokes a host bootloader installer, downloads a file, or writes
to a block device.  Ambiguous identities never produce a dependency key.
"""

import os
import re
import selectors
import shutil
import stat
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_BOOT_BLOB_SIZE = 64 * 1024 * 1024
MAX_BOOT_MEMBERS = 64
_TRUSTED_7Z_PATH = "/usr/bin:/bin"
_TRUSTED_7Z_DIRECTORIES = frozenset(_TRUSTED_7Z_PATH.split(":"))

_GRUB_MARKERS = (
    b"GNU GRUB  version %s",
    b"GNU GRUB version %s",
    b"GRUB  version %s",
    b"GRUB version %s",
)
_VERSION_TEXT = re.compile(
    rb"[1-9][0-9]{0,2}(?:\.[0-9]{1,3})+(?:[-+~._:][0-9A-Za-z.+~:_-]{1,63})?"
)
_SYSLINUX_MARKER = re.compile(
    rb"(?P<family>ISO|SYS)LINUX[ \t]+"
    rb"(?P<version>[1-9][0-9]{0,2}\.[0-9]{1,3})"
    rb"(?P<tail>[^\x00\r\n]{0,96})"
)


@dataclass(frozen=True)
class BootloaderIdentity:
    """Identity derived from one boot payload.

    ``version`` is the advertised upstream version. ``build`` is a stronger
    package/build identifier when the payload contains one.  A missing GRUB
    build is intentional: downstream GRUB patches can be incompatible while
    retaining the same upstream version.
    """

    family: str
    version: str | None
    build: str | None
    source: str
    custom_build: bool | None
    ambiguous: bool = False
    candidates: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    @property
    def exact(self) -> bool:
        return self.version is not None and not self.ambiguous

    @property
    def dependency_key(self) -> str | None:
        """Return a catalog key only when artifact compatibility is known.

        A bare GRUB version is not enough.  In contrast, released Syslinux and
        Isolinux payloads encode the version used by their matching modules.
        """

        if not self.exact or self.build is None:
            return None
        slug = "syslinux" if self.family in {"Syslinux", "Isolinux"} else self.family.casefold()
        return f"{slug}:{self.build}"


@dataclass(frozen=True)
class BootloaderAnalysis:
    identities: tuple[BootloaderIdentity, ...]
    issues: tuple[str, ...] = ()
    complete: bool = True

    def resolved(self, family: str) -> BootloaderIdentity | None:
        """Resolve one family, failing closed on conflicting image members."""

        if not self.complete:
            return None
        wanted = _family_group(family)
        matches = [item for item in self.identities if _family_group(item.family) == wanted]
        if not matches or any(item.ambiguous for item in matches):
            return None
        signatures = {(item.version, item.build, item.custom_build) for item in matches}
        if len(signatures) != 1:
            return None
        return matches[0]

    @property
    def dependency_keys(self) -> tuple[str, ...]:
        keys: list[str] = []
        for family in dict.fromkeys(_family_group(item.family) for item in self.identities):
            identity = self.resolved(family)
            if identity and identity.dependency_key:
                keys.append(identity.dependency_key)
        return tuple(keys)


def _family_group(family: str) -> str:
    return "Syslinux/Isolinux" if family in {"Syslinux", "Isolinux", "Syslinux/Isolinux"} else family


def _nul_strings(data: bytes, *, limit: int = 128) -> list[bytes]:
    """Return bounded printable NUL-delimited strings from untrusted bytes."""

    result: list[bytes] = []
    for token in data.split(b"\0"):
        token = token.strip(b"\r\n \t")
        if 0 < len(token) <= limit and all(0x20 <= byte < 0x7f for byte in token):
            result.append(token)
    return result


def _version_after_marker(blob: bytes, offset: int, marker: bytes) -> bytes | None:
    # The version is normally the next C string. Some downstream builds add a
    # newline or an extra NUL, so inspect a small bounded region.
    nearby = _nul_strings(blob[offset + len(marker):offset + len(marker) + 160])
    return next((token for token in nearby if _VERSION_TEXT.fullmatch(token)), None)


def identify_grub_blob(
    blob: bytes, source: str = "<memory>", *, nonstandard_prefix: bool = False
) -> BootloaderIdentity | None:
    """Identify a GRUB module/EFI payload using embedded build strings.

    The parser does not treat the mere word ``GRUB`` as evidence. It requires
    GRUB's version format string followed by a syntactically valid version.
    """

    if len(blob) > MAX_BOOT_BLOB_SIZE:
        raise ValueError("Boot payload exceeds the inspection size limit")

    bases: set[str] = set()
    marker_names: set[str] = set()
    marker_offsets: list[tuple[int, bytes]] = []
    for marker in _GRUB_MARKERS:
        start = 0
        while (offset := blob.find(marker, start)) >= 0:
            marker_offsets.append((offset, marker))
            marker_names.add(marker.decode("ascii"))
            version = _version_after_marker(blob, offset, marker)
            if version is not None:
                bases.add(version.decode("ascii"))
            start = offset + len(marker)

    if not bases:
        return None

    evidence = [f"format marker: {name}" for name in sorted(marker_names)]
    custom_flags: list[str] = []
    if b"grub_debug_is_enabled" in blob:
        custom_flags.append("downstream grub_debug_is_enabled symbol")
    if nonstandard_prefix:
        custom_flags.append("nonstandard /boot/grub2 prefix")
    evidence.extend(custom_flags)

    if len(bases) != 1:
        candidates = tuple(sorted(bases))
        return BootloaderIdentity(
            "GRUB", None, None, source, None, True, candidates, tuple(evidence)
        )

    version = next(iter(bases))
    build_candidates: set[str] = set()
    prefix_bytes = version.encode("ascii")
    # Package versions are commonly stored close to the version format string
    # but are not necessarily the immediately following C string.
    for offset, marker in marker_offsets:
        window = blob[offset + len(marker):offset + len(marker) + 4096]
        for token in _nul_strings(window):
            if (
                token.startswith(prefix_bytes)
                and token != prefix_bytes
                and _VERSION_TEXT.fullmatch(token)
            ):
                build_candidates.add(token.decode("ascii"))

    if len(build_candidates) > 1:
        candidates = tuple(sorted(build_candidates))
        return BootloaderIdentity(
            "GRUB", version, None, source, True, True, candidates, tuple(evidence)
        )

    build = next(iter(build_candidates), None)
    custom: bool | None = True if build or custom_flags else None
    if build:
        evidence.append(f"package build: {build}")
    elif custom_flags:
        evidence.append("custom build detected, but no exact package build was embedded")
    else:
        evidence.append("upstream version only; downstream patch identity is unknown")
    return BootloaderIdentity(
        "GRUB", version, build, source, custom, False,
        (build or version,), tuple(evidence),
    )


def _syslinux_build(version: str, tail: bytes) -> tuple[str | None, bool | None]:
    text = tail.decode("ascii", errors="ignore").strip(" \t*")
    if not text:
        return version, False
    token = text.split()[0].strip("*")
    if token.startswith(version) and token != version:
        suffix = token[len(version):]
    elif re.fullmatch(r"[0-9A-Za-z.+~:_-]{1,63}", token):
        # Syslinux displays release dates as a second token. Normalize the
        # separator to '-' so the identity is safe as one catalog component.
        suffix = "-" + token
    else:
        # Invalid build metadata must not become a path/catalog key.
        return None, None
    return version + suffix, bool(suffix)


def identify_syslinux_blob(blob: bytes, source: str = "<memory>") -> BootloaderIdentity | None:
    """Identify Syslinux/Isolinux and retain its encoded build suffix."""

    if len(blob) > MAX_BOOT_BLOB_SIZE:
        raise ValueError("Boot payload exceeds the inspection size limit")

    found: set[tuple[str, str | None, bool | None]] = set()
    for match in _SYSLINUX_MARKER.finditer(blob):
        family = "Isolinux" if match.group("family") == b"ISO" else "Syslinux"
        version = match.group("version").decode("ascii")
        build, custom = _syslinux_build(version, match.group("tail"))
        found.add((family, build, custom))
    if not found:
        return None

    if len(found) != 1 or any(build is None for _, build, _ in found):
        candidates = tuple(sorted(
            f"{family} {build or '<invalid build metadata>'}"
            for family, build, _ in found
        ))
        return BootloaderIdentity(
            "Syslinux/Isolinux", None, None, source, None, True, candidates,
            ("conflicting embedded Syslinux/Isolinux markers",),
        )

    family, build, custom = next(iter(found))
    assert build is not None and custom is not None
    # The upstream part is always the leading major.minor pair.
    version_match = re.match(r"[0-9]+\.[0-9]+", build)
    assert version_match is not None
    version = version_match.group(0)
    evidence = (f"embedded {family.upper()} version marker",)
    return BootloaderIdentity(
        family, version, build, source, custom, False, (build,), evidence
    )


def analyze_bootloader_blob(blob: bytes, source: str = "<memory>") -> BootloaderAnalysis:
    """Analyze one payload without guessing its family from its filename."""

    identities = tuple(
        item for item in (
            identify_grub_blob(blob, source), identify_syslinux_blob(blob, source)
        ) if item is not None
    )
    issues: tuple[str, ...] = ()
    if len(identities) > 1:
        issues = (f"{source} contains markers for more than one bootloader family",)
    return BootloaderAnalysis(identities, issues)


def _normalized_member(path: str) -> str | None:
    text = path.replace("\\", "/")
    if (
        text.startswith("/") or text.startswith("//")
        or re.match(r"^[A-Za-z]:", text)
        or any(ord(char) < 0x20 for char in text)
    ):
        return None
    pure = PurePosixPath(text)
    if not text or ".." in pure.parts or any(char in text for char in "*?[]"):
        return None
    return pure.as_posix()


def _looks_like_bootloader_candidate(path: str) -> bool:
    lowered = path.replace("\\", "/").casefold()
    name = lowered.rsplit("/", 1)[-1]
    fallback_shape = lowered.lstrip("/")
    if re.match(r"^[a-z]:/", fallback_shape):
        fallback_shape = fallback_shape[3:]
    return bool(
        name in {"isolinux.bin", "syslinux.bin", "ldlinux.sys"}
        or (name in {"normal.mod", "core.img"} and "grub" in lowered)
        or (name.startswith("grub") and name.endswith(".efi"))
        or (fallback_shape.startswith("efi/boot/boot") and name.endswith(".efi"))
    )


def _bootloader_member_selection(
    paths: Iterable[str],
) -> tuple[tuple[str, ...], bool, bool]:
    """Select candidates and report whether the bounded selection overflowed."""

    selected: list[str] = []
    seen: set[str] = set()
    overflowed = False
    unsafe_candidate = False
    for original in paths:
        path = _normalized_member(original)
        if path is None:
            unsafe_candidate = unsafe_candidate or _looks_like_bootloader_candidate(original)
            continue
        lowered = path.casefold()
        name = PurePosixPath(lowered).name
        is_syslinux = name in {"isolinux.bin", "syslinux.bin", "ldlinux.sys"}
        is_grub_module = name in {"normal.mod", "core.img"} and "grub" in lowered
        is_grub_efi = name.startswith("grub") and name.endswith(".efi")
        is_fallback_efi = lowered.startswith("efi/boot/boot") and name.endswith(".efi")
        if not (is_syslinux or is_grub_module or is_grub_efi or is_fallback_efi):
            continue
        if path in seen:
            continue
        seen.add(path)
        if len(selected) >= MAX_BOOT_MEMBERS:
            overflowed = True
            break
        selected.append(path)
    return tuple(selected), overflowed, unsafe_candidate


def bootloader_member_paths(paths: Iterable[str]) -> tuple[str, ...]:
    """Select bounded boot payload candidates from an archive catalog.

    This compatibility helper returns only the selected paths. Authorization
    callers must use :func:`analyze_iso_bootloaders`, which also fails closed
    when the catalog contains more candidates than can be inspected.
    """

    selected, _overflowed, _unsafe_candidate = _bootloader_member_selection(paths)
    return selected


def analyze_bootloader_members(members: Mapping[str, bytes]) -> BootloaderAnalysis:
    """Analyze already-read ISO/archive members and detect member conflicts."""

    identities: list[BootloaderIdentity] = []
    issues: list[str] = []
    complete = True
    for source, blob in members.items():
        normalized = _normalized_member(source)
        if normalized is None:
            issues.append(f"Skipped unsafe archive member name: {source!r}")
            complete = False
            continue
        nonstandard = "/boot/grub2/" in f"/{normalized.casefold()}"
        try:
            grub = identify_grub_blob(blob, normalized, nonstandard_prefix=nonstandard)
            syslinux = identify_syslinux_blob(blob, normalized)
        except ValueError as error:
            issues.append(f"{normalized}: {error}")
            complete = False
            continue
        identities.extend(item for item in (grub, syslinux) if item is not None)

    analysis = BootloaderAnalysis(tuple(identities), tuple(issues), complete)
    for family in dict.fromkeys(_family_group(item.family) for item in identities):
        matches = [item for item in identities if _family_group(item.family) == family]
        if complete and matches and analysis.resolved(family) is None:
            issues.append(f"Conflicting {family} identities across image members")
    return BootloaderAnalysis(tuple(identities), tuple(issues), complete)


MemberReader = Callable[[Path, str], bytes]


def _trusted_7z() -> str | None:
    executable = shutil.which("7z", path=_TRUSTED_7Z_PATH)
    if not executable:
        return None
    normalized = os.path.normpath(executable)
    if (
        not os.path.isabs(normalized)
        or os.path.dirname(normalized) not in _TRUSTED_7Z_DIRECTORIES
        or os.path.basename(normalized) != "7z"
    ):
        return None
    return normalized


def read_archive_member_with_7z(
    image: Path, member: str, *, timeout: float = 15.0,
    image_fd: int | None = None, cancel_check: Callable[[], None] | None = None,
    max_bytes: int = MAX_BOOT_BLOB_SIZE,
) -> bytes:
    """Read one exact member with deterministic optical-namespace selection.

    7-Zip chooses different filesystems for a ``.iso`` pathname and the same
    bytes exposed through ``/proc/self/fd``.  Prefer UDF, then ISO9660, before
    retaining auto-detection solely for non-optical compatibility.  Selected
    boot payloads are non-empty; an empty result therefore means that the
    member was absent from that candidate namespace.
    """

    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BOOT_BLOB_SIZE:
        raise ValueError("The boot payload read limit is invalid")
    executable = _trusted_7z()
    if not executable:
        raise OSError("7z is not installed; boot payload members were not read")
    deadline = time.monotonic() + timeout
    for archive_type in ("Udf", "Iso", None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out reading {member}")
        try:
            payload = _read_archive_member_once(
                executable,
                image,
                member,
                timeout=remaining,
                image_fd=image_fd,
                cancel_check=cancel_check,
                max_bytes=max_bytes,
                archive_type=archive_type,
            )
        except _ArchiveNamespaceUnavailable:
            continue
        if payload or archive_type is None:
            return payload
    raise OSError(f"7z could not read {member}")


class _ArchiveNamespaceUnavailable(OSError):
    pass


def _read_archive_member_once(
    executable: str,
    image: Path,
    member: str,
    *,
    timeout: float,
    image_fd: int | None,
    cancel_check: Callable[[], None] | None,
    max_bytes: int,
    archive_type: str | None,
) -> bytes:
    source = str(image) if image_fd is None else f"/proc/self/fd/{image_fd}"
    type_switch = () if archive_type is None else (f"-t{archive_type}",)
    process = subprocess.Popen(
        [
            executable, "x", "-so", "-spd", "-y", *type_switch,
            "--", source, member,
        ],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        pass_fds=(() if image_fd is None else (image_fd,)),
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        while True:
            if cancel_check is not None:
                cancel_check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out reading {member}")
            events = selector.select(min(remaining, 0.25))
            if not events:
                if process.poll() is not None:
                    break
                continue
            block = os.read(
                process.stdout.fileno(),
                min(1024 * 1024, max_bytes + 1 - len(output)),
            )
            if not block:
                break
            output.extend(block)
            if len(output) > max_bytes:
                raise ValueError(f"{member} exceeds the inspection size limit")
        if cancel_check is not None:
            cancel_check()
        returncode = process.wait(timeout=1)
        if returncode:
            raise _ArchiveNamespaceUnavailable(
                f"7z could not read {member} as {archive_type or 'auto'}"
            )
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        try:
            process.stdout.close()
        except OSError:
            pass


def analyze_iso_bootloaders(
    image: Path, member_paths: Iterable[str], *, reader: MemberReader | None = None,
    timeout: float = 30.0, image_fd: int | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> BootloaderAnalysis:
    """Read selected image members and analyze payload identity.

    ``reader`` is injectable so callers/tests can supply an ISO library. The
    default reader uses host ``7z`` strictly as an unprivileged archive reader.
    """

    if image_fd is None:
        if not image.is_file():
            raise OSError("The selected image is not a regular file")
    elif not stat.S_ISREG(os.fstat(image_fd).st_mode):
        raise OSError("The selected image descriptor is not a regular file")
    started = time.monotonic()
    blobs: dict[str, bytes] = {}
    issues: list[str] = []
    selected, overflowed, unsafe_candidate = _bootloader_member_selection(member_paths)
    complete = not overflowed and not unsafe_candidate
    if overflowed:
        issues.append(
            f"Bootloader inspection found more than {MAX_BOOT_MEMBERS} candidate "
            "payloads; exact dependency matching is disabled"
        )
    if unsafe_candidate:
        issues.append(
            "An unsafe bootloader candidate path was rejected; exact dependency "
            "matching is disabled"
        )
    for member in selected:
        if cancel_check is not None:
            cancel_check()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            issues.append("Bootloader inspection reached its overall time limit")
            complete = False
            break
        try:
            blobs[member] = (
                reader(image, member) if reader
                else read_archive_member_with_7z(
                    image, member, timeout=min(15.0, remaining), image_fd=image_fd,
                    cancel_check=cancel_check,
                )
            )
        except (OSError, TimeoutError, ValueError) as error:
            issues.append(f"{member}: {error}")
            complete = False
    if cancel_check is not None:
        cancel_check()
    result = analyze_bootloader_members(blobs)
    return BootloaderAnalysis(
        result.identities, tuple(issues) + result.issues,
        complete and result.complete,
    )
