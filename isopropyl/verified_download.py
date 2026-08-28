from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Authority-neutral, pinned-image download and publication transaction.

Authority adapters authenticate or otherwise bind one exact artifact, then
return a one-run :class:`ResolvedDownloadSource`.  A source URL is transport
state only: the artifact's filename, size, and SHA-256 remain authoritative.

The destination hardlink is the commit point.  In particular, no callback is
invoked between the final descriptor/path verification and ``os.link()``.
"""

import hashlib
import hmac
import os
import re
import stat
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


FREE_SPACE_RESERVE = 64 * 1024 * 1024
MAX_DOWNLOAD_TIMEOUT = 24 * 60 * 60
READ_SIZE = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
_DIRECTORY_FLAGS |= getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_URL_IN_ERROR = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_RESUME_STAGE_RE = re.compile(r"\.isopropyl-download-[0-9a-f]{64}\Z")
_MAX_ERROR_DETAIL = 512


class VerifiedDownloadError(RuntimeError):
    """A pinned artifact could not be downloaded or published safely."""


class VerifiedDownloadCancelled(VerifiedDownloadError):
    """The caller cancelled before the publication commit point."""


class DownloadResponse(Protocol):
    headers: object

    def read(self, size: int = -1) -> bytes: ...
    def geturl(self) -> str: ...
    def close(self) -> None: ...
    def getcode(self) -> int: ...


class PinnedDownloadArtifact(Protocol):
    id: str
    filename: str
    size: int
    sha256: str


OpenUrl = Callable[..., DownloadResponse]
Progress = Callable[[int, int], None]
CancelCheck = Callable[[], None]


@dataclass(frozen=True)
class ResolvedDownloadSource:
    """One exact, already-authorized URL for the current transaction only."""

    url: str


@dataclass(frozen=True)
class DownloadedVerifiedImage:
    path: Path
    release_id: str
    size: int
    sha256: str


@dataclass(frozen=True)
class DownloadErrorPolicy:
    error_type: type[VerifiedDownloadError] = VerifiedDownloadError
    cancelled_type: type[VerifiedDownloadCancelled] = VerifiedDownloadCancelled
    subject: str = "Image"
    hash_authority: str = "pinned"

    def error(self, message: str) -> VerifiedDownloadError:
        return self.error_type(message)

    def cancelled(self, message: str) -> VerifiedDownloadCancelled:
        return self.cancelled_type(message)


DEFAULT_ERROR_POLICY = DownloadErrorPolicy()


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirects are disabled for verified downloads",
            headers, fp,
        )


def default_urlopen(
    request: urllib.request.Request, *, timeout: float,
) -> DownloadResponse:
    """Open one request with redirects disabled at the transport boundary."""

    opener = urllib.request.build_opener(RejectRedirectHandler())
    return opener.open(request, timeout=timeout)  # type: ignore[return-value]


def safe_error_detail(error: BaseException) -> str:
    """Return bounded diagnostics without exposing a URL or its bearer query.

    Temporary CDN URLs can function as credentials.  HTTP errors deliberately
    expose only their numeric status.  Other exception text has every complete
    HTTP(S) URL removed before it can reach a dialog or log.
    """

    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP status {error.code}"
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        if isinstance(reason, OSError):
            detail = reason.strerror or reason.__class__.__name__
        else:
            detail = reason.__class__.__name__
    elif isinstance(error, OSError):
        detail = error.strerror or str(error) or error.__class__.__name__
    else:
        detail = str(error) or error.__class__.__name__
    detail = _URL_IN_ERROR.sub("<redacted URL>", detail)
    return detail[:_MAX_ERROR_DETAIL]


def check_cancel(
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> None:
    if cancel_check is not None:
        cancel_check()
    if cancel_event.is_set():
        raise policy.cancelled(f"{policy.subject} download was cancelled")


def deadline_check(
    deadline: float, *, policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> None:
    if time.monotonic() > deadline:
        raise policy.error(f"{policy.subject} download reached its overall time limit")


def open_response(
    opener: OpenUrl,
    request: urllib.request.Request,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> DownloadResponse:
    check_cancel(cancel_event, cancel_check, policy=policy)
    deadline_check(deadline, policy=policy)
    try:
        response = opener(
            request, timeout=min(30, max(0.001, deadline - time.monotonic()))
        )
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        detail = safe_error_detail(error)
        raise policy.error(f"Download connection failed: {detail}") from error
    try:
        check_cancel(cancel_event, cancel_check, policy=policy)
        deadline_check(deadline, policy=policy)
    except BaseException:
        try:
            response.close()
        except Exception:
            pass
        raise
    return response


def response_blocks(
    response: DownloadResponse,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> Iterable[bytes]:
    while True:
        check_cancel(cancel_event, cancel_check, policy=policy)
        deadline_check(deadline, policy=policy)
        try:
            block = response.read(READ_SIZE)
        except Exception as error:
            raise policy.error(
                f"Download read failed: {safe_error_detail(error)}"
            ) from error
        check_cancel(cancel_event, cancel_check, policy=policy)
        deadline_check(deadline, policy=policy)
        if not block:
            return
        if type(block) is not bytes:
            raise policy.error("Download returned non-byte data")
        yield block


def response_header(response: DownloadResponse, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    value = headers.get(name) if headers is not None and hasattr(headers, "get") else None
    return value if type(value) is str else None


def response_status(
    response: DownloadResponse,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> int:
    value = getattr(response, "status", None)
    if type(value) is not int:
        try:
            value = response.getcode()
        except Exception:
            value = None
    if type(value) is not int:
        raise policy.error("Download response omitted its HTTP status")
    return value


def validate_response_url(
    response: DownloadResponse,
    expected: str,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> None:
    try:
        final = response.geturl()
    except Exception as error:
        raise policy.error("Download response omitted its final URL") from error
    if final != expected:
        raise policy.error("Download redirected away from its exact pinned URL")


def parse_decimal_header(
    value: str | None,
    label: str,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> int:
    if (
        value is None or len(value) > 20 or not value.isascii()
        or not value.isdecimal()
    ):
        raise policy.error(f"Response omitted a valid {label}")
    return int(value)


def open_absolute_directory(
    path: Path, *, policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> int:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise policy.error("Download destination parent must be a canonical absolute path")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise policy.error("Download destination parent is unsafe")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            previous = descriptor
            descriptor = child
            os.close(previous)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns,
    ) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns,
    )


def assert_destination_absent(
    parent_fd: int,
    name: str,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise policy.error("Download destination already exists; it will not be overwritten")


def resume_stage_name(artifact: PinnedDownloadArtifact) -> str:
    """Return a fixed safe stage name bound to the complete artifact identity."""

    values = (artifact.id, artifact.filename, str(artifact.size), artifact.sha256)
    if (
        type(artifact.id) is not str or not artifact.id
        or type(artifact.filename) is not str or not artifact.filename
        or type(artifact.size) is not int or artifact.size <= 0
        or type(artifact.sha256) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", artifact.sha256)
    ):
        raise ValueError("Download artifact identity is invalid")
    digest = hashlib.sha256()
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f".isopropyl-download-{digest.hexdigest()}"


def is_resume_stage_name(value: object) -> bool:
    return type(value) is str and _RESUME_STAGE_RE.fullmatch(value) is not None


def open_stage(
    parent_fd: int,
    name: str,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> tuple[int, str, os.stat_result]:
    if not is_resume_stage_name(name):
        raise policy.error("Download resume directory identity is invalid")
    stage_name = name
    try:
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(stage_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise policy.error(
            f"Download resume directory is unsafe: {safe_error_detail(error)}"
        ) from error
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise policy.error("Download resume directory has unsafe ownership or mode")
        if any(entry != "partial" for entry in os.listdir(descriptor)):
            raise policy.error("Download resume directory contains unexpected entries")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, stage_name, status


def revalidate_directory(
    path: Path,
    descriptor: int,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
    open_directory: Callable[[Path], int] | None = None,
) -> None:
    current = -1
    try:
        current = (
            open_directory(path) if open_directory is not None
            else open_absolute_directory(path, policy=policy)
        )
        opened = os.fstat(descriptor)
        named = os.fstat(current)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise policy.error("Download destination directory changed")
    except OSError as error:
        raise policy.error(
            f"Download destination directory changed: {safe_error_detail(error)}"
        ) from error
    finally:
        if current >= 0:
            os.close(current)


def open_partial(
    stage_fd: int,
    expected_size: int,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open("partial", _FILE_FLAGS, dir_fd=stage_fd)
    except FileNotFoundError:
        try:
            descriptor = os.open(
                "partial", _FILE_FLAGS | os.O_CREAT | os.O_EXCL, 0o600,
                dir_fd=stage_fd,
            )
        except OSError as error:
            raise policy.error(
                f"Partial download path is unsafe: {safe_error_detail(error)}"
            ) from error
    except OSError as error:
        raise policy.error(
            f"Partial download path is unsafe: {safe_error_detail(error)}"
        ) from error
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid()
            or status.st_nlink != 1 or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size > expected_size
        ):
            raise policy.error("Partial download has unsafe identity, mode, or size")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, status


def hash_partial(
    descriptor: int,
    size: int,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> hashlib._Hash:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        check_cancel(cancel_event, cancel_check, policy=policy)
        deadline_check(deadline, policy=policy)
        block = os.pread(descriptor, min(READ_SIZE, size - offset), offset)
        if not block:
            raise policy.error("Partial download changed while it was read")
        digest.update(block)
        offset += len(block)
    return digest


def verify_completed_partial(
    stage_fd: int,
    descriptor: int,
    artifact: PinnedDownloadArtifact,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
    hash_partial_fn: Callable[..., hashlib._Hash] | None = None,
    same_file_fn: Callable[[os.stat_result, os.stat_result], bool] = same_file,
) -> tuple[os.stat_result, str]:
    """Re-read exact final bytes and freeze descriptor/path identity for publish."""

    before = os.fstat(descriptor)
    named_before = os.stat("partial", dir_fd=stage_fd, follow_symlinks=False)
    if (
        not same_file_fn(before, named_before) or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1 or before.st_size != artifact.size
    ):
        raise policy.error("Completed partial image changed before final verification")
    hasher = hash_partial_fn or (
        lambda fd, size, **kwargs: hash_partial(fd, size, policy=policy, **kwargs)
    )
    digest = hasher(
        descriptor, artifact.size, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    ).hexdigest()
    check_cancel(cancel_event, cancel_check, policy=policy)
    deadline_check(deadline, policy=policy)
    after = os.fstat(descriptor)
    named_after = os.stat("partial", dir_fd=stage_fd, follow_symlinks=False)
    if not same_file_fn(before, after) or not same_file_fn(after, named_after):
        raise policy.error("Completed partial image changed during final verification")
    if not hmac.compare_digest(digest, artifact.sha256):
        raise policy.error(
            "Completed image failed its final "
            f"{policy.hash_authority} SHA-256 checksum"
        )
    return after, digest


def revalidate_stage(
    parent_fd: int,
    name: str,
    descriptor: int,
    expected: os.stat_result,
    *,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise policy.error("Download resume directory changed while it was in use")


def download_image(
    artifact: PinnedDownloadArtifact,
    source_url: str,
    descriptor: int,
    initial: os.stat_result,
    opener: OpenUrl,
    progress: Progress | None,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
    hash_partial_fn: Callable[..., hashlib._Hash] | None = None,
    open_response_fn: Callable[..., DownloadResponse] | None = None,
    response_blocks_fn: Callable[..., Iterable[bytes]] | None = None,
    validate_response_url_fn: Callable[[DownloadResponse, str], None] | None = None,
    response_status_fn: Callable[[DownloadResponse], int] | None = None,
    response_header_fn: Callable[[DownloadResponse, str], str | None] = response_header,
    parse_decimal_header_fn: Callable[[str | None, str], int] | None = None,
) -> tuple[os.stat_result, str]:
    done = initial.st_size
    hasher = hash_partial_fn or (
        lambda fd, size, **kwargs: hash_partial(fd, size, policy=policy, **kwargs)
    )
    digest = hasher(
        descriptor, done, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    )
    if done == artifact.size:
        value = digest.hexdigest()
        if not hmac.compare_digest(value, artifact.sha256):
            raise policy.error("Completed partial download has the wrong checksum")
        if progress is not None:
            progress(done, artifact.size)
        return os.fstat(descriptor), value
    filesystem = os.fstatvfs(descriptor)
    available = filesystem.f_bavail * filesystem.f_frsize
    if available < artifact.size - done + FREE_SPACE_RESERVE:
        raise policy.error("Not enough free space for the image and safety reserve")
    headers = {"Accept-Encoding": "identity"}
    if done:
        headers["Range"] = f"bytes={done}-"
    request = urllib.request.Request(source_url, headers=headers)
    response_opener = open_response_fn or (
        lambda selected_opener, selected_request, **kwargs: open_response(
            selected_opener, selected_request, policy=policy, **kwargs,
        )
    )
    response = response_opener(
        opener, request, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    )
    try:
        if validate_response_url_fn is None:
            validate_response_url(response, source_url, policy=policy)
        else:
            validate_response_url_fn(response, source_url)
        status = (
            response_status_fn(response) if response_status_fn is not None
            else response_status(response, policy=policy)
        )
        if response_header_fn(response, "Content-Encoding") not in (None, "identity"):
            raise policy.error("Image response used an unexpected content encoding")
        parser = parse_decimal_header_fn or (
            lambda value, label: parse_decimal_header(value, label, policy=policy)
        )
        content_length = parser(
            response_header_fn(response, "Content-Length"), "Content-Length"
        )
        if done and status == 200:
            if content_length != artifact.size:
                raise policy.error("Restart response has the wrong exact size")
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
            done = 0
            digest = hashlib.sha256()
        elif done and status == 206:
            expected_range = f"bytes {done}-{artifact.size - 1}/{artifact.size}"
            if response_header_fn(response, "Content-Range") != expected_range:
                raise policy.error("Resume response has the wrong Content-Range")
        elif not done and status != 200:
            raise policy.error("Image server returned an unexpected HTTP status")
        elif done and status not in (200, 206):
            raise policy.error("Image server refused a safe resume")
        expected_body = artifact.size - done
        if content_length != expected_body:
            raise policy.error("Image response has the wrong exact size")
        os.lseek(descriptor, done, os.SEEK_SET)
        if progress is not None:
            progress(done, artifact.size)
        blocks = response_blocks_fn or (
            lambda selected_response, **kwargs: response_blocks(
                selected_response, policy=policy, **kwargs,
            )
        )
        for block in blocks(
            response, deadline=deadline, cancel_event=cancel_event,
            cancel_check=cancel_check,
        ):
            if done + len(block) > artifact.size:
                raise policy.error("Image response exceeded its cataloged size")
            view = memoryview(block)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise policy.error("Could not write the partial image")
                view = view[written:]
            digest.update(block)
            done += len(block)
            if progress is not None:
                progress(done, artifact.size)
        if done != artifact.size:
            raise policy.error("Image download ended before its exact size")
        value = digest.hexdigest()
        if not hmac.compare_digest(value, artifact.sha256):
            raise policy.error(
                "Downloaded image failed its "
                f"{policy.hash_authority} SHA-256 checksum"
            )
        os.fsync(descriptor)
        return os.fstat(descriptor), value
    finally:
        try:
            response.close()
        except Exception:
            pass


AuthorizeSource = Callable[
    [OpenUrl, float, threading.Event, CancelCheck | None],
    ResolvedDownloadSource,
]
def execute_verified_download(
    artifact: PinnedDownloadArtifact,
    destination: Path,
    authorize_source: AuthorizeSource,
    progress: Progress | None = None,
    *,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None = None,
    overall_timeout: float = 6 * 60 * 60,
    opener: OpenUrl = default_urlopen,
    policy: DownloadErrorPolicy = DEFAULT_ERROR_POLICY,
    open_absolute_directory_fn: Callable[[Path], int] | None = None,
    assert_destination_absent_fn: Callable[[int, str], None] | None = None,
    open_stage_fn: Callable[[int, str], tuple[int, str, os.stat_result]] | None = None,
    open_partial_fn: Callable[[int, int], tuple[int, os.stat_result]] | None = None,
    download_image_fn: Callable[..., tuple[os.stat_result, str]] | None = None,
    revalidate_stage_fn: Callable[[int, str, int, os.stat_result], None] | None = None,
    revalidate_directory_fn: Callable[[Path, int], None] | None = None,
    check_cancel_fn: Callable[[threading.Event, CancelCheck | None], None] | None = None,
    deadline_check_fn: Callable[[float], None] | None = None,
    verify_completed_partial_fn: Callable[..., tuple[os.stat_result, str]] | None = None,
    same_file_fn: Callable[[os.stat_result, os.stat_result], bool] = same_file,
) -> DownloadedVerifiedImage:
    """Run one complete resumable download and no-overwrite publication."""

    if (
        isinstance(overall_timeout, bool)
        or not isinstance(overall_timeout, (int, float))
        or not 0 < overall_timeout <= MAX_DOWNLOAD_TIMEOUT
    ):
        raise ValueError("Download timeout must be between 0 and 24 hours")
    native_path_type = type(Path())
    if type(destination) is not native_path_type:
        raise ValueError("Download destination must be an exact native pathlib.Path")
    if not destination.is_absolute():
        raise ValueError("Download destination must be an absolute pathlib.Path")
    destination_name = destination.name
    destination_parent = destination.parent
    if type(destination_name) is not str or type(destination_parent) is not native_path_type:
        raise ValueError("Download destination path primitives are invalid")
    if destination_name != artifact.filename:
        raise ValueError("Download destination must retain the exact cataloged filename")
    resume_name = resume_stage_name(artifact)

    open_directory = open_absolute_directory_fn or (
        lambda path: open_absolute_directory(path, policy=policy)
    )
    assert_absent = assert_destination_absent_fn or (
        lambda parent, name: assert_destination_absent(parent, name, policy=policy)
    )
    stage_opener = open_stage_fn or (
        lambda parent, name: open_stage(parent, name, policy=policy)
    )
    partial_opener = open_partial_fn or (
        lambda stage, size: open_partial(stage, size, policy=policy)
    )
    cancellation_check = check_cancel_fn or (
        lambda event, callback: check_cancel(event, callback, policy=policy)
    )
    deadline_validator = deadline_check_fn or (
        lambda value: deadline_check(value, policy=policy)
    )
    stage_validator = revalidate_stage_fn or (
        lambda parent, name, descriptor, expected: revalidate_stage(
            parent, name, descriptor, expected, policy=policy,
        )
    )
    directory_validator = revalidate_directory_fn or (
        lambda path, descriptor: revalidate_directory(
            path, descriptor, policy=policy,
        )
    )
    downloader = download_image_fn or (
        lambda selected, source, descriptor, initial, selected_opener, selected_progress,
        **kwargs: download_image(
            selected, source, descriptor, initial, selected_opener,
            selected_progress, policy=policy, **kwargs,
        )
    )
    completed_verifier = verify_completed_partial_fn or (
        lambda stage, descriptor, selected, **kwargs: verify_completed_partial(
            stage, descriptor, selected, policy=policy, **kwargs,
        )
    )

    deadline = time.monotonic() + float(overall_timeout)
    parent_fd = stage_fd = partial_fd = -1
    stage_name = ""
    stage_identity: os.stat_result | None = None
    remove_bad_partial = False
    published_identity: tuple[int, int] | None = None
    committed = False
    try:
        parent_fd = open_directory(destination_parent)
        assert_absent(parent_fd, destination_name)
        cancellation_check(cancel_event, cancel_check)
        source = authorize_source(
            opener, deadline, cancel_event, cancel_check,
        )
        if type(source) is not ResolvedDownloadSource or type(source.url) is not str or not source.url:
            raise policy.error("Download authority returned an invalid bound source")
        # Authority is established before resumable on-disk state is touched.
        assert_absent(parent_fd, destination_name)
        stage_fd, stage_name, stage_identity = stage_opener(parent_fd, resume_name)
        partial_fd, initial = partial_opener(stage_fd, artifact.size)
        downloader(
            artifact, source.url, partial_fd, initial, opener, progress,
            deadline=deadline, cancel_event=cancel_event, cancel_check=cancel_check,
        )
        assert stage_identity is not None
        stage_validator(parent_fd, stage_name, stage_fd, stage_identity)
        directory_validator(destination_parent, parent_fd)
        cancellation_check(cancel_event, cancel_check)
        deadline_validator(deadline)
        os.fsync(partial_fd)
        os.fsync(stage_fd)
        final, digest = completed_verifier(
            stage_fd, partial_fd, artifact, deadline=deadline,
            cancel_event=cancel_event, cancel_check=cancel_check,
        )
        # This must remain the immediate operation after the verifier returns.
        try:
            os.link(
                "partial", destination_name, src_dir_fd=stage_fd,
                dst_dir_fd=parent_fd, follow_symlinks=False,
            )
        except FileExistsError as error:
            raise policy.error(
                "Download destination appeared and was not overwritten"
            ) from error
        committed = True
        published_identity = (final.st_dev, final.st_ino)
        try:
            os.fsync(parent_fd)
        except OSError:
            pass

        cleanup_private = False
        try:
            linked = os.fstat(partial_fd)
            named_partial = os.stat("partial", dir_fd=stage_fd, follow_symlinks=False)
            named_destination = os.stat(
                destination_name, dir_fd=parent_fd, follow_symlinks=False,
            )
            if (
                same_file_fn(linked, named_partial)
                and same_file_fn(linked, named_destination)
                and stat.S_ISREG(linked.st_mode) and linked.st_nlink == 2
                and linked.st_size == artifact.size
                and linked.st_mtime_ns == final.st_mtime_ns
                and (linked.st_dev, linked.st_ino) == published_identity
            ):
                os.unlink("partial", dir_fd=stage_fd)
                cleanup_private = True
        except OSError:
            pass

        if cleanup_private:
            try:
                stage_validator(parent_fd, stage_name, stage_fd, stage_identity)
                named_stage = os.stat(
                    stage_name, dir_fd=parent_fd, follow_symlinks=False,
                )
                if (
                    stat.S_ISDIR(named_stage.st_mode)
                    and (named_stage.st_dev, named_stage.st_ino)
                    == (stage_identity.st_dev, stage_identity.st_ino)
                ):
                    os.rmdir(stage_name, dir_fd=parent_fd)
            except (VerifiedDownloadError, OSError):
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass

        # Link success is absolute commit. Nothing after it may turn success
        # into failure, even if same-user namespace mutation has occurred.
        return DownloadedVerifiedImage(
            destination, artifact.id, artifact.size, digest,
        )
    except policy.cancelled_type:
        raise
    except policy.error_type as error:
        remove_bad_partial = "checksum" in str(error).casefold()
        raise
    except (OSError, urllib.error.URLError) as error:
        raise policy.error(
            f"{policy.subject} download failed safely: {safe_error_detail(error)}"
        ) from error
    finally:
        if partial_fd >= 0:
            try:
                os.close(partial_fd)
            except OSError:
                if not committed:
                    raise
        if remove_bad_partial and stage_fd >= 0:
            try:
                os.unlink("partial", dir_fd=stage_fd)
            except OSError:
                pass
        if stage_fd >= 0:
            try:
                os.close(stage_fd)
            except OSError:
                if not committed:
                    raise
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                if not committed:
                    raise
