# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from isopropyl.verified_download import (
    ResolvedDownloadSource,
    VerifiedDownloadError,
    execute_verified_download,
    open_response,
    resume_stage_name,
    response_blocks,
    safe_error_detail,
)


SECRET_URL = "https://cdn.example.test/windows.iso?token=do-not-log-this"
SECRET = "do-not-log-this"


class FailingResponse(BytesIO):
    headers: dict[str, str] = {}

    def read(self, size: int = -1) -> bytes:
        raise OSError(f"read failed for {SECRET_URL}")

    def geturl(self) -> str:
        return SECRET_URL

    def getcode(self) -> int:
        return 200


class Response(BytesIO):
    def __init__(self, body: bytes, url: str) -> None:
        super().__init__(body)
        self.url = url
        self.status = 200
        self.headers = {"Content-Length": str(len(body))}

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status


@dataclass(frozen=True)
class Artifact:
    id: str
    filename: str
    size: int
    sha256: str


class VerifiedDownloadTests(unittest.TestCase):
    def test_transaction_traverses_absolute_directory_and_publishes(self):
        payload = b"authority-neutral image" * 4096
        source_url = "https://cdn.example.test/pinned.iso?token=temporary"
        artifact = Artifact(
            "pinned-test", "pinned.iso", len(payload),
            hashlib.sha256(payload).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve() / artifact.filename

            def authorize(_opener, _deadline, _event, _cancel_check):
                return ResolvedDownloadSource(source_url)

            def opener(request, **_kwargs):
                self.assertEqual(request.full_url, source_url)
                return Response(payload, source_url)

            result = execute_verified_download(
                artifact,
                destination,
                authorize,
                cancel_event=threading.Event(),
                opener=opener,
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(result.path, destination)
            self.assertEqual(result.release_id, artifact.id)
            self.assertEqual(result.sha256, artifact.sha256)
            self.assertFalse(
                (destination.parent / resume_stage_name(artifact)).exists()
            )

    def test_resume_stage_name_binds_every_artifact_identity_field(self):
        artifact = Artifact("release-a", "image.iso", 123, "a" * 64)
        original = resume_stage_name(artifact)
        self.assertRegex(original, r"^\.isopropyl-download-[0-9a-f]{64}$")
        for changed in (
            Artifact("release-b", artifact.filename, artifact.size, artifact.sha256),
            Artifact(artifact.id, "other.iso", artifact.size, artifact.sha256),
            Artifact(artifact.id, artifact.filename, 124, artifact.sha256),
            Artifact(artifact.id, artifact.filename, artifact.size, "b" * 64),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(resume_stage_name(changed), original)

    def test_http_transport_error_omits_temporary_url_and_query(self):
        request = urllib.request.Request(SECRET_URL)

        def fail(*_args, **_kwargs):
            raise urllib.error.HTTPError(
                SECRET_URL, 403, "expired", {}, None,
            )

        with self.assertRaises(VerifiedDownloadError) as raised:
            open_response(
                fail,
                request,
                deadline=time.monotonic() + 10,
                cancel_event=threading.Event(),
                cancel_check=None,
            )
        message = str(raised.exception)
        self.assertIn("HTTP status 403", message)
        self.assertNotIn(SECRET, message)
        self.assertNotIn(SECRET_URL, message)

    def test_arbitrary_connection_error_redacts_complete_url(self):
        request = urllib.request.Request(SECRET_URL)

        with self.assertRaises(VerifiedDownloadError) as raised:
            open_response(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError(f"connection refused at {SECRET_URL}")
                ),
                request,
                deadline=time.monotonic() + 10,
                cancel_event=threading.Event(),
                cancel_check=None,
            )
        message = str(raised.exception)
        self.assertIn("<redacted URL>", message)
        self.assertNotIn(SECRET, message)

    def test_read_error_redacts_complete_url(self):
        with self.assertRaises(VerifiedDownloadError) as raised:
            tuple(response_blocks(
                FailingResponse(),
                deadline=time.monotonic() + 10,
                cancel_event=threading.Event(),
                cancel_check=None,
            ))
        message = str(raised.exception)
        self.assertIn("read failed", message)
        self.assertNotIn(SECRET, message)
        self.assertNotIn(SECRET_URL, message)

    def test_safe_detail_is_bounded_after_redaction(self):
        detail = safe_error_detail(RuntimeError(("x" * 800) + SECRET_URL))
        self.assertLessEqual(len(detail), 512)
        self.assertNotIn(SECRET, detail)


if __name__ == "__main__":
    unittest.main()
