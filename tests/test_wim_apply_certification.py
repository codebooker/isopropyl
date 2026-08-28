# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import fcntl
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import certify_wim_apply_backend as harness


class WimApplyCertificationHarnessTests(unittest.TestCase):
    def test_privilege_state_reads_all_uids_and_capability_sets(self):
        status = """\
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
"""
        with patch.object(Path, "read_text", return_value=status):
            state = harness._process_privilege_state()
        self.assertEqual(state["uids"], (1000, 1000, 1000, 1000))
        self.assertEqual(state["capabilities"]["CapEff"], 0)
        self.assertNotEqual(state["capabilities"]["CapBnd"], 0)

    def test_privilege_state_rejects_missing_duplicate_or_malformed_fields(self):
        base = """\
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0
CapPrm:\t0
CapEff:\t0
CapBnd:\t0
CapAmb:\t0
"""
        payloads = (
            base.replace("CapAmb:\t0\n", ""),
            base + "CapEff:\t0\n",
            base.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\tbad"),
        )
        for payload in payloads:
            with (
                self.subTest(payload=payload),
                patch.object(Path, "read_text", return_value=payload),
                self.assertRaises(harness.CertificationError),
            ):
                harness._process_privilege_state()

    def test_unprivileged_gate_rejects_every_latent_root_id_and_capability_set(self):
        clean = {
            "uids": (1000, 1000, 1000, 1000),
            "capabilities": {
                "CapInh": 0,
                "CapPrm": 0,
                "CapEff": 0,
                "CapAmb": 0,
                "CapBnd": 0x1FFFFFFFFFF,
            },
        }
        self.assertEqual(harness._require_unprivileged_process(clean)[0][1], 1000)
        for position in range(4):
            uids = list(clean["uids"])
            uids[position] = 0
            with self.subTest(uid_position=position), self.assertRaises(
                harness.CertificationError,
            ):
                harness._require_unprivileged_process({**clean, "uids": tuple(uids)})
        for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            with self.subTest(capability=name), self.assertRaises(
                harness.CertificationError,
            ):
                harness._require_unprivileged_process(
                    {
                        **clean,
                        "capabilities": {**clean["capabilities"], name: 1},
                    },
                )

    def test_anonymous_target_is_private_unlinked_and_read_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            descriptor = harness._anonymous_target(temporary)
            try:
                status = os.fstat(descriptor)
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                self.assertTrue(stat.S_ISREG(status.st_mode))
                self.assertEqual(status.st_nlink, 0)
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                self.assertEqual(flags & os.O_ACCMODE, os.O_RDWR)
            finally:
                os.close(descriptor)

    def test_tool_gate_rejects_setid_bits_and_file_capabilities(self):
        setid = os.stat_result(
            (stat.S_IFREG | 0o4755, 1, 1, 1, 0, 0, 1, 0, 0, 0),
        )
        with (
            patch.object(harness.os, "lstat", return_value=setid),
            self.assertRaisesRegex(harness.CertificationError, "not trusted"),
        ):
            harness._tool("/usr/bin/fake")

        ordinary = os.stat_result(
            (stat.S_IFREG | 0o755, 1, 1, 1, 0, 0, 1, 0, 0, 0),
        )
        with (
            patch.object(harness.os, "lstat", return_value=ordinary),
            patch.object(harness.os.path, "realpath", return_value="/usr/bin/fake"),
            patch.object(harness.os, "getxattr", return_value=b"capability"),
            self.assertRaisesRegex(harness.CertificationError, "file capabilities"),
        ):
            harness._tool("/usr/bin/fake")


if __name__ == "__main__":
    unittest.main()
