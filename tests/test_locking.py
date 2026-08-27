from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import subprocess
import sys
import tempfile
import unittest

from isopropyl.locking import (
    CooperativeLockError,
    LOCK_CONFLICT_EXIT_CODE,
    add_native_sfdisk_lock,
    cooperative_lock_command,
    is_cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)


class CooperativeLockTests(unittest.TestCase):
    def test_resolves_only_the_fixed_system_flock(self):
        self.assertEqual(
            resolve_flock(lambda name: "/usr/bin/flock" if name == "flock" else None),
            "/usr/bin/flock",
        )
        for value in (None, "flock", "/tmp/flock", "/usr/bin/not-flock"):
            with self.subTest(value=value), self.assertRaises(CooperativeLockError):
                resolve_flock(lambda _name, result=value: result)

    def test_wraps_one_privileged_command_without_a_shell(self):
        command = cooperative_lock_command(
            "/usr/bin/pkexec",
            "/usr/bin/flock",
            "/dev/sdz",
            ["/usr/bin/dd", "if=/tmp/image", "of=/dev/sdz"],
        )
        self.assertEqual(command[:2], ["/usr/bin/pkexec", "/usr/bin/flock"])
        self.assertEqual(
            command[2:8],
            [
                "--exclusive", "--nonblock", "--conflict-exit-code",
                str(LOCK_CONFLICT_EXIT_CODE), "--no-fork", "/dev/sdz",
            ],
        )
        self.assertEqual(command[8], "/usr/bin/dd")
        self.assertNotIn("sh", command)
        self.assertTrue(is_cooperative_lock_command(command))
        self.assertFalse(is_cooperative_lock_command(command[:7]))
        self.assertFalse(is_cooperative_lock_command([
            *command[:5], "76", *command[6:],
        ]))

    def test_rejects_unsafe_device_tools_and_arguments(self):
        valid = ("/usr/bin/pkexec", "/usr/bin/flock", "/dev/sdz")
        for tool in ([], ["dd"], ["/tmp/dd"], ["/usr/bin/dd", "bad\x00arg"]):
            with self.subTest(tool=tool), self.assertRaises(CooperativeLockError):
                cooperative_lock_command(*valid, tool)
        with self.assertRaises(CooperativeLockError):
            cooperative_lock_command(
                "/usr/bin/pkexec", "/usr/bin/flock", "/tmp/not-device",
                ["/usr/bin/dd"],
            )

    def test_sfdisk_uses_its_native_nonblocking_lock(self):
        command = add_native_sfdisk_lock(
            ["/usr/bin/pkexec", "/usr/sbin/sfdisk", "--wipe", "always", "/dev/sdz"],
            "/usr/sbin/sfdisk",
        )
        self.assertEqual(command[2], "--lock=nonblock")
        with self.assertRaises(CooperativeLockError):
            add_native_sfdisk_lock(command, "/usr/sbin/sfdisk")

    def test_conflict_exit_has_a_specific_bounded_message(self):
        message = lock_conflict_message(LOCK_CONFLICT_EXIT_CODE, "tool failed")
        self.assertIn("lock-aware", message)
        self.assertEqual(lock_conflict_message(1, "tool failed"), "tool failed")

    def test_real_flock_is_fail_fast_released_on_exit_and_advisory(self):
        flock = resolve_flock()
        with tempfile.NamedTemporaryFile() as target:
            holder = subprocess.Popen(
                [
                    flock, "--exclusive", "--nonblock", "--no-fork",
                    target.name, sys.executable, "-c",
                    "import sys,time; print('ready'); sys.stdout.flush(); time.sleep(30)",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert holder.stdout is not None
                self.assertEqual(holder.stdout.readline().strip(), "ready")
                conflict = subprocess.run(
                    [
                        flock, "--exclusive", "--nonblock",
                        "--conflict-exit-code", str(LOCK_CONFLICT_EXIT_CODE),
                        target.name, "/usr/bin/true",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False,
                )
                self.assertEqual(conflict.returncode, LOCK_CONFLICT_EXIT_CODE)
                # BSD locks are intentionally documented as advisory.
                with open(target.name, "ab") as unlocked_writer:
                    unlocked_writer.write(b"uncooperative")
            finally:
                holder.terminate()
                holder.wait(timeout=5)
                if holder.stdout is not None:
                    holder.stdout.close()
                if holder.stderr is not None:
                    holder.stderr.close()
            after = subprocess.run(
                [flock, "--exclusive", "--nonblock", target.name, "/usr/bin/true"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            self.assertEqual(after.returncode, 0)


if __name__ == "__main__":
    unittest.main()
