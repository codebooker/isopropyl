from __future__ import annotations

import errno
import unittest

from isopropyl import syslinux_device_helper as helper


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


class PositionalRetryTests(unittest.TestCase):
    def operations(self, clock: FakeClock, **overrides: object) -> helper.HelperOperations:
        values = {"monotonic": clock.monotonic, "sleep": clock.sleep}
        values.update(overrides)
        return helper.HelperOperations(**values)

    def test_eagain_uses_three_bounded_cancel_aware_delays(self) -> None:
        clock = FakeClock()
        calls = 0
        guard_times: list[float] = []
        cancel_calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls <= 3:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return b"x"

        def cancel() -> None:
            nonlocal cancel_calls
            cancel_calls += 1

        value = helper._pread_with_retry(
            7,
            1,
            19,
            operations=self.operations(clock, pread=pread),
            retry_guard=lambda: guard_times.append(clock.now),
            cancel_check=cancel,
        )

        self.assertEqual(value, b"x")
        self.assertEqual(calls, 4)
        self.assertAlmostEqual(clock.now, 2.6)
        self.assertEqual(
            [round(value, 6) for value in guard_times],
            [0.0, 0.1, 0.1, 0.6, 0.6, 2.6],
        )
        self.assertTrue(clock.sleeps)
        self.assertLessEqual(max(clock.sleeps), 0.05)
        self.assertGreater(cancel_calls, len(clock.sleeps))

    def test_fourth_eagain_is_terminal_without_an_extra_wait(self) -> None:
        clock = FakeClock()
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EWOULDBLOCK, "still unavailable")

        with self.assertRaises(BlockingIOError):
            helper._pread_with_retry(
                7,
                1,
                19,
                operations=self.operations(clock, pread=pread),
                retry_guard=lambda: None,
            )
        self.assertEqual(calls, 4)
        self.assertAlmostEqual(clock.now, 2.6)

    def test_eintr_is_immediate_and_does_not_consume_eagain_budget(self) -> None:
        clock = FakeClock()
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls <= 6:
                raise InterruptedError(errno.EINTR, "interrupted")
            if calls <= 9:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return b"x"

        value = helper._pread_with_retry(
            7,
            1,
            19,
            operations=self.operations(clock, pread=pread),
            retry_guard=lambda: None,
        )
        self.assertEqual(value, b"x")
        self.assertEqual(calls, 10)
        self.assertAlmostEqual(clock.now, 2.6)

    def test_repeated_eintr_is_bounded_by_the_syscall_limit(self) -> None:
        clock = FakeClock()
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise InterruptedError(errno.EINTR, "interrupted forever")

        with self.assertRaises(InterruptedError):
            helper._pread_with_retry(
                7,
                1,
                19,
                operations=self.operations(clock, pread=pread),
                retry_guard=lambda: None,
            )
        self.assertEqual(calls, helper._POSITIONAL_MAX_SYSCALLS)
        self.assertEqual(clock.sleeps, [])

    def test_positive_partial_write_resets_the_stall_budget_and_advances(self) -> None:
        clock = FakeClock()
        calls: list[int] = []
        failures: dict[int, int] = {}

        def pwrite(_fd: int, data: bytes, offset: int) -> int:
            calls.append(offset)
            failures[offset] = failures.get(offset, 0) + 1
            if failures[offset] <= 3:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return min(1, len(data))

        operations = self.operations(clock, pwrite=pwrite)

        def write_at(fd: int, data: bytes, offset: int) -> int:
            return helper._pwrite_with_retry(
                fd,
                data,
                offset,
                operations=operations,
                retry_guard=lambda: None,
            )

        helper._write_exact(7, b"ab", 0, write_at=write_at)
        self.assertEqual(calls, [0, 0, 0, 0, 1, 1, 1, 1])
        self.assertAlmostEqual(clock.now, 5.2)

    def test_fatal_write_errno_is_called_once(self) -> None:
        clock = FakeClock()
        calls = 0

        def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise OSError(errno.EIO, "ambiguous media error")

        with self.assertRaises(OSError):
            helper._pwrite_with_retry(
                7,
                b"x",
                19,
                operations=self.operations(clock, pwrite=pwrite),
                retry_guard=lambda: None,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(clock.sleeps, [])

    def test_retry_guard_failure_prevents_a_second_io(self) -> None:
        clock = FakeClock()
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")

        def changed() -> None:
            raise helper.HelperVerificationError("target generation changed")

        with self.assertRaises(helper.HelperVerificationError):
            helper._pread_with_retry(
                7,
                1,
                19,
                operations=self.operations(clock, pread=pread),
                retry_guard=changed,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(clock.sleeps, [])

    def test_cancel_during_backoff_prevents_a_second_io(self) -> None:
        clock = FakeClock()
        calls = 0

        def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")

        def cancel() -> None:
            if clock.now >= 0.05:
                raise helper.HelperCancelled("cancelled during retry wait")

        with self.assertRaises(helper.HelperCancelled):
            helper._pwrite_with_retry(
                7,
                b"x",
                19,
                operations=self.operations(clock, pwrite=pwrite),
                retry_guard=lambda: None,
                cancel_check=cancel,
            )
        self.assertEqual(calls, 1)
        self.assertAlmostEqual(clock.now, 0.05)

    def test_nonrepeatable_call_does_not_retry_eintr(self) -> None:
        calls = 0

        def fsync() -> None:
            nonlocal calls
            calls += 1
            raise InterruptedError(errno.EINTR, "ambiguous durability")

        with self.assertRaises(helper.HelperError):
            helper._call_once(fsync, "fsync failed")
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
