from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import errno
import math
import os
import tempfile
import unittest

from isopropyl.descriptor_io import (
    MAX_IO_BYTES,
    DescriptorDeadlineExceeded,
    DescriptorIoProtocolError,
    DescriptorReadError,
    DescriptorRetryExhausted,
    DescriptorWriteError,
    IoAccounting,
    IoEvent,
    IoEventKind,
    IoOperation,
    ReadOutcome,
    RetryPolicy,
    read_exact_at as _read_exact_at,
    write_all_at as _write_all_at,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.waits: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def wait(self, duration: float) -> None:
        self.waits.append(duration)
        self.now += duration


class CancelledForTest(Exception):
    pass


def allow_retry() -> None:
    pass


def read_exact_at(*args: object, **kwargs: object):
    kwargs.setdefault("retry_guard", allow_retry)
    return _read_exact_at(*args, **kwargs)  # type: ignore[arg-type]


def write_all_at(*args: object, **kwargs: object):
    kwargs.setdefault("retry_guard", allow_retry)
    return _write_all_at(*args, **kwargs)  # type: ignore[arg-type]


class DescriptorReadTests(unittest.TestCase):
    def test_partial_reads_advance_the_fixed_offset(self) -> None:
        calls: list[tuple[int, int, int]] = []
        values = iter((b"ab", b"c", b"def"))

        def pread(fd: int, size: int, offset: int) -> bytes:
            calls.append((fd, size, offset))
            return next(values)

        clock = FakeClock()
        outcome = read_exact_at(
            7,
            6,
            4096,
            pread=pread,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )

        self.assertEqual(outcome.data, b"abcdef")
        self.assertEqual(
            calls,
            [(7, 6, 4096), (7, 4, 4098), (7, 3, 4099)],
        )
        self.assertEqual(outcome.accounting.operation, IoOperation.READ)
        self.assertEqual(outcome.accounting.requested_bytes, 6)
        self.assertEqual(outcome.accounting.transferred_bytes, 6)
        self.assertEqual(outcome.accounting.io_syscalls, 3)
        self.assertTrue(outcome.accounting.completed)

    def test_transient_read_errors_use_the_bounded_schedule(self) -> None:
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EINTR, "interrupted")
            if calls == 2:
                raise OSError(errno.EAGAIN, "again")
            return b"done"

        clock = FakeClock()
        events = []
        outcome = read_exact_at(
            3,
            4,
            8,
            policy=RetryPolicy(
                max_attempts=4,
                backoff_schedule_seconds=(0.01, 0.02, 0.02),
            ),
            pread=pread,
            monotonic=clock.monotonic,
            wait=clock.wait,
            on_event=events.append,
        )

        self.assertEqual(outcome.data, b"done")
        self.assertEqual(len(clock.waits), 1)
        self.assertAlmostEqual(clock.waits[0], 0.01)
        self.assertEqual(outcome.accounting.io_syscalls, 3)
        self.assertEqual(outcome.accounting.transient_failures, 2)
        self.assertEqual(outcome.accounting.retries, 2)
        self.assertAlmostEqual(outcome.accounting.waited_seconds, 0.01)
        self.assertEqual(
            [event.kind for event in events],
            [
                IoEventKind.STARTED,
                IoEventKind.RETRY,
                IoEventKind.RETRY,
                IoEventKind.PROGRESS,
                IoEventKind.COMPLETED,
            ],
        )

    def test_transient_sequence_resets_after_authoritative_progress(self) -> None:
        values: list[bytes | BaseException] = [
            OSError(errno.EAGAIN, "again"),
            b"a",
            InterruptedError(),
            b"b",
        ]

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            value = values.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        clock = FakeClock()
        outcome = read_exact_at(
            1,
            2,
            0,
            policy=RetryPolicy(max_attempts=2),
            pread=pread,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(outcome.data, b"ab")
        self.assertEqual(outcome.accounting.io_syscalls, 4)
        self.assertEqual(outcome.accounting.retries, 2)

    def test_non_allowlisted_read_error_is_never_retried(self) -> None:
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise OSError(errno.EIO, "I/O error")

        clock = FakeClock()
        with self.assertRaises(DescriptorReadError) as raised:
            read_exact_at(
                1,
                1,
                0,
                pread=pread,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(raised.exception.accounting.io_syscalls, 1)
        self.assertEqual(raised.exception.accounting.retries, 0)
        self.assertEqual(clock.waits, [])

    def test_read_retry_exhaustion_is_exact(self) -> None:
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "again")

        clock = FakeClock()
        with self.assertRaises(DescriptorRetryExhausted) as raised:
            read_exact_at(
                1,
                1,
                0,
                policy=RetryPolicy(max_attempts=3),
                pread=pread,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 3)
        self.assertEqual(raised.exception.accounting.transient_failures, 3)
        self.assertEqual(raised.exception.accounting.retries, 2)

    def test_default_eagain_policy_is_four_attempts_with_exact_schedule(self) -> None:
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "again")

        clock = FakeClock()
        with self.assertRaises(DescriptorRetryExhausted) as raised:
            read_exact_at(
                1,
                1,
                0,
                pread=pread,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 4)
        self.assertAlmostEqual(sum(clock.waits), 2.6)
        self.assertEqual(raised.exception.accounting.retries, 3)
        self.assertEqual(raised.exception.accounting.retry_guard_checks, 7)

    def test_eintr_is_immediate_and_does_not_consume_stall_attempts(self) -> None:
        values: list[bytes | BaseException] = [
            OSError(errno.EAGAIN, "again"),
            OSError(errno.EINTR, "interrupted"),
            OSError(errno.EAGAIN, "again"),
            b"x",
        ]

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            value = values.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        clock = FakeClock()
        outcome = read_exact_at(
            1,
            1,
            0,
            policy=RetryPolicy(
                max_attempts=3,
                backoff_schedule_seconds=(0.1, 0.5),
            ),
            pread=pread,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(outcome.data, b"x")
        self.assertAlmostEqual(sum(clock.waits), 0.6)
        self.assertEqual(outcome.accounting.transient_failures, 3)
        self.assertEqual(outcome.accounting.retries, 3)

    def test_read_deadline_caps_backoff_and_prevents_another_syscall(self) -> None:
        calls = 0

        def pread(_fd: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "again")

        clock = FakeClock()
        with self.assertRaises(DescriptorDeadlineExceeded) as raised:
            read_exact_at(
                1,
                1,
                0,
                policy=RetryPolicy(
                    max_attempts=4,
                    backoff_schedule_seconds=(0.02, 0.02, 0.02),
                    deadline_seconds=0.015,
                ),
                pread=pread,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 1)
        self.assertAlmostEqual(sum(clock.waits), 0.015)
        self.assertEqual(raised.exception.accounting.io_syscalls, 1)
        self.assertEqual(raised.exception.accounting.retries, 1)

    def test_cancellation_is_checked_during_backoff(self) -> None:
        cancelled = False

        def cancel_check() -> None:
            if cancelled:
                raise CancelledForTest

        clock = FakeClock()

        def wait(duration: float) -> None:
            nonlocal cancelled
            clock.wait(duration)
            cancelled = True

        events = []
        with self.assertRaises(CancelledForTest):
            read_exact_at(
                1,
                1,
                0,
                policy=RetryPolicy(
                    backoff_schedule_seconds=(0.2, 0.2, 0.2),
                ),
                cancel_check=cancel_check,
                pread=lambda *_args: (_ for _ in ()).throw(
                    OSError(errno.EAGAIN, "again")
                ),
                monotonic=clock.monotonic,
                wait=wait,
                on_event=events.append,
            )
        self.assertEqual(clock.waits, [0.05])
        self.assertEqual(events[-1].kind, IoEventKind.CANCELLED)

    def test_eof_and_malformed_read_results_fail_closed(self) -> None:
        for value in (b"", True, bytearray(b"x"), b"too long"):
            with self.subTest(value=value):
                clock = FakeClock()
                with self.assertRaises(DescriptorIoProtocolError):
                    read_exact_at(
                        1,
                        1,
                        0,
                        pread=lambda *_args, value=value: value,  # type: ignore[return-value]
                        monotonic=clock.monotonic,
                        wait=clock.wait,
                    )

    def test_syscall_bound_stops_pathological_positive_fragments(self) -> None:
        clock = FakeClock()
        with self.assertRaises(DescriptorIoProtocolError) as raised:
            read_exact_at(
                1,
                3,
                0,
                policy=RetryPolicy(max_syscalls=2),
                pread=lambda *_args: b"x",
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(raised.exception.accounting.io_syscalls, 2)
        self.assertEqual(raised.exception.accounting.transferred_bytes, 2)

    def test_deadline_is_cooperative_and_does_not_discard_a_successful_read(self) -> None:
        clock = FakeClock()

        def slow_success(_fd: int, _size: int, _offset: int) -> bytes:
            clock.now += 5.0
            return b"x"

        outcome = read_exact_at(
            1,
            1,
            0,
            policy=RetryPolicy(deadline_seconds=0.01),
            pread=slow_success,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(outcome.data, b"x")
        self.assertTrue(outcome.accounting.completed)
        self.assertEqual(outcome.accounting.elapsed_seconds, 5.0)


class DescriptorWriteTests(unittest.TestCase):
    def test_positive_partial_writes_advance_without_replaying_bytes(self) -> None:
        calls: list[tuple[int, bytes, int]] = []
        counts = iter((2, 1, 3))

        def pwrite(fd: int, data: bytes, offset: int) -> int:
            calls.append((fd, data, offset))
            return next(counts)

        clock = FakeClock()
        result = write_all_at(
            9,
            b"abcdef",
            2048,
            pwrite=pwrite,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )

        self.assertEqual(
            calls,
            [
                (9, b"abcdef", 2048),
                (9, b"cdef", 2050),
                (9, b"def", 2051),
            ],
        )
        self.assertEqual(result.transferred_bytes, 6)
        self.assertEqual(result.io_syscalls, 3)
        self.assertTrue(result.completed)

    def test_ambiguous_pwrite_error_is_never_retried(self) -> None:
        calls = 0

        def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise OSError(errno.EIO, "failure")

        clock = FakeClock()
        with self.assertRaises(DescriptorWriteError) as raised:
            write_all_at(
                1,
                b"data",
                0,
                pwrite=pwrite,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(raised.exception.accounting.io_syscalls, 1)
        self.assertEqual(raised.exception.accounting.retries, 0)
        self.assertEqual(clock.waits, [])

    def test_linux_zero_progress_pwrite_errors_require_guarded_retry(self) -> None:
        for number in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK):
            with self.subTest(number=number):
                calls = 0
                guards = 0

                def pwrite(_fd: int, data: bytes, _offset: int) -> int:
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise OSError(number, "retryable zero progress")
                    return len(data)

                def guard() -> None:
                    nonlocal guards
                    guards += 1

                clock = FakeClock()
                result = write_all_at(
                    1,
                    b"data",
                    0,
                    retry_guard=guard,
                    pwrite=pwrite,
                    monotonic=clock.monotonic,
                    wait=clock.wait,
                )
                self.assertEqual(calls, 2)
                self.assertEqual(guards, 2)
                self.assertEqual(result.retry_guard_checks, 2)
                self.assertEqual(result.retries, 1)
                expected_wait = 0.0 if number == errno.EINTR else 0.1
                self.assertAlmostEqual(sum(clock.waits), expected_wait)

    def test_retry_guard_failure_prevents_write_replay(self) -> None:
        calls = 0

        def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "zero progress")

        def reject() -> None:
            raise CancelledForTest

        clock = FakeClock()
        with self.assertRaises(CancelledForTest):
            write_all_at(
                1,
                b"x",
                0,
                retry_guard=reject,
                pwrite=pwrite,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(clock.waits, [])

    def test_zero_progress_write_stalls_use_default_four_attempt_bound(self) -> None:
        calls = 0

        def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "zero progress")

        clock = FakeClock()
        with self.assertRaises(DescriptorRetryExhausted) as raised:
            write_all_at(
                1,
                b"x",
                0,
                pwrite=pwrite,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, 4)
        self.assertAlmostEqual(sum(clock.waits), 2.6)
        self.assertEqual(raised.exception.accounting.retries, 3)
        self.assertEqual(raised.exception.accounting.retry_guard_checks, 7)

    def test_exception_after_partial_progress_does_not_replay_prefix(self) -> None:
        calls: list[tuple[bytes, int]] = []

        def pwrite(_fd: int, data: bytes, offset: int) -> int:
            calls.append((data, offset))
            if len(calls) == 1:
                return 2
            raise OSError(errno.EIO, "ambiguous")

        clock = FakeClock()
        with self.assertRaises(DescriptorWriteError) as raised:
            write_all_at(
                1,
                b"abcd",
                100,
                pwrite=pwrite,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(calls, [(b"abcd", 100), (b"cd", 102)])
        self.assertEqual(raised.exception.accounting.transferred_bytes, 2)
        self.assertEqual(raised.exception.accounting.io_syscalls, 2)

    def test_zero_or_malformed_write_progress_fails_without_replay(self) -> None:
        for value in (0, -1, True, 5, None):
            with self.subTest(value=value):
                calls = 0

                def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
                    nonlocal calls
                    calls += 1
                    return value  # type: ignore[return-value]

                clock = FakeClock()
                with self.assertRaises(DescriptorIoProtocolError):
                    write_all_at(
                        1,
                        b"data",
                        0,
                        pwrite=pwrite,
                        monotonic=clock.monotonic,
                        wait=clock.wait,
                    )
                self.assertEqual(calls, 1)

    def test_only_prewrite_readiness_may_retry(self) -> None:
        readiness: list[tuple[int, int, int]] = []
        writes: list[tuple[bytes, int]] = []

        def prewrite(fd: int, offset: int, remaining: int) -> None:
            readiness.append((fd, offset, remaining))
            if len(readiness) < 3:
                raise OSError(errno.EAGAIN, "not ready")

        def pwrite(_fd: int, data: bytes, offset: int) -> int:
            writes.append((data, offset))
            return len(data)

        clock = FakeClock()
        result = write_all_at(
            5,
            b"data",
            20,
            prewrite=prewrite,
            pwrite=pwrite,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(
            readiness,
            [(5, 20, 4), (5, 20, 4), (5, 20, 4)],
        )
        self.assertEqual(writes, [(b"data", 20)])
        self.assertEqual(result.readiness_checks, 3)
        self.assertEqual(result.retries, 2)
        self.assertEqual(result.io_syscalls, 1)

    def test_prewrite_is_rechecked_for_unwritten_suffix(self) -> None:
        readiness: list[tuple[int, int]] = []
        counts = iter((2, 2))

        clock = FakeClock()
        result = write_all_at(
            1,
            b"data",
            10,
            prewrite=lambda _fd, offset, remaining: readiness.append(
                (offset, remaining)
            ),
            pwrite=lambda _fd, _data, _offset: next(counts),
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(readiness, [(10, 4), (12, 2)])
        self.assertEqual(result.readiness_checks, 2)

    def test_nontransient_or_exhausted_prewrite_never_calls_pwrite(self) -> None:
        for number, expected in (
            (errno.EIO, DescriptorWriteError),
            (errno.EAGAIN, DescriptorRetryExhausted),
        ):
            with self.subTest(number=number):
                writes = 0

                def pwrite(_fd: int, _data: bytes, _offset: int) -> int:
                    nonlocal writes
                    writes += 1
                    return 1

                clock = FakeClock()
                with self.assertRaises(expected):
                    write_all_at(
                        1,
                        b"x",
                        0,
                        policy=RetryPolicy(max_attempts=2),
                        prewrite=lambda *_args, number=number: (
                            _ for _ in ()
                        ).throw(OSError(number, "failure")),
                        pwrite=pwrite,
                        monotonic=clock.monotonic,
                        wait=clock.wait,
                    )
                self.assertEqual(writes, 0)

    def test_hook_failures_cannot_change_a_completed_write(self) -> None:
        events = 0

        def broken_hook(_event: object) -> None:
            nonlocal events
            events += 1
            raise RuntimeError("observer failed")

        clock = FakeClock()
        result = write_all_at(
            1,
            b"x",
            0,
            pwrite=lambda _fd, data, _offset: len(data),
            monotonic=clock.monotonic,
            wait=clock.wait,
            on_event=broken_hook,
        )
        self.assertTrue(result.completed)
        self.assertEqual(events, 3)

    def test_deadline_cannot_preempt_and_does_not_replay_a_slow_write(self) -> None:
        clock = FakeClock()
        calls = 0

        def slow_success(_fd: int, data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            clock.now += 5.0
            return len(data)

        result = write_all_at(
            1,
            b"x",
            0,
            policy=RetryPolicy(deadline_seconds=0.01),
            pwrite=slow_success,
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(calls, 1)
        self.assertTrue(result.completed)
        self.assertEqual(result.elapsed_seconds, 5.0)


class DescriptorValidationTests(unittest.TestCase):
    def test_real_regular_file_round_trip_uses_fixed_offsets(self) -> None:
        clock = FakeClock()
        with tempfile.TemporaryFile() as stream:
            stream.truncate(32)
            written = write_all_at(
                stream.fileno(),
                b"payload",
                7,
                pwrite=os.pwrite,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
            outcome = read_exact_at(
                stream.fileno(),
                7,
                7,
                pread=os.pread,
                monotonic=clock.monotonic,
                wait=clock.wait,
            )
        self.assertEqual(outcome.data, b"payload")
        self.assertEqual(written.transferred_bytes, 7)
        self.assertEqual(outcome.accounting.transferred_bytes, 7)

    def test_zero_length_operations_are_explicit_noops(self) -> None:
        clock = FakeClock()
        read = read_exact_at(
            0,
            0,
            0,
            pread=lambda *_args: self.fail("pread called"),
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        write = write_all_at(
            0,
            b"",
            0,
            pwrite=lambda *_args: self.fail("pwrite called"),
            monotonic=clock.monotonic,
            wait=clock.wait,
        )
        self.assertEqual(read.data, b"")
        self.assertEqual(read.accounting.io_syscalls, 0)
        self.assertEqual(write.io_syscalls, 0)
        self.assertTrue(read.accounting.completed)
        self.assertTrue(write.completed)

    def test_strict_descriptor_size_offset_and_data_validation(self) -> None:
        clock = FakeClock()
        invalid_reads = (
            (True, 1, 0, TypeError),
            (-1, 1, 0, ValueError),
            (1, True, 0, TypeError),
            (1, -1, 0, ValueError),
            (1, MAX_IO_BYTES + 1, 0, ValueError),
            (1, 1, True, TypeError),
            (1, 1, -1, ValueError),
            (1, 2, (1 << 63) - 2, ValueError),
        )
        for descriptor, size, offset, expected in invalid_reads:
            with self.subTest(descriptor=descriptor, size=size, offset=offset):
                with self.assertRaises(expected):
                    read_exact_at(
                        descriptor,  # type: ignore[arg-type]
                        size,  # type: ignore[arg-type]
                        offset,  # type: ignore[arg-type]
                        pread=lambda *_args: b"x",
                        monotonic=clock.monotonic,
                        wait=clock.wait,
                    )
        for data in (bytearray(b"x"), memoryview(b"x"), "x", True):
            with self.subTest(data=data):
                with self.assertRaises(TypeError):
                    write_all_at(
                        1,
                        data,  # type: ignore[arg-type]
                        0,
                        monotonic=clock.monotonic,
                        wait=clock.wait,
                    )

    def test_retry_policy_rejects_bool_nonfinite_and_out_of_bounds(self) -> None:
        invalid = (
            {"max_attempts": True},
            {"max_attempts": 0},
            {"max_syscalls": 0},
            {"backoff_schedule_seconds": [0.1, 0.5, 2.0]},
            {"backoff_schedule_seconds": (math.nan, 0.5, 2.0)},
            {"backoff_schedule_seconds": (math.inf, 0.5, 2.0)},
            {"backoff_schedule_seconds": (-1, 0.5, 2.0)},
            {"backoff_schedule_seconds": (6, 0.5, 2.0)},
            {"max_attempts": 5},
            {"deadline_seconds": 0},
            {"deadline_seconds": 61},
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises((TypeError, ValueError)):
                    RetryPolicy(**values)

    def test_public_accounting_and_outcome_types_reject_forged_values(self) -> None:
        valid = IoAccounting(IoOperation.READ, 0, 1, 1, completed=True)
        with self.assertRaises(TypeError):
            IoAccounting("read", 0, 1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            IoAccounting(IoOperation.READ, 0, 1, 2)
        with self.assertRaises(ValueError):
            IoAccounting(IoOperation.READ, 0, 1, 0, completed=True)
        with self.assertRaises(TypeError):
            IoAccounting(IoOperation.READ, 0, 1, completed=1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            IoAccounting(
                IoOperation.READ,
                0,
                1,
                waited_seconds=1.0,
                elapsed_seconds=0.5,
            )
        with self.assertRaises(TypeError):
            IoEvent("completed", valid)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            IoEvent(IoEventKind.COMPLETED, valid, error_number=True)
        with self.assertRaises(ValueError):
            ReadOutcome(b"", valid)
        with self.assertRaises(ValueError):
            ReadOutcome(
                b"x",
                IoAccounting(IoOperation.WRITE, 0, 1, 1, completed=True),
            )

    def test_callbacks_and_clock_are_validated_fail_closed(self) -> None:
        clock = FakeClock()
        with self.assertRaises(TypeError):
            _read_exact_at(1, 1, 0)
        with self.assertRaises(TypeError):
            read_exact_at(1, 1, 0, pread=None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            read_exact_at(1, 1, 0, monotonic=None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            write_all_at(1, b"x", 0, prewrite=True)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            read_exact_at(
                1,
                1,
                0,
                pread=lambda *_args: b"x",
                monotonic=lambda: math.nan,
                wait=clock.wait,
            )

    def test_clock_regression_and_nonadvancing_wait_fail_closed(self) -> None:
        values = iter((10.0, 9.0))
        with self.assertRaises(DescriptorIoProtocolError):
            read_exact_at(
                1,
                1,
                0,
                pread=lambda *_args: b"x",
                monotonic=lambda: next(values),
                wait=lambda _delay: None,
            )

        clock = FakeClock()
        with self.assertRaises(DescriptorIoProtocolError):
            read_exact_at(
                1,
                1,
                0,
                pread=lambda *_args: (_ for _ in ()).throw(
                    OSError(errno.EAGAIN, "again")
                ),
                monotonic=clock.monotonic,
                wait=lambda _delay: None,
            )


if __name__ == "__main__":
    unittest.main()
