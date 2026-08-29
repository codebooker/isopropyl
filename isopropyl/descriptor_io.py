from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, fixed-offset descriptor I/O with conservative retry semantics.

Reads are replayable because ``pread`` does not mutate the descriptor offset.
Writes are different: only Linux-documented zero-progress ``EINTR``, ``EAGAIN``,
and ``EWOULDBLOCK`` failures are replayable.  Every replay requires a caller's
target guard both after the error and immediately before the next syscall.  All
other write failures are ambiguous and fail closed.  A positive short-write
count is authoritative progress and only the as-yet unwritten suffix is
submitted next.  Deadlines are cooperative checks between syscalls and wait
slices; they cannot preempt a blocking kernel call.  A successful syscall result
remains authoritative even when that call returns after the deadline timestamp.
"""

import errno
import math
import os
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable


MAX_IO_BYTES = 64 * 1024 * 1024
MAX_OFFSET = (1 << 63) - 1
MAX_ATTEMPTS = 32
MAX_SYSCALLS = 65_536
MAX_DEADLINE_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 5.0
MAX_WAIT_SLICE_SECONDS = 0.05

# EAGAIN and EWOULDBLOCK are equal on Linux, but spelling out both documents the
# complete policy.  In particular, EIO, EBUSY, ENOMEM, and ETIMEDOUT are absent.
TRANSIENT_READ_ERRNOS = frozenset(
    {errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK}
)
TRANSIENT_PREWRITE_ERRNOS = TRANSIENT_READ_ERRNOS
TRANSIENT_WRITE_ERRNOS = TRANSIENT_READ_ERRNOS

CancelCheck = Callable[[], None]
Monotonic = Callable[[], float]
Wait = Callable[[float], None]
Pread = Callable[[int, int, int], bytes]
Pwrite = Callable[[int, bytes, int], int]
PrewriteCheck = Callable[[int, int, int], None]
RetryGuard = Callable[[], None]


class IoOperation(Enum):
    READ = "read"
    WRITE = "write"


class IoEventKind(Enum):
    STARTED = "started"
    RETRY = "retry"
    PROGRESS = "progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RetryPolicy:
    """Bounds for one descriptor operation.

    ``max_attempts`` limits consecutive non-``EINTR`` stalls.  Positive read or
    write progress starts a new sequence; ``EINTR`` is immediate and consumes
    only the independent ``max_syscalls`` budget.  That syscall bound also stops
    pathological streams that return tiny positive fragments forever.  The
    deadline is cooperative rather than a hard wall-clock timeout: it is checked
    before syscalls and during retry waits, but cannot interrupt a syscall.
    """

    max_attempts: int = 4
    max_syscalls: int = 1024
    backoff_schedule_seconds: tuple[float, ...] = (0.1, 0.5, 2.0)
    deadline_seconds: float = 5.0

    def __post_init__(self) -> None:
        _bounded_int("max_attempts", self.max_attempts, 1, MAX_ATTEMPTS)
        _bounded_int("max_syscalls", self.max_syscalls, 1, MAX_SYSCALLS)
        if type(self.backoff_schedule_seconds) is not tuple:
            raise TypeError("backoff_schedule_seconds must be a tuple")
        if len(self.backoff_schedule_seconds) < self.max_attempts - 1:
            raise ValueError("backoff schedule does not cover max_attempts")
        if len(self.backoff_schedule_seconds) > MAX_ATTEMPTS - 1:
            raise ValueError("backoff schedule is too long")
        schedule = tuple(
            _bounded_float(
                f"backoff_schedule_seconds[{index}]",
                value,
                0.0,
                MAX_BACKOFF_SECONDS,
            )
            for index, value in enumerate(self.backoff_schedule_seconds)
        )
        deadline = _bounded_float(
            "deadline_seconds",
            self.deadline_seconds,
            0.0,
            MAX_DEADLINE_SECONDS,
            lower_inclusive=False,
        )
        object.__setattr__(self, "backoff_schedule_seconds", schedule)
        object.__setattr__(self, "deadline_seconds", deadline)


@dataclass(frozen=True)
class IoAccounting:
    operation: IoOperation
    offset: int
    requested_bytes: int
    transferred_bytes: int = 0
    io_syscalls: int = 0
    readiness_checks: int = 0
    retry_guard_checks: int = 0
    transient_failures: int = 0
    retries: int = 0
    wait_calls: int = 0
    waited_seconds: float = 0.0
    elapsed_seconds: float = 0.0
    completed: bool = False

    def __post_init__(self) -> None:
        if type(self.operation) is not IoOperation:
            raise TypeError("operation must be an IoOperation")
        _bounded_int("offset", self.offset, 0, MAX_OFFSET)
        _bounded_int("requested_bytes", self.requested_bytes, 0, MAX_IO_BYTES)
        if self.requested_bytes > MAX_OFFSET - self.offset:
            raise ValueError("accounting range exceeds the supported bound")
        _bounded_int(
            "transferred_bytes", self.transferred_bytes, 0, self.requested_bytes
        )
        _bounded_int("io_syscalls", self.io_syscalls, 0, MAX_SYSCALLS)
        counter_bound = MAX_SYSCALLS * MAX_ATTEMPTS
        for name, value in (
            ("readiness_checks", self.readiness_checks),
            ("retry_guard_checks", self.retry_guard_checks),
            ("transient_failures", self.transient_failures),
            ("retries", self.retries),
            ("wait_calls", self.wait_calls),
        ):
            _bounded_int(name, value, 0, counter_bound)
        waited = _bounded_float(
            "waited_seconds", self.waited_seconds, 0.0, float(MAX_OFFSET)
        )
        elapsed = _bounded_float(
            "elapsed_seconds", self.elapsed_seconds, 0.0, float(MAX_OFFSET)
        )
        if waited > elapsed + 1e-9:
            raise ValueError("waited_seconds exceeds elapsed_seconds")
        if type(self.completed) is not bool:
            raise TypeError("completed must be a boolean")
        if self.completed and self.transferred_bytes != self.requested_bytes:
            raise ValueError("completed accounting must cover every requested byte")
        object.__setattr__(self, "waited_seconds", waited)
        object.__setattr__(self, "elapsed_seconds", elapsed)


@dataclass(frozen=True)
class IoEvent:
    kind: IoEventKind
    accounting: IoAccounting
    error_number: int | None = None
    backoff_seconds: float = 0.0

    def __post_init__(self) -> None:
        if type(self.kind) is not IoEventKind:
            raise TypeError("kind must be an IoEventKind")
        if type(self.accounting) is not IoAccounting:
            raise TypeError("accounting must be IoAccounting")
        if self.error_number is not None:
            _bounded_int("error_number", self.error_number, 0, (1 << 31) - 1)
        backoff = _bounded_float(
            "backoff_seconds", self.backoff_seconds, 0.0, MAX_BACKOFF_SECONDS
        )
        object.__setattr__(self, "backoff_seconds", backoff)


@dataclass(frozen=True)
class ReadOutcome:
    data: bytes
    accounting: IoAccounting

    def __post_init__(self) -> None:
        if type(self.data) is not bytes:
            raise TypeError("read outcome data must be bytes")
        if type(self.accounting) is not IoAccounting:
            raise TypeError("read outcome accounting must be IoAccounting")
        if self.accounting.operation is not IoOperation.READ:
            raise ValueError("read outcome accounting has the wrong operation")
        if not self.accounting.completed:
            raise ValueError("read outcome accounting is incomplete")
        if len(self.data) != self.accounting.transferred_bytes:
            raise ValueError("read outcome length does not match its accounting")


IoEventHook = Callable[[IoEvent], None]


class DescriptorIoError(RuntimeError):
    """Base failure with the last trustworthy accounting snapshot."""

    def __init__(self, message: str, accounting: IoAccounting) -> None:
        super().__init__(message)
        self.accounting = accounting


class DescriptorReadError(DescriptorIoError):
    pass


class DescriptorWriteError(DescriptorIoError):
    pass


class DescriptorRetryExhausted(DescriptorIoError):
    pass


class DescriptorDeadlineExceeded(DescriptorIoError):
    pass


class DescriptorIoProtocolError(DescriptorIoError):
    pass


def _bounded_int(name: str, value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} is outside the supported bounds")
    return value


def _bounded_float(
    name: str,
    value: object,
    minimum: float,
    maximum: float,
    *,
    lower_inclusive: bool = True,
) -> float:
    if type(value) not in {int, float}:
        raise TypeError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    below = result < minimum if lower_inclusive else result <= minimum
    if below or result > maximum:
        raise ValueError(f"{name} is outside the supported bounds")
    return result


def _validate_common(
    descriptor: object,
    size: object,
    offset: object,
    policy: object,
    cancel_check: object,
    monotonic: object,
    wait: object,
    io_call: object,
    on_event: object,
) -> tuple[int, int, int, RetryPolicy]:
    descriptor_value = _bounded_int("descriptor", descriptor, 0, MAX_OFFSET)
    size_value = _bounded_int("size", size, 0, MAX_IO_BYTES)
    offset_value = _bounded_int("offset", offset, 0, MAX_OFFSET)
    if size_value > MAX_OFFSET - offset_value:
        raise ValueError("offset plus size exceeds the supported bound")
    if type(policy) is not RetryPolicy:
        raise TypeError("policy must be a RetryPolicy")
    for name, callback in (
        ("cancel_check", cancel_check),
        ("on_event", on_event),
    ):
        if callback is not None and not callable(callback):
            raise TypeError(f"{name} must be callable")
    for name, callback in (
        ("monotonic", monotonic),
        ("wait", wait),
        ("descriptor operation", io_call),
    ):
        if not callable(callback):
            raise TypeError(f"{name} must be callable")
    return descriptor_value, size_value, offset_value, policy


class _Execution:
    def __init__(
        self,
        accounting: IoAccounting,
        policy: RetryPolicy,
        cancel_check: CancelCheck | None,
        monotonic: Monotonic,
        wait: Wait,
        on_event: IoEventHook | None,
    ) -> None:
        self.accounting = accounting
        self.policy = policy
        self.cancel_check = cancel_check
        self.monotonic = monotonic
        self.wait = wait
        self.on_event = on_event
        self.started = self._raw_time()
        self.last_time = self.started
        self.deadline = self.started + policy.deadline_seconds
        if not math.isfinite(self.deadline):
            raise ValueError("deadline is not representable")
        self._refresh(self.started)

    def _raw_time(self) -> float:
        value = self.monotonic()
        if type(value) not in {int, float} or not math.isfinite(float(value)):
            raise ValueError("monotonic clock returned an invalid value")
        return float(value)

    def _refresh(self, now: float | None = None) -> float:
        current = self._raw_time() if now is None else now
        if current < self.last_time:
            raise DescriptorIoProtocolError(
                "monotonic clock moved backwards", self.accounting
            )
        self.last_time = current
        self.accounting = replace(
            self.accounting, elapsed_seconds=current - self.started
        )
        return current

    def emit(
        self,
        kind: IoEventKind,
        *,
        error_number: int | None = None,
        backoff_seconds: float = 0.0,
    ) -> None:
        if self.on_event is None:
            return
        try:
            event = IoEvent(kind, self.accounting, error_number, backoff_seconds)
            self.on_event(event)
        except Exception:
            # Accounting hooks are observational.  They must never change the
            # outcome of a descriptor operation, especially after a write.
            pass

    def cancel(self) -> None:
        if self.cancel_check is None:
            return
        try:
            self.cancel_check()
        except Exception:
            self._refresh()
            self.emit(IoEventKind.CANCELLED)
            raise

    def require_budget(self) -> float:
        self.cancel()
        now = self._refresh()
        remaining = self.deadline - now
        if remaining <= 0.0:
            self.emit(IoEventKind.FAILED)
            raise DescriptorDeadlineExceeded(
                "descriptor I/O deadline expired", self.accounting
            )
        return remaining

    def backoff(self, requested: float, error_number: int) -> None:
        remaining = self.require_budget()
        duration = min(requested, remaining)
        self.emit(
            IoEventKind.RETRY,
            error_number=error_number,
            backoff_seconds=duration,
        )
        target = self.last_time + duration
        while self.last_time < target:
            self.cancel()
            remaining_deadline = self.deadline - self.last_time
            if remaining_deadline <= 0.0:
                self.emit(IoEventKind.FAILED)
                raise DescriptorDeadlineExceeded(
                    "descriptor I/O deadline expired during backoff",
                    self.accounting,
                )
            delay = min(
                target - self.last_time,
                remaining_deadline,
                MAX_WAIT_SLICE_SECONDS,
            )
            before = self.last_time
            try:
                self.wait(delay)
            except Exception as error:
                self._refresh()
                self.emit(IoEventKind.FAILED)
                raise DescriptorIoProtocolError(
                    "descriptor I/O wait callback failed", self.accounting
                ) from error
            after = self._refresh()
            if after <= before:
                self.emit(IoEventKind.FAILED)
                raise DescriptorIoProtocolError(
                    "descriptor I/O wait made no monotonic progress",
                    self.accounting,
                )
            self.accounting = replace(
                self.accounting,
                wait_calls=self.accounting.wait_calls + 1,
                waited_seconds=self.accounting.waited_seconds + after - before,
            )
            self.cancel()
        if self.last_time >= self.deadline:
            self.emit(IoEventKind.FAILED)
            raise DescriptorDeadlineExceeded(
                "descriptor I/O deadline expired during backoff", self.accounting
            )

    def syscall(self) -> None:
        if self.accounting.io_syscalls >= self.policy.max_syscalls:
            self.emit(IoEventKind.FAILED)
            raise DescriptorIoProtocolError(
                "descriptor I/O syscall bound was exceeded", self.accounting
            )
        self.accounting = replace(
            self.accounting, io_syscalls=self.accounting.io_syscalls + 1
        )


def _backoff(policy: RetryPolicy, failure_index: int) -> float:
    return policy.backoff_schedule_seconds[failure_index - 1]


def _transient_errno(error: OSError, allowed: frozenset[int]) -> int | None:
    number = errno.EINTR if isinstance(error, InterruptedError) else error.errno
    if type(number) is int and number in allowed:
        return number
    return None


def _run_retry_guard(execution: _Execution, retry_guard: RetryGuard) -> None:
    execution.cancel()
    execution.accounting = replace(
        execution.accounting,
        retry_guard_checks=execution.accounting.retry_guard_checks + 1,
    )
    try:
        retry_guard()
    except Exception:
        execution._refresh()
        execution.emit(IoEventKind.FAILED)
        raise
    execution._refresh()


def read_exact_at(
    descriptor: int,
    size: int,
    offset: int,
    *,
    retry_guard: RetryGuard,
    policy: RetryPolicy = RetryPolicy(),
    cancel_check: CancelCheck | None = None,
    monotonic: Monotonic = time.monotonic,
    wait: Wait = time.sleep,
    pread: Pread = os.pread,
    on_event: IoEventHook | None = None,
) -> ReadOutcome:
    """Read exactly ``size`` bytes, retrying only safe transient failures."""

    descriptor, size, offset, policy = _validate_common(
        descriptor,
        size,
        offset,
        policy,
        cancel_check,
        monotonic,
        wait,
        pread,
        on_event,
    )
    if not callable(retry_guard):
        raise TypeError("retry_guard must be callable")
    execution = _Execution(
        IoAccounting(IoOperation.READ, offset, size),
        policy,
        cancel_check,
        monotonic,
        wait,
        on_event,
    )
    execution.emit(IoEventKind.STARTED)
    if size == 0:
        execution.accounting = replace(execution.accounting, completed=True)
        execution.emit(IoEventKind.COMPLETED)
        return ReadOutcome(b"", execution.accounting)

    chunks: list[bytes] = []
    consecutive_failures = 0
    retry_pending = False
    while execution.accounting.transferred_bytes < size:
        execution.require_budget()
        if retry_pending:
            _run_retry_guard(execution, retry_guard)
            retry_pending = False
        execution.syscall()
        done = execution.accounting.transferred_bytes
        try:
            chunk = pread(descriptor, size - done, offset + done)
        except OSError as error:
            execution._refresh()
            number = _transient_errno(error, TRANSIENT_READ_ERRNOS)
            if number is None:
                execution.emit(IoEventKind.FAILED, error_number=error.errno)
                raise DescriptorReadError(
                    "fixed-offset descriptor read failed", execution.accounting
                ) from error
            execution.accounting = replace(
                execution.accounting,
                transient_failures=execution.accounting.transient_failures + 1,
            )
            stalled_attempts = (
                consecutive_failures + 1
                if number != errno.EINTR else consecutive_failures
            )
            _run_retry_guard(execution, retry_guard)
            if number != errno.EINTR and stalled_attempts >= policy.max_attempts:
                execution.emit(IoEventKind.FAILED, error_number=number)
                raise DescriptorRetryExhausted(
                    "fixed-offset descriptor read exhausted its retry bound",
                    execution.accounting,
                ) from error
            consecutive_failures = stalled_attempts
            execution.accounting = replace(
                execution.accounting, retries=execution.accounting.retries + 1
            )
            if number != errno.EINTR:
                execution.backoff(_backoff(policy, consecutive_failures), number)
            else:
                execution.emit(
                    IoEventKind.RETRY,
                    error_number=number,
                    backoff_seconds=0.0,
                )
            retry_pending = True
            continue
        except Exception as error:
            execution._refresh()
            execution.emit(IoEventKind.FAILED)
            raise DescriptorReadError(
                "fixed-offset descriptor read callback failed",
                execution.accounting,
            ) from error

        execution._refresh()
        remaining = size - done
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            execution.emit(IoEventKind.FAILED)
            raise DescriptorIoProtocolError(
                "fixed-offset descriptor read made invalid progress",
                execution.accounting,
            )
        chunks.append(chunk)
        consecutive_failures = 0
        execution.accounting = replace(
            execution.accounting,
            transferred_bytes=done + len(chunk),
        )
        execution.emit(IoEventKind.PROGRESS)

    execution.accounting = replace(execution.accounting, completed=True)
    execution.emit(IoEventKind.COMPLETED)
    return ReadOutcome(b"".join(chunks), execution.accounting)


def write_all_at(
    descriptor: int,
    data: bytes,
    offset: int,
    *,
    retry_guard: RetryGuard,
    policy: RetryPolicy = RetryPolicy(),
    cancel_check: CancelCheck | None = None,
    monotonic: Monotonic = time.monotonic,
    wait: Wait = time.sleep,
    pwrite: Pwrite = os.pwrite,
    prewrite: PrewriteCheck | None = None,
    on_event: IoEventHook | None = None,
) -> IoAccounting:
    """Write all bytes without ever replaying ambiguous write progress.

    ``prewrite`` is an optional readiness check called before each ``pwrite``.
    Allowlisted errors from it are provably pre-syscall and may be retried.
    Linux-documented zero-progress interruptions from ``pwrite`` itself may also
    be retried.  All retry paths require the caller's ``retry_guard`` twice.
    """

    if type(data) is not bytes:
        raise TypeError("data must be immutable bytes")
    descriptor, size, offset, policy = _validate_common(
        descriptor,
        len(data),
        offset,
        policy,
        cancel_check,
        monotonic,
        wait,
        pwrite,
        on_event,
    )
    if prewrite is not None and not callable(prewrite):
        raise TypeError("prewrite must be callable")
    if not callable(retry_guard):
        raise TypeError("retry_guard must be callable")
    execution = _Execution(
        IoAccounting(IoOperation.WRITE, offset, size),
        policy,
        cancel_check,
        monotonic,
        wait,
        on_event,
    )
    execution.emit(IoEventKind.STARTED)
    if size == 0:
        execution.accounting = replace(execution.accounting, completed=True)
        execution.emit(IoEventKind.COMPLETED)
        return execution.accounting

    write_stalls = 0
    write_retry_pending = False
    while execution.accounting.transferred_bytes < size:
        done = execution.accounting.transferred_bytes
        remaining = size - done
        readiness_failures = 0
        readiness_retry_pending = False
        while prewrite is not None:
            execution.require_budget()
            if readiness_retry_pending:
                _run_retry_guard(execution, retry_guard)
                readiness_retry_pending = False
            execution.accounting = replace(
                execution.accounting,
                readiness_checks=execution.accounting.readiness_checks + 1,
            )
            try:
                prewrite(descriptor, offset + done, remaining)
            except OSError as error:
                execution._refresh()
                number = _transient_errno(error, TRANSIENT_PREWRITE_ERRNOS)
                if number is None:
                    execution.emit(IoEventKind.FAILED, error_number=error.errno)
                    raise DescriptorWriteError(
                        "descriptor pre-write readiness check failed",
                        execution.accounting,
                    ) from error
                execution.accounting = replace(
                    execution.accounting,
                    transient_failures=execution.accounting.transient_failures + 1,
                )
                stalled_attempts = (
                    readiness_failures + 1
                    if number != errno.EINTR else readiness_failures
                )
                _run_retry_guard(execution, retry_guard)
                if number != errno.EINTR and stalled_attempts >= policy.max_attempts:
                    execution.emit(IoEventKind.FAILED, error_number=number)
                    raise DescriptorRetryExhausted(
                        "descriptor pre-write check exhausted its retry bound",
                        execution.accounting,
                    ) from error
                readiness_failures = stalled_attempts
                execution.accounting = replace(
                    execution.accounting, retries=execution.accounting.retries + 1
                )
                if number != errno.EINTR:
                    execution.backoff(_backoff(policy, readiness_failures), number)
                else:
                    execution.emit(
                        IoEventKind.RETRY,
                        error_number=number,
                        backoff_seconds=0.0,
                    )
                readiness_retry_pending = True
                continue
            except Exception as error:
                execution._refresh()
                execution.emit(IoEventKind.FAILED)
                raise DescriptorWriteError(
                    "descriptor pre-write readiness callback failed",
                    execution.accounting,
                ) from error
            execution._refresh()
            break

        execution.require_budget()
        if write_retry_pending:
            _run_retry_guard(execution, retry_guard)
            write_retry_pending = False
        execution.syscall()
        try:
            count = pwrite(descriptor, data[done:], offset + done)
        except OSError as error:
            execution._refresh()
            number = _transient_errno(error, TRANSIENT_WRITE_ERRNOS)
            if number is None:
                execution.emit(IoEventKind.FAILED, error_number=error.errno)
                raise DescriptorWriteError(
                    "fixed-offset descriptor write failed ambiguously",
                    execution.accounting,
                ) from error
            execution.accounting = replace(
                execution.accounting,
                transient_failures=execution.accounting.transient_failures + 1,
            )
            stalled_attempts = (
                write_stalls + 1 if number != errno.EINTR else write_stalls
            )
            _run_retry_guard(execution, retry_guard)
            if number != errno.EINTR and stalled_attempts >= policy.max_attempts:
                execution.emit(IoEventKind.FAILED, error_number=number)
                raise DescriptorRetryExhausted(
                    "fixed-offset descriptor write exhausted its retry bound",
                    execution.accounting,
                ) from error
            execution.accounting = replace(
                execution.accounting, retries=execution.accounting.retries + 1
            )
            write_stalls = stalled_attempts
            if number != errno.EINTR:
                execution.backoff(_backoff(policy, stalled_attempts), number)
            else:
                execution.emit(
                    IoEventKind.RETRY,
                    error_number=number,
                    backoff_seconds=0.0,
                )
            write_retry_pending = True
            continue
        except Exception as error:
            execution._refresh()
            execution.emit(IoEventKind.FAILED)
            raise DescriptorWriteError(
                "fixed-offset descriptor write failed ambiguously",
                execution.accounting,
            ) from error
        execution._refresh()
        if type(count) is not int or count <= 0 or count > remaining:
            execution.emit(IoEventKind.FAILED)
            raise DescriptorIoProtocolError(
                "fixed-offset descriptor write made invalid progress",
                execution.accounting,
            )
        execution.accounting = replace(
            execution.accounting, transferred_bytes=done + count
        )
        write_stalls = 0
        execution.emit(IoEventKind.PROGRESS)

    execution.accounting = replace(execution.accounting, completed=True)
    execution.emit(IoEventKind.COMPLETED)
    return execution.accounting
