from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Best-effort, read-only diagnostics for a busy block device.

The probe never kills a process and never weakens an unmount failure. It uses
the trusted system ``fuser`` with a fixed argument vector, then reads only the
owning process name and numeric UID from a descriptor-bound ``/proc/<pid>``
directory.
"""

import os
import re
import select
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


CONFLICT_PROBE_TIMEOUT_SECONDS = 3
MAX_CONFLICT_OUTPUT_BYTES = 64 * 1024
MAX_REPORTED_PROCESSES = 12
MAX_PROCESS_NAME_BYTES = 256
MAX_PROCESS_STAT_BYTES = 4096
TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_TOOL_DIRECTORIES = frozenset(TRUSTED_TOOL_PATH.split(":"))
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_PID = re.compile(r"[1-9][0-9]*")


@dataclass(frozen=True)
class ConflictingProcess:
    pid: int
    name: str
    uid: int


@dataclass(frozen=True)
class ConflictReport:
    processes: tuple[ConflictingProcess, ...]
    observed_count: int


def _find_tool(name: str) -> str | None:
    return shutil.which(name, path=TRUSTED_TOOL_PATH)


def _trusted_fuser(finder: Callable[[str], str | None]) -> str | None:
    value = finder("fuser")
    if not isinstance(value, str):
        return None
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.basename(value) != "fuser"
        or os.path.dirname(value) not in TRUSTED_TOOL_DIRECTORIES
    ):
        return None
    return value


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is None:
            process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=0.2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _capture_fuser(
    fuser: str,
    target: str,
    *,
    popen: Callable[..., subprocess.Popen[bytes]],
    deadline: float,
    maximum_bytes: int,
) -> tuple[str, int] | None:
    """Capture one fuser snapshot without buffering beyond the hard ceiling."""

    if maximum_bytes <= 0 or time.monotonic() >= deadline:
        return None
    try:
        process = popen(
            [fuser, "-m", target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        return None
    streams = (process.stdout, process.stderr)
    buffers = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    open_descriptors = set(buffers)
    captured = 0
    failed = False
    try:
        for descriptor in open_descriptors:
            os.set_blocking(descriptor, False)
        while open_descriptors:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            try:
                readable, _, _ = select.select(
                    tuple(open_descriptors), (), (), min(0.1, remaining),
                )
            except (OSError, ValueError):
                failed = True
                break
            for descriptor in readable:
                allowance = maximum_bytes + 1 - captured
                try:
                    block = os.read(descriptor, min(4096, max(1, allowance)))
                except BlockingIOError:
                    continue
                except OSError:
                    failed = True
                    break
                if not block:
                    open_descriptors.discard(descriptor)
                    continue
                buffers[descriptor].extend(block)
                captured += len(block)
                if captured > maximum_bytes:
                    failed = True
                    break
            if failed:
                break
        if failed:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            return None
        if returncode:
            return None
        stdout = bytes(buffers[process.stdout.fileno()])
        return stdout.decode("utf-8", errors="replace"), captured
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    finally:
        try:
            running = process.poll() is None
        except OSError:
            running = True
        if running:
            _stop_process(process)
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass


def _display_text(value: str, limit: int = 80) -> str:
    printable = "".join(
        character if character.isprintable() else " " for character in value
    )
    return " ".join(printable.split())[:limit]


@dataclass(frozen=True)
class _ResolvedProcess:
    process: ConflictingProcess
    proc_inode: int
    starttime: int


def _read_proc_file(directory: int, name: str, maximum: int) -> bytes | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
    except OSError:
        return None
    try:
        raw = os.read(descriptor, maximum + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return raw if len(raw) <= maximum else None


def _stat_starttime(raw: bytes | None) -> int | None:
    if not raw:
        return None
    closing = raw.rfind(b")")
    if closing < 0:
        return None
    fields = raw[closing + 1:].split()
    if len(fields) <= 19:
        return None
    try:
        return int(fields[19])
    except ValueError:
        return None


def _read_process(
    pid: int,
    *,
    proc_root: Path,
) -> _ResolvedProcess | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(proc_root / str(pid), flags)
    except OSError:
        return None
    try:
        try:
            process_status = os.fstat(directory)
        except OSError:
            return None
        raw_name = _read_proc_file(directory, "comm", MAX_PROCESS_NAME_BYTES)
        name = (
            _display_text(raw_name.decode("utf-8", errors="replace"))
            if raw_name is not None else ""
        )
        starttime = _stat_starttime(
            _read_proc_file(directory, "stat", MAX_PROCESS_STAT_BYTES)
        )
    finally:
        os.close(directory)
    if not name or starttime is None:
        return None
    return _ResolvedProcess(
        ConflictingProcess(pid, name, process_status.st_uid),
        process_status.st_ino,
        starttime,
    )


def _pids(stdout: str) -> list[int]:
    found: list[int] = []
    seen: set[int] = set()
    for match in _PID.finditer(stdout):
        pid = int(match.group())
        if pid not in seen:
            seen.add(pid)
            found.append(pid)
    return found


def probe_conflicting_processes(
    target: str,
    *,
    finder: Callable[[str], str | None] = _find_tool,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    proc_root: Path = Path("/proc"),
) -> ConflictReport:
    """Return processes using *target*, or an empty best-effort report."""

    if not isinstance(target, str) or not _BLOCK_PATH.fullmatch(target):
        return ConflictReport((), 0)
    fuser = _trusted_fuser(finder)
    if fuser is None:
        return ConflictReport((), 0)
    deadline = time.monotonic() + CONFLICT_PROBE_TIMEOUT_SECONDS
    first = _capture_fuser(
        fuser, target, popen=popen, deadline=deadline,
        maximum_bytes=MAX_CONFLICT_OUTPUT_BYTES,
    )
    if not first:
        return ConflictReport((), 0)
    first_stdout, first_bytes = first
    first_pids = _pids(first_stdout)
    resolved = tuple(
        process
        for pid in first_pids[:MAX_REPORTED_PROCESSES]
        if (process := _read_process(pid, proc_root=proc_root)) is not None
    )
    second = _capture_fuser(
        fuser, target, popen=popen, deadline=deadline,
        maximum_bytes=MAX_CONFLICT_OUTPUT_BYTES - first_bytes,
    )
    if not second:
        return ConflictReport((), 0)
    second_stdout, _second_bytes = second
    stable_pids = set(first_pids).intersection(_pids(second_stdout))
    processes = tuple(
        item.process
        for item in resolved
        if item.process.pid in stable_pids
        and _same_process(item, proc_root)
    )
    return ConflictReport(processes, len(stable_pids))


def _same_process(process: _ResolvedProcess, proc_root: Path) -> bool:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(
            proc_root / str(process.process.pid), flags,
        )
    except OSError:
        return False
    try:
        current = os.fstat(directory)
        starttime = _stat_starttime(
            _read_proc_file(directory, "stat", MAX_PROCESS_STAT_BYTES)
        )
    except OSError:
        return False
    finally:
        os.close(directory)
    return current.st_ino == process.proc_inode and starttime == process.starttime


def conflict_diagnostic_suffix(
    target: str,
    *,
    exists: Callable[[str], bool] = os.path.exists,
    **probe_options: object,
) -> str:
    """Format a bounded user-facing suffix for an unmount failure."""

    if not isinstance(target, str) or not _BLOCK_PATH.fullmatch(target):
        return ""
    try:
        if not exists(target):
            return ""
    except Exception:
        return ""
    try:
        report = probe_conflicting_processes(target, **probe_options)
    except Exception:
        return ""
    if not report.processes:
        return ""
    entries = []
    for process in report.processes:
        entries.append(
            f"{process.name} (PID {process.pid}, UID {process.uid})"
        )
    remaining = report.observed_count - len(report.processes)
    if remaining > 0:
        entries.append(f"and {remaining} more")
    return (
        " A recent snapshot found these processes using the target: "
        + ", ".join(entries)
        + ". Close them and try again."
    )
