"""Request OS authorization to relaunch the native GUI, without starting a write."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAC_AUTH_SCRIPT = """on run argv
    do shell script (item 1 of argv) with administrator privileges
end run"""

MAC_DETACHED_LAUNCHER = (
    "import subprocess,sys; log=open(sys.argv[1],'ab',buffering=0); "
    "child=subprocess.Popen(sys.argv[2:],stdin=subprocess.DEVNULL,stdout=log,"
    "stderr=subprocess.STDOUT,start_new_session=True,close_fds=True); print(child.pid)"
)


def mac_launch_command(arguments: list[str], log: Path) -> str:
    return shlex.join([sys.executable, "-I", "-c", MAC_DETACHED_LAUNCHER, str(log), *arguments])


def relaunch_arguments(image: str, checksum: str, target: str, include_fixed: bool) -> list[str]:
    arguments = [sys.executable, "-I", "-c",
                 "from isopropyl.entrypoints import gui; raise SystemExit(gui())"]
    for name, value in (("--image", image), ("--sha256", checksum), ("--target", target)):
        if value:
            arguments.extend((name, value))
    if include_fixed:
        arguments.append("--include-usb-hard-drives")
    return arguments


def launch_log_path(host: str) -> Path:
    base = (Path.home() / "Library" / "Logs" if host == "darwin" else
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))))
    directory = base / "ISOpropyl"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "native-launch.log"
    # Precreate as the desktop user, so an elevated child can append without
    # making the diagnostic inaccessible to the original application.
    with path.open("w", encoding="utf-8") as stream:
        stream.write("ISOpropyl authorized GUI launch\n")
    path.chmod(0o600)
    return path


def process_alive(pid: int) -> bool:
    if sys.platform != 'win32':
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except OSError:
            return False
    # os.kill(pid, 0) terminates a Windows process. Query it instead.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 5  # Access denied to an elevated process.
    try:
        code = wintypes.DWORD()
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        kernel.CloseHandle(handle)


def wait_for_ready(report: Path, log: Path, *, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with report.open(encoding="utf-8") as stream:
                state = json.loads(stream.read(2048))
        except (OSError, ValueError):
            time.sleep(.1)
            continue
        if not isinstance(state, dict):
            break
        if state.get("state") == "ready" and state.get("elevated") is True:
            pid = state.get("pid")
            if type(pid) is not int or pid <= 0:
                break
            if not process_alive(pid):
                break
            return
        if state.get("state") == "ready":
            raise PermissionError("The replacement app opened without administrator access. The current window has been kept open.")
        break
    try:
        with log.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 4096))
            detail = stream.read(4096).decode("utf-8", "replace").strip()
    except OSError:
        detail = "No startup diagnostic was available."
    raise RuntimeError(
        "The authorized app did not report a successful startup. "
        f"The current window has been kept open; no write was started.\nLog: {log}\n{detail}"
    )


def report_gui_ready(path: str) -> None:
    from .native_disk_io import require_privileges
    try:
        require_privileges(sys.platform)
        elevated = True
    except (PermissionError, ValueError, RuntimeError):
        elevated = False
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        if hasattr(os, "fchmod"):
            os.fchmod(stream.fileno(), 0o644)
        json.dump({"state": "ready", "elevated": elevated, "pid": os.getpid()}, stream)


def request_write_access(image: str = "", checksum: str = "", target: str = "",
                         include_fixed: bool = False, *, host: str | None = None, session_state: str = "", portable: bool = False) -> None:
    host = host or sys.platform
    if host not in {"darwin", "win32"}:
        raise ValueError("Native GUI elevation is supported on macOS and Windows")
    log = launch_log_path(host)
    arguments = relaunch_arguments(image, checksum, target, include_fixed)
    if portable:arguments.append("--portable")
    # Capture Python startup exceptions on Windows too (pythonw has no console).
    arguments[3] = (
        "import sys; log=sys.argv.pop(1); sys.stdout=sys.stderr=open(log,'a',buffering=1); "
        "from isopropyl.entrypoints import gui; raise SystemExit(gui())"
    )
    arguments.insert(4, str(log))
    with tempfile.TemporaryDirectory(prefix="isopropyl-launch-") as directory:
        report = Path(directory) / "ready.json"
        if session_state:
            import hashlib
            payload=session_state.encode('ascii')
            if len(payload)>16*1024*1024:raise ValueError('Session settings exceed their limit')
            state=Path(directory)/'session.txt';state.write_bytes(payload);state.chmod(0o600)
            arguments.extend(('--session-state-file',str(state),'--session-state-sha256',hashlib.sha256(payload).hexdigest()))
        arguments.extend(("--startup-report", str(report)))
        _launch_authorized(arguments, host, log)
        wait_for_ready(report, log)


def _launch_authorized(arguments: list[str], host: str, log: Path) -> None:
    if host == "darwin":
        # The script is fixed; every command argument is individually shell-quoted.
        # Python creates a new session and redirects every standard descriptor.
        # macOS nohup attempts a console ioctl and fails in the authorization
        # service's non-terminal environment before it can launch the GUI.
        command = mac_launch_command(arguments, log)
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", MAC_AUTH_SCRIPT, command],
            check=False, capture_output=True, text=True, timeout=180, shell=False,
        )
        if result.returncode:
            if "-128" in (result.stderr or ""):
                raise PermissionError("Authorization cancelled. No write was started.")
            detail = (result.stderr or "").strip()[-2048:]
            raise PermissionError(detail or "macOS could not authorize write access")
    elif host == "win32":
        import ctypes
        from ctypes import wintypes
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        launch = shell.ShellExecuteW
        launch.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                           wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
        launch.restype = ctypes.c_ssize_t
        if launch(None, "runas", arguments[0], subprocess.list2cmdline(arguments[1:]),
                  os.getcwd(), 1) <= 32:
            raise PermissionError("Windows authorization was cancelled or write access could not be granted. No write was started.")
