"""Native whole-disk handles. All OS APIs are imported only on their host."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import errno
import os
import stat
import struct
from contextlib import ExitStack, contextmanager

from .native_devices import (
    DISKUTIL,
    MAC_DISK,
    WIN_DISK,
    WIN_VOLUME,
    NativeDevice,
    command,
)


def authorized_mac_open(path: str, flags: int) -> int:
    """Receive an authorized descriptor from Apple's signed disk opener."""
    import array
    import socket
    import subprocess
    import tempfile

    descriptors = []
    process = None
    parent, child = socket.socketpair()
    try:
        with parent, child, tempfile.TemporaryFile() as errors:
            parent.settimeout(120)
            process = subprocess.Popen(
                ['/usr/libexec/authopen', '-stdoutpipe', '-o', str(flags), path],
                stdin=subprocess.DEVNULL, stdout=child, stderr=errors, close_fds=True)
            child.close()
            try:
                _, ancillary, message_flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(16 * array.array('i').itemsize))
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        received = array.array('i')
                        received.frombytes(data[:len(data) - len(data) % received.itemsize])
                        descriptors.extend(received)
                code = process.wait(timeout=5)
            except (TimeoutError, subprocess.TimeoutExpired) as error:
                raise OSError('Authorized disk access timed out; no write was started') from error
            if code or message_flags & socket.MSG_CTRUNC or len(descriptors) != 1:
                errors.seek(0)
                detail = errors.read(2048).decode('utf-8', errors='replace').strip()
                guidance = ('\nOpen System Settings → Privacy & Security → Files and Folders and allow '
                            'ISOpropyl access to removable volumes. If raw-disk access is still denied, '
                            'add ISOpropyl.app under Full Disk Access, then quit and reopen it.'
                            if 'Operation not permitted' in detail else '')
                raise PermissionError(f'macOS could not authorize access to {path}. {detail}{guidance}')
            os.set_inheritable(descriptors[0], False)
            return descriptors.pop()
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for descriptor in descriptors:
            os.close(descriptor)


def require_privileges(host: str) -> None:
    from .host_platform import validate_host
    validate_host(host=host)
    if host == "darwin":
        if os.geteuid() != 0:
            raise PermissionError("Writing requires sudo. Use sudo /absolute/path/to/isopropyl-cli write …")
    elif host == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Writing requires a terminal opened with Run as administrator")
    else:
        raise ValueError("Unsupported native write host")


class MacDisk:
    def __init__(self, descriptor: int):
        self.descriptor = descriptor

    def read(self, size: int) -> bytes:
        return os.read(self.descriptor, size)

    def write(self, data: bytes) -> int:
        return os.write(self.descriptor, data)

    def seek(self, offset: int) -> None:
        os.lseek(self.descriptor, offset, os.SEEK_SET)

    def flush(self) -> None:
        import fcntl
        os.fsync(self.descriptor)
        # _IOW('d', 22, dk_synchronize_t); options and reserved bytes are zero.
        fcntl.ioctl(self.descriptor, 0x80186416, bytes(24))


class WindowsApi:
    """Pointer-sized, explicitly typed Win32 declarations for 64-bit Python."""
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w = c, w
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "DeviceIoControl": ([w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
            "ReadFile": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
            "WriteFile": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
            "SetFilePointerEx": ([w.HANDLE, c.c_longlong, c.POINTER(c.c_longlong), w.DWORD], w.BOOL),
            "FlushFileBuffers": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = arguments, result

    def check(self, result):
        if not result:
            raise self.c.WinError(self.c.get_last_error())
        return result

    def open(self, path: str, *, read_only=False):
        handle = self.kernel.CreateFileW(path, 0x80000000 if read_only else 0xC0000000, 3, None, 3, 0xA0000000, None)
        if handle == self.c.c_void_p(-1).value:
            raise self.c.WinError(self.c.get_last_error())
        return handle

    def control(self, handle, code: int, output_size: int = 0) -> bytes:
        output = self.c.create_string_buffer(output_size) if output_size else None
        returned = self.w.DWORD()
        self.check(self.kernel.DeviceIoControl(handle, code, None, 0, output, output_size, self.c.byref(returned), None))
        if output_size and returned.value != output_size:
            raise OSError("Native disk control returned incomplete metadata")
        return output.raw if output else b""


class WindowsDisk:
    def __init__(self, api: WindowsApi, handle):
        self.api, self.handle = api, handle

    def read(self, size: int) -> bytes:
        # FILE_FLAG_NO_BUFFERING makes verification reach storage instead of
        # accepting bytes retained in the Windows file cache. Allocate a
        # separately aligned address while retaining its owner through I/O.
        buffer = self.api.c.create_string_buffer(size + 65535)
        address = (self.api.c.addressof(buffer) + 65535) & ~65535
        count = self.api.w.DWORD()
        self.api.check(self.api.kernel.ReadFile(self.handle, address, size, self.api.c.byref(count), None))
        if count.value>size:raise OSError('Windows read returned an invalid byte count')
        return self.api.c.string_at(address, count.value)

    def write(self, data: bytes) -> int:
        buffer = self.api.c.create_string_buffer(len(data) + 65535)
        address = (self.api.c.addressof(buffer) + 65535) & ~65535
        self.api.c.memmove(address, data, len(data))
        count = self.api.w.DWORD()
        self.api.check(self.api.kernel.WriteFile(self.handle, address, len(data), self.api.c.byref(count), None))
        return count.value

    def seek(self, offset: int) -> None:
        self.api.check(self.api.kernel.SetFilePointerEx(self.handle, offset, None, 0))

    def flush(self) -> None:
        self.api.check(self.api.kernel.FlushFileBuffers(self.handle))


@contextmanager
def open_disk(target: NativeDevice, host: str):
    """Unmount/lock every volume, bind the opened device, retain locks to close."""
    device = target.device
    with ExitStack() as stack:
        if host == "darwin":
            import fcntl
            name = device.path.removeprefix("/dev/")
            if not MAC_DISK.fullmatch(name):
                raise ValueError("Expected an exact macOS whole-disk path")
            for container in target.volumes:
                if not container.startswith("/dev/") or not MAC_DISK.fullmatch(container[5:]) or container == device.path:
                    raise ValueError("Invalid APFS container identity")
            for container in target.volumes:
                command([DISKUTIL, "unmountDisk", container])
            command([DISKUTIL, "unmountDisk", device.path])
            raw = f"/dev/r{name}"
            flags = os.O_RDWR | os.O_EXLOCK | os.O_NONBLOCK | os.O_NOFOLLOW
            try:
                if os.geteuid() != 0:
                    raise PermissionError(errno.EPERM, 'Disk descriptor requires authorization')
                descriptor = os.open(raw, flags)
            except PermissionError as error:
                if error.errno != errno.EPERM:
                    raise
                if not stat.S_ISCHR(os.lstat(raw).st_mode):
                    raise OSError('The raw disk path is not a character device') from error
                # authopen canonicalizes the path and rejects O_NOFOLLOW.
                # Bind the returned descriptor to this device below.
                descriptor = authorized_mac_open(raw, flags & ~os.O_NOFOLLOW)
            stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != os.stat(raw).st_rdev:
                raise OSError("Opened target is not the selected raw device")
            sector = struct.unpack("=I", fcntl.ioctl(descriptor, 0x40046418, bytes(4)))[0]
            blocks = struct.unpack("=Q", fcntl.ioctl(descriptor, 0x40086419, bytes(8)))[0]
            external = struct.unpack("=Q", fcntl.ioctl(descriptor, 0x40086421, bytes(8)))[0]
            if sector != device.logical_sector_size or blocks * sector != device.size or external != 1:
                raise OSError("Opened disk geometry or external location changed")
            yield MacDisk(descriptor)
        elif host == "win32":
            match = WIN_DISK.fullmatch(device.path)
            if not match:
                raise ValueError("Expected an exact Windows PhysicalDrive path")
            api = WindowsApi()
            number = int(match[1])
            for volume in target.volumes:
                if not WIN_VOLUME.fullmatch(volume):
                    raise ValueError("Invalid volume identity")
                handle = api.open(volume.rstrip("\\"))
                stack.callback(api.kernel.CloseHandle, handle)
                # STORAGE_DEVICE_NUMBER: type, disk number, partition number.
                if struct.unpack("<III", api.control(handle, 0x2D1080, 12))[1] != number:
                    raise OSError("Volume moved to another physical disk")
                api.control(handle, 0x90018)  # FSCTL_LOCK_VOLUME
                api.control(handle, 0x90020)  # FSCTL_DISMOUNT_VOLUME
            handle = api.open(device.path)
            stack.callback(api.kernel.CloseHandle, handle)
            if struct.unpack("<III", api.control(handle, 0x2D1080, 12))[1] != number:
                raise OSError("Physical disk number changed")
            size = struct.unpack("<q", api.control(handle, 0x7405C, 8))[0]
            geometry = api.control(handle, 0x70000, 24)  # DISK_GEOMETRY
            sector = struct.unpack_from("<I", geometry, 20)[0]
            if size != device.size or sector != device.logical_sector_size:
                raise OSError("Opened disk geometry changed")
            yield WindowsDisk(api, handle)
        else:
            raise ValueError("Unsupported native disk backend")

@contextmanager
def open_read_disk(target: NativeDevice, host: str):
    """Unmount/lock source volumes and retain a read-only whole-drive handle."""
    device = target.device
    with ExitStack() as stack:
        if host == 'darwin':
            import fcntl
            name = device.path.removeprefix('/dev/')
            if not MAC_DISK.fullmatch(name):
                raise ValueError('Expected an exact macOS whole-disk path')
            for container in target.volumes:
                if not container.startswith('/dev/') or not MAC_DISK.fullmatch(container[5:]) or container==device.path:
                    raise ValueError('Invalid source APFS container identity')
                command([DISKUTIL,'unmountDisk',container])
            command([DISKUTIL,'unmountDisk',device.path])
            raw = '/dev/r' + name
            flags = os.O_RDONLY | os.O_EXLOCK | os.O_NONBLOCK | os.O_NOFOLLOW
            try:
                descriptor = os.open(raw, flags)
            except PermissionError:
                descriptor = authorized_mac_open(raw, flags & ~os.O_NOFOLLOW)
            stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != os.stat(raw).st_rdev:
                raise OSError('Opened source is not the selected raw device')
            sector = struct.unpack('=I', fcntl.ioctl(descriptor, 0x40046418, bytes(4)))[0]
            blocks = struct.unpack('=Q', fcntl.ioctl(descriptor, 0x40086419, bytes(8)))[0]
            if sector != device.logical_sector_size or blocks * sector != device.size:
                raise OSError('Opened source geometry changed')
            yield MacDisk(descriptor)
        elif host == 'win32':
            if not WIN_DISK.fullmatch(device.path):
                raise ValueError('Expected an exact Windows PhysicalDrive path')
            api = WindowsApi()
            number = int(WIN_DISK.fullmatch(device.path)[1])
            for volume in target.volumes:
                if not WIN_VOLUME.fullmatch(volume):raise ValueError('Invalid source volume identity')
                source_handle=api.open(volume.rstrip('\\'),read_only=True)
                stack.callback(api.kernel.CloseHandle,source_handle)
                if struct.unpack('<III',api.control(source_handle,0x2D1080,12))[1]!=number:
                    raise OSError('Source volume moved to another physical disk')
                api.control(source_handle,0x90018)
                api.control(source_handle,0x90020)
            handle = api.open(device.path, read_only=True)
            stack.callback(api.kernel.CloseHandle, handle)
            number = int(WIN_DISK.fullmatch(device.path)[1])
            if struct.unpack('<III', api.control(handle, 0x2D1080, 12))[1] != number:
                raise OSError('Physical source number changed')
            size = struct.unpack('<q', api.control(handle, 0x7405C, 8))[0]
            sector = struct.unpack_from('<I', api.control(handle, 0x70000, 24), 20)[0]
            if size != device.size or sector != device.logical_sector_size:
                raise OSError('Opened source geometry changed')
            yield WindowsDisk(api, handle)
        else:
            raise ValueError('Unsupported native read backend')
