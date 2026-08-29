#!/usr/bin/python3 -I
from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Build ISOpropyl's auditable Debian/Ubuntu binary package without networking."""

import argparse
import gzip
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "isopropyl"
DEBIAN_REVISION = "1"
DEFAULT_SOURCE_DATE_EPOCH = 1_787_788_800  # 2026-08-27T00:00:00Z
TRUSTED_PATH = "/usr/bin:/bin"
SAFE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~_-]*\Z")
SUPPORTED_ARCHITECTURES = frozenset({"amd64", "arm64"})
PYTHON_PACKAGE_FILES = tuple(
    """
__init__.py
app.py
authenticode.py
authenticode_worker.py
backup.py
boot_identity.py
bootloaders.py
casper_media.py
cli.py
conflicts.py
constructed.py
data/bootloaders-v2.json
data/distro-write-policies-v1.json
data/freedos-images-v1.json
data/io.github.codebooker.isopropyl.svg
data/linux-images-v1.json
data/microsoft-dbx-authenticode-v1.json
data/windows-images-v2.json
dbx.py
devices.py
diagnostics.py
distro_policies.py
eltorito.py
erase.py
extraction.py
fast_zero.py
fat_image.py
formatting.py
freedos_downloads.py
images.py
iso.py
iso_staging.py
linux_downloads.py
locking.py
logging_setup.py
media_test.py
optical.py
partition_tables.py
persistence.py
private_fat32.py
progress.py
raw_device.py
raw_device_runner.py
raw_snapshot.py
raw_workflow.py
restore_device_helper.py
restore_device_runner.py
runtime_validation.py
settings.py
sources.py
staging_tree.py
syslinux.py
syslinux_device.py
syslinux_device_helper.py
syslinux_device_runner.py
syslinux_fat.py
syslinux_iso_fat32.py
syslinux_staging.py
syslinux_transaction.py
syslinux_workflow.py
timestamps.py
uefi.py
uefi_ntfs.py
uefi_shell.py
verified_download.py
virtual.py
vtsi.py
wim.py
wim_apply_backend.py
wim_apply_protocol.py
windows.py
windows_bcd.py
windows_bcd_capture.py
windows_bcd_capture_import.py
windows_bcd_hivex.py
windows_bcd_oracle.py
windows_bootex.py
windows_downloads.py
windows_paths.py
windows_to_go.py
windows_hive.py
writer.py
zip_overlay.py
""".split()
)
LICENSE_FILES = (
    "CERTVALIDATOR-MIT.txt",
    "MICROSOFT-SECUREBOOT-OBJECTS-BSD-2-CLAUSE-PATENT.txt",
    "SYSLINUX-MBR-MIT.txt",
)
COMPRESSED_DOCUMENTS = (
    ("README.md", "README.md.gz"),
    ("SECURITY.md", "SECURITY.md.gz"),
    ("FEATURE_MATRIX.md", "FEATURE_MATRIX.md.gz"),
    ("ROADMAP.md", "ROADMAP.md.gz"),
    ("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md.gz"),
    ("LICENSE", "LICENSE.gz"),
)

PAYLOAD_FILES: tuple[tuple[str, str, int], ...] = (
    ("packaging/debian/isopropyl", "usr/bin/isopropyl", 0o755),
    ("packaging/debian/isopropyl-cli", "usr/bin/isopropyl-cli", 0o755),
    (
        "packaging/debian/isopropyl-validate-windows-bcd-capture",
        "usr/bin/isopropyl-validate-windows-bcd-capture",
        0o755,
    ),
    (
        "tools/validate_windows_bcd_capture.py",
        "usr/lib/isopropyl-tools/validate_windows_bcd_capture.py",
        0o644,
    ),
    (
        "packaging/debian/isopropyl-import-windows-bcd-capture",
        "usr/bin/isopropyl-import-windows-bcd-capture",
        0o755,
    ),
    (
        "tools/import_windows_bcd_capture.py",
        "usr/lib/isopropyl-tools/import_windows_bcd_capture.py",
        0o644,
    ),
    (
        "tools/capture_windows_bcd_oracle.ps1",
        "usr/share/doc/isopropyl/examples/capture_windows_bcd_oracle.ps1",
        0o644,
    ),
    (
        "helper/isopropyl-device-helper",
        "usr/libexec/isopropyl-device-helper",
        0o755,
    ),
    (
        "isopropyl/syslinux_device_helper.py",
        "usr/libexec/isopropyl/syslinux_device_helper.py",
        0o644,
    ),
    (
        "helper/isopropyl-restore-device-helper",
        "usr/libexec/isopropyl-restore-device-helper",
        0o755,
    ),
    (
        "isopropyl/restore_device_helper.py",
        "usr/libexec/isopropyl/restore_device_helper.py",
        0o644,
    ),
    (
        "packaging/debian/io.github.codebooker.isopropyl.desktop",
        "usr/share/applications/io.github.codebooker.isopropyl.desktop",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.metainfo.xml",
        "usr/share/metainfo/io.github.codebooker.isopropyl.metainfo.xml",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.svg",
        "usr/share/icons/hicolor/scalable/apps/io.github.codebooker.isopropyl.svg",
        0o644,
    ),
    (
        "data/icons/48x48/apps/io.github.codebooker.isopropyl.png",
        "usr/share/icons/hicolor/48x48/apps/io.github.codebooker.isopropyl.png",
        0o644,
    ),
    (
        "data/icons/64x64/apps/io.github.codebooker.isopropyl.png",
        "usr/share/icons/hicolor/64x64/apps/io.github.codebooker.isopropyl.png",
        0o644,
    ),
    (
        "data/icons/128x128/apps/io.github.codebooker.isopropyl.png",
        "usr/share/icons/hicolor/128x128/apps/io.github.codebooker.isopropyl.png",
        0o644,
    ),
    (
        "data/icons/256x256/apps/io.github.codebooker.isopropyl.png",
        "usr/share/icons/hicolor/256x256/apps/io.github.codebooker.isopropyl.png",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.policy",
        "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.policy",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.raw-write.policy",
        "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.raw-write.policy",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.fast-zero.policy",
        "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.fast-zero.policy",
        0o644,
    ),
    (
        "data/io.github.codebooker.isopropyl.restore-device.policy",
        "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.restore-device.policy",
        0o644,
    ),
    (
        "packaging/debian/copyright",
        "usr/share/doc/isopropyl/copyright",
        0o644,
    ),
    ("BRANDING.md", "usr/share/doc/isopropyl/BRANDING.md", 0o644),
    (
        "packaging/debian/README.Debian",
        "usr/share/doc/isopropyl/README.Debian",
        0o644,
    ),
)


class PackageBuildError(RuntimeError):
    """The package could not be built from an exact safe source tree."""


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return DEFAULT_SOURCE_DATE_EPOCH
    if not raw.isascii() or not raw.isdecimal():
        raise PackageBuildError("SOURCE_DATE_EPOCH must be an ASCII integer")
    value = int(raw)
    if not 0 <= value <= 4_294_967_295:
        raise PackageBuildError("SOURCE_DATE_EPOCH is outside the supported range")
    return value


def _version() -> str:
    try:
        project_text = _read_regular(ROOT / "pyproject.toml").decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise PackageBuildError("Could not read the project version") from error
    matches = re.findall(r'^version = "([^"]+)"$', project_text, re.MULTILINE)
    if len(matches) != 1 or SAFE_VERSION.fullmatch(matches[0]) is None:
        raise PackageBuildError("The project version is not Debian-safe")
    version = matches[0]
    try:
        init_text = _read_regular(ROOT / "isopropyl/__init__.py").decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise PackageBuildError("Could not read the package version") from error
    if f'__version__ = "{version}"' not in init_text:
        raise PackageBuildError("Project version declarations disagree")
    return f"{version}-{DEBIAN_REVISION}"


def _mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o755)


def _read_regular(source: Path) -> bytes:
    try:
        source_status = source.lstat()
    except OSError as error:
        raise PackageBuildError(f"Required source is unavailable: {source}") from error
    if not stat.S_ISREG(source_status.st_mode) or source_status.st_nlink != 1:
        raise PackageBuildError(f"Required source is not a singly linked file: {source}")
    descriptor = -1
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or opened_status.st_nlink != 1
            or (opened_status.st_dev, opened_status.st_ino)
            != (source_status.st_dev, source_status.st_ino)
        ):
            raise PackageBuildError(f"Required source changed while opening: {source}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read()
        final_status = os.fstat(descriptor)
    except OSError as error:
        raise PackageBuildError(f"Could not safely read required source: {source}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(opened_status, name) != getattr(final_status, name) for name in identity_fields)
        or len(payload) != opened_status.st_size
    ):
        raise PackageBuildError(f"Required source changed while reading: {source}")
    return payload


def _copy_regular(source: Path, destination: Path, mode: int) -> None:
    payload = _read_regular(source)
    _mkdir(destination.parent)
    with destination.open("xb") as output:
        output.write(payload)
    destination.chmod(mode)


def _write_bytes(destination: Path, payload: bytes, mode: int = 0o644) -> None:
    _mkdir(destination.parent)
    with destination.open("xb") as stream:
        stream.write(payload)
    destination.chmod(mode)


def _copy_python_package(stage: Path) -> None:
    source_root = ROOT / "isopropyl"
    destination_root = stage / "usr/lib/python3/dist-packages/isopropyl"
    expected = set(PYTHON_PACKAGE_FILES)
    actual: set[str] = set()
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(source_root)
        if "__pycache__" in relative.parts:
            continue
        status = source.lstat()
        if stat.S_ISDIR(status.st_mode):
            if relative.as_posix() != "data":
                raise PackageBuildError(
                    f"Python package contains an unexpected directory: {relative}"
                )
            continue
        actual.add(relative.as_posix())
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        details = "; ".join(
            part
            for part in (
                f"unexpected={unexpected}" if unexpected else "",
                f"missing={missing}" if missing else "",
            )
            if part
        )
        raise PackageBuildError(f"Python package allowlist mismatch: {details}")
    for relative_name in PYTHON_PACKAGE_FILES:
        _copy_regular(
            source_root / relative_name,
            destination_root / relative_name,
            0o644,
        )
    if not (destination_root / "data/windows-images-v2.json").is_file():
        raise PackageBuildError("The current Windows catalog was not packaged")
    if (destination_root / "data/windows-images-v1.json").exists():
        raise PackageBuildError("The retired Windows catalog entered the package")


def _copy_licenses(stage: Path) -> None:
    source_root = ROOT / "licenses"
    actual = {source.name for source in source_root.iterdir()}
    expected = set(LICENSE_FILES)
    if actual != expected:
        raise PackageBuildError("License allowlist does not match the source tree")
    for name in LICENSE_FILES:
        _copy_regular(
            source_root / name,
            stage / "usr/share/doc/isopropyl/licenses" / name,
            0o644,
        )


def _write_gzip(source: Path, destination: Path, epoch: int) -> None:
    payload = _read_regular(source)
    _mkdir(destination.parent)
    with destination.open("xb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch,
        ) as compressed:
            compressed.write(payload)
    destination.chmod(0o644)


def _write_changelog(stage: Path, epoch: int) -> None:
    _write_gzip(
        ROOT / "packaging/debian/changelog",
        stage / "usr/share/doc/isopropyl/changelog.Debian.gz",
        epoch,
    )


def _write_compressed_documents(stage: Path, epoch: int) -> None:
    for source_name, destination_name in COMPRESSED_DOCUMENTS:
        _write_gzip(
            ROOT / source_name,
            stage / "usr/share/doc/isopropyl" / destination_name,
            epoch,
        )


def _write_manpages(stage: Path, epoch: int) -> None:
    for name in ("isopropyl.1", "isopropyl-cli.1"):
        _write_gzip(
            ROOT / "packaging/debian" / name,
            stage / "usr/share/man/man1" / f"{name}.gz",
            epoch,
        )


def _installed_size(stage: Path) -> int:
    total = sum(
        path.stat().st_size
        for path in stage.rglob("*")
        if path.is_file() and "DEBIAN" not in path.relative_to(stage).parts
    )
    return max(1, (total + 1023) // 1024)


def _control(version: str, architecture: str, installed_size: int) -> bytes:
    return (
        "Package: isopropyl\n"
        f"Version: {version}\n"
        "Section: utils\n"
        "Priority: optional\n"
        f"Architecture: {architecture}\n"
        "Maintainer: ISOpropyl contributors <codebooker@users.noreply.github.com>\n"
        f"Installed-Size: {installed_size}\n"
        "Depends: python3 (>= 3.10), python3-pyqt6 (>= 6.5), "
        "python3-pyqt6 (<< 7), pkexec, udisks2, fdisk, parted, udev, "
        "dosfstools, ntfs-3g, ca-certificates, gpgv, 7zip | p7zip-full\n"
        "Recommends: polkit-1-auth-agent, wimtools, qemu-utils, exfatprogs, "
        "udftools (>= 1.1), e2fsprogs, f3, xorriso, "
        "python3-zstandard | zstd, psmisc\n"
        "Suggests: python3-hivex\n"
        "Homepage: https://github.com/codebooker/isopropyl\n"
        "Description: safety-first bootable USB and SD writer for Linux\n"
        " ISOpropyl provides a Qt interface and a confirmation-bound terminal\n"
        " raw writer, filesystem-aware UEFI media construction, image inspection,\n"
        " verified downloads, drive tools, and guarded PolicyKit transactions.\n"
        " .\n"
        " This is destructive alpha software; verify every selected target and\n"
        " keep post-write verification enabled.\n"
    ).encode("utf-8")


def _write_md5sums(stage: Path) -> None:
    records: list[str] = []
    for path in sorted(stage.rglob("*")):
        relative = path.relative_to(stage)
        if not path.is_file() or "DEBIAN" in relative.parts:
            continue
        digest = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
        records.append(f"{digest}  {relative.as_posix()}")
    _write_bytes(
        stage / "DEBIAN/md5sums",
        ("\n".join(records) + "\n").encode("ascii"),
    )


def _normalize(stage: Path, epoch: int) -> None:
    for path in sorted(stage.rglob("*"), reverse=True):
        if path.is_symlink():
            raise PackageBuildError(f"Package stage contains a symbolic link: {path}")
        if path.is_dir():
            path.chmod(0o755)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(stage, (epoch, epoch), follow_symlinks=False)


def _dpkg_deb() -> str:
    executable = shutil.which("dpkg-deb", path=TRUSTED_PATH)
    if executable is None or Path(executable).resolve() != Path("/usr/bin/dpkg-deb"):
        raise PackageBuildError("Trusted /usr/bin/dpkg-deb is unavailable")
    return executable


def _architecture() -> str:
    executable = shutil.which("dpkg", path=TRUSTED_PATH)
    if executable is None or Path(executable).resolve() != Path("/usr/bin/dpkg"):
        raise PackageBuildError("Trusted /usr/bin/dpkg is unavailable")
    try:
        completed = subprocess.run(
            [executable, "--print-architecture"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"},
        )
    except subprocess.CalledProcessError as error:
        raise PackageBuildError("dpkg could not determine the host architecture") from error
    architecture = completed.stdout.strip()
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise PackageBuildError(
            "ISOpropyl's privileged helper currently supports only amd64 and arm64"
        )
    return architecture


def build_package(output_directory: Path) -> Path:
    epoch = _source_date_epoch()
    version = _version()
    architecture = _architecture()
    output_directory = output_directory.expanduser().resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        raise PackageBuildError("Package output is not a directory")
    final = output_directory / f"{PACKAGE}_{version}_{architecture}.deb"
    if final.exists() or final.is_symlink():
        raise PackageBuildError(f"Refusing to overwrite existing package: {final}")

    with tempfile.TemporaryDirectory(
        prefix=".isopropyl-deb-", dir=output_directory,
    ) as temporary:
        temporary_root = Path(temporary)
        stage = temporary_root / "root"
        _mkdir(stage)
        for source_name, destination_name, mode in PAYLOAD_FILES:
            _copy_regular(ROOT / source_name, stage / destination_name, mode)
        _copy_python_package(stage)
        _copy_licenses(stage)
        _write_changelog(stage, epoch)
        _write_compressed_documents(stage, epoch)
        _write_manpages(stage, epoch)
        _write_bytes(
            stage / "DEBIAN/control",
            _control(version, architecture, _installed_size(stage)),
        )
        _write_md5sums(stage)
        _normalize(stage, epoch)

        built = temporary_root / final.name
        environment = {
            "PATH": TRUSTED_PATH,
            "LC_ALL": "C",
            "LANG": "C",
            "SOURCE_DATE_EPOCH": str(epoch),
        }
        try:
            subprocess.run(
                [
                    _dpkg_deb(), "--root-owner-group", "--uniform-compression",
                    "--threads-max=1", "-Zxz", "-z9", "--build",
                    str(stage), str(built),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
        except subprocess.CalledProcessError as error:
            raise PackageBuildError("dpkg-deb rejected the package stage") from error
        if not built.is_file() or built.is_symlink() or built.stat().st_size == 0:
            raise PackageBuildError("dpkg-deb did not return a regular package")
        built.chmod(0o644)
        try:
            os.link(built, final)
        except FileExistsError as error:
            raise PackageBuildError(f"Refusing to overwrite existing package: {final}") from error
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "dist",
        help="directory for isopropyl_VERSION_ARCH.deb (default: dist)",
    )
    arguments = parser.parse_args()
    try:
        result = build_package(arguments.output_dir)
    except (OSError, PackageBuildError) as error:
        parser.exit(1, f"isopropyl-deb: {error}\n")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
