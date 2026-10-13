# Supported platforms

ISOpropyl supports Linux and Windows on x86-64 and ARM64, and macOS on Apple
silicon ARM64. Native macOS packages require macOS 13 or newer; native Windows
packages require Windows 10 1903 or newer, or Windows 11. Intel macOS, Rosetta
Python, 32-bit x86 and 32-bit ARM hosts are excluded. Host architecture does not
change the architecture of the installer being written.

## Shared workflows

The native macOS and Windows interfaces use the same compact dimensions,
dark-gray/orange visual language and Yes/Cancel erase confirmation as Linux.
Advanced controls live in dialogs so the main window stays small.

| Workflow | Linux | macOS / Windows |
|---|---|---|
| USB/SD discovery, fixed USB opt-in, ignored drives | Supported | Supported, with native disk identity and locking |
| Raw and hybrid ISO writes | Supported | Supported, activation headers published after mandatory read-back |
| Compressed and sparse inputs | gzip, bzip2, xz/LZMA, ZIP, Zstandard, UNIX compress, VTSI | Same formats; VTSI requires the exact advertised target size |
| Virtual disk inputs and compressed virtual disks | VHD, VHDX, QCOW, QCOW2 | Same formats, private QEMU conversion and independent comparison |
| ISO extraction mode | Supported profiles | FAT32 or NTFS, MBR/GPT, UEFI and the shared experimental BIOS profiles |
| Windows installer preparation | Supported | Shared customization, edition selection, large WIM splitting and large ESD conversion |
| Reviewed Windows BootEx replacement | Exact supported official ISO profiles | Same profiles and compatibility acknowledgments |
| UEFI:NTFS | Supported profiles | Same pinned helper and payload trust policy |
| Persistence | Supported Ubuntu amd64 Casper profiles | Ubuntu 20.04, 22.04 and 24.04 profiles, shared configuration transforms and ext4 persistence |
| ZIP overlays | Supported additive transforms | Same path, collision and reserved-file policies |
| Image inspection, checksums and plan details | Supported | Full catalog, bootloader/El Torito, EFI, Authenticode and DBX analysis |
| Official image downloads | Ubuntu, Windows, FreeDOS | Same catalogs, authority checks and verified resumable publication |
| Drive backups | Raw, sparse raw, VHD, VHDX | Same formats, read-only capture, independent source reread and no-overwrite publication |
| Optical capture | Supported | Native data-disc discovery, read-only capture and source reread |
| Restore/format | FAT12/16/32, exFAT, NTFS, UDF, ext2/3/4 | Same filesystem choices, MBR/GPT, labels and allocation controls; 512/1024/2048/4096-byte logical sectors |
| Zeroing and media tests | Supported | Full/fast logical zeroing, sampled capacity probe, configurable full surface passes and combined testing |
| UEFI Shell and GRUB rescue | Supported profiles | Same pinned multi-architecture UEFI Shell and experimental GRUB rescue profiles |
| Settings, logs and helper cache | Supported | Native settings, portable INI mode, size units, ignored drives, diagnostics and cache controls |
| CLI | Raw writer | Raw writer plus native media preparation, inspection and drive tools |

Experimental Linux profiles remain experimental everywhere. Windows To Go,
standalone apply-format containers and other unfinished Linux features are not
made supported by this portability work. Signature inspection reports evidence;
it does not assert that a machine's Secure Boot firmware trusts a payload.
Partitioned UDF may not auto-mount on macOS, matching the upstream formatter's
reported operating-system limitation.

## Native implementation

ISO extraction, filesystem construction, customization and boot-sector changes
operate on private regular files before any target is opened. The final writer
binds the confirmed target identity, holds one native device handle, writes and
verifies payload bytes while activation headers are withheld, then publishes and
reads back those headers. Stale backup partition metadata outside the image is
cleared and checked. This is logical writing/erasure, not hardware Secure Erase.

macOS keeps the interface and preparation process at user privilege. The signed
system `authopen` service authorizes a raw disk descriptor for the device worker.
Windows uses UAC and native Win32 volume locks, dismounts and aligned uncached
I/O. Administrator relaunch preserves installer/media settings. Console helpers
run with hidden windows.

Bundled helper executables have architecture-specific SHA-256 manifests,
provenance and license texts. They are verified before use. Source checkouts may
use known host-installed tools; packaged apps include their dependencies.

## Building and testing

Use native 64-bit Python with the project's declared dependencies for source
runs. `python tools/install_macos.py --launch` installs the Apple silicon app and
runtime. `tools/build_windows_portable.py` builds an offline runtime bundle for
`--architecture x86-64` or `--architecture arm64`; `tools/build_windows_exe.py`
wraps it in an unsigned portable EXE. Helper build and smoke-test scripts live in
`tools/`. Portable settings use `--portable` or an `isopropyl.ini` beside the
launcher. Ordinary settings use the operating system's Qt settings location.

Automated tests use regular disk images and mock devices, including mutation,
failed read-back, cancellation and publication failures. Native CI runs on Apple
silicon, Windows x86-64 and Windows ARM64; Linux CI runs both architectures. CI
never writes a physical drive. Regular-image preparation and virtual-disk tests
are distinct from physical USB and firmware boot testing. The original macOS
Windows installer workflow was tested on a real USB and booted a laptop; the
expanded workflows need representative physical-media testing before release
certification. See [PARITY.md](PARITY.md) for validation evidence.
