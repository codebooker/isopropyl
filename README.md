<div align="center">

![ISOpropyl — Bootable media, made simple](data/isopropyl-hero.svg)

[![Tests](https://github.com/codebooker/isopropyl/actions/workflows/test.yml/badge.svg)](https://github.com/codebooker/isopropyl/actions/workflows/test.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-F6922E.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-252B35.svg?logo=linux&logoColor=white)](#requirements)
[![Status: alpha](https://img.shields.io/badge/status-alpha-5B6574.svg)](#project-status)

**A capable, safety-first USB image writer built for Linux.**

[Install](#install-from-source) · [Quick start](#quick-start) · [Features](#highlights) · [Safety](#safety-by-design) · [Rufus parity](FEATURE_MATRIX.md) · [Roadmap](ROADMAP.md)

<sub>DD &nbsp;•&nbsp; FILESYSTEM-AWARE ISO MODE &nbsp;•&nbsp; WINDOWS CUSTOMIZATION &nbsp;•&nbsp; FULL READ-BACK VERIFICATION</sub>

</div>

![ISOpropyl inspecting a Windows installer image and a synthetic removable drive](data/screenshot.png)

<p align="center"><sub>Rendered with synthetic image and device metadata. No physical drive was written.</sub></p>

ISOpropyl makes bootable USB and SD media without running an entire graphical
application as root. It pairs an approachable Qt interface with explicit write
methods, detailed preflight inspection, narrow privilege boundaries, and
verification after writing.

It is inspired by Rufus, but it is a Linux-native project—not a port and not yet
a feature-for-feature replacement.

> [!CAUTION]
> **ISOpropyl is destructive alpha software.** There is no packaged release yet,
> and physical-media coverage is still limited. Keep backups, leave verification
> enabled, and check the target model, capacity, path, and serial before approving
> a write.

## Highlights

| Capability | What ISOpropyl does |
|---|---|
| **Authenticated raw writing** | Expands every supported raw input into a private anonymous snapshot, shows its SHA-256 and exact target in a typed confirmation, then uses a guarded PolicyKit transaction with mandatory pre-activation read-back and optional full verification. |
| **Filesystem-aware ISO mode** | Rebuilds eligible UEFI media as FAT32 or NTFS with a pinned UEFI:NTFS bridge, then SHA-256 verifies every destination file. |
| **Windows installer options** | Selects WIM/ESD editions, splits oversized WIMs when supported, and can generate a reviewed `autounattend.xml` for setup, privacy, account, and quality-of-life options. |
| **Compressed and virtual images** | Supports common compression formats plus VHD, VHDX, QCOW, and QCOW2 through identity-bound expansion into authenticated anonymous snapshots. |
| **Inspection before erasure** | Examines partition tables, El Torito entries, EFI architecture, Windows metadata, bootloader evidence, and image checksums. |
| **Drive tools** | Backs up drives, restores ordinary filesystems, captures optical discs, securely erases media, and runs bad-block or fake-capacity tests in separate warned workflows. |
| **Linux image download** | Downloads the pinned Ubuntu LTS profile from distribution-owned infrastructure and verifies its signed checksum manifest. |
| **UEFI recovery media** | Builds a multi-architecture UEFI Shell drive from exact upstream payloads after explicit network consent. |

For the exhaustive, evidence-based Rufus comparison, see the
[feature matrix](FEATURE_MATRIX.md).

## Install from source

ISOpropyl currently has no release tarball, Flatpak, AppImage, or distribution
package. For alpha testing, install the host tools listed under
[Requirements](#requirements), then use an isolated Python environment:

```bash
git clone https://github.com/codebooker/isopropyl.git
cd isopropyl
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
isopropyl
```

Raw/DD writes use ISOpropyl's fixed privileged host integration; there is no
fallback to a pathname-based `dd` writer. Install that integration explicitly
from the same trusted checkout before testing raw writes:

```bash
sudo make install-host-helper PREFIX=/usr
```

Re-run that command after changing the helper or its PolicyKit policy. Ordinary
image inspection and non-raw UI exploration do not require it.

For development, replace `python -m pip install .` with
`python -m pip install -e .`. A checkout can also be launched directly:

```bash
./isopropyl-gui
./isopropyl-gui path/to/image.iso
```

> [!IMPORTANT]
> Run ISOpropyl as your normal desktop user. Never launch the GUI with `sudo`.

## Quick start

### Write an image exactly

1. Choose or drop a hybrid ISO, raw image, supported compressed image, virtual
   disk, or VTSI sparse image.
2. Select a removable destination and inspect its model, capacity, path, and
   serial number.
3. Choose the recommended raw, virtual-restore, or VTSI path.
4. Keep **Verify after writing** enabled, allow private snapshot preparation,
   then check the expanded size, SHA-256, target identity, and warnings in the
   final dialog before typing its exact authorization phrase.

### Rebuild an eligible ISO

1. Choose a structurally valid UEFI ISO and select
   **ISO mode — filesystem-aware, UEFI-only**.
2. Open **Plan details…** to review the filesystem, boot limitations,
   transformations, and temporary-space requirement.
3. For recognized Windows media, optionally open **Windows options…** and review
   the generated answer file.
4. Optionally add one bounded, additive ZIP overlay. Existing ISO files cannot
   be replaced.
5. Confirm the exact target and let ISOpropyl verify the finished filesystem.

Useful shortcuts: <kbd>Ctrl</kbd>+<kbd>O</kbd> opens an image,
<kbd>Ctrl</kbd>+<kbd>R</kbd> refreshes targets,
<kbd>Ctrl</kbd>+<kbd>L</kbd> opens the log, and <kbd>Esc</kbd> cancels.

Launch with `isopropyl --portable` to keep non-destructive preferences in an
`isopropyl.ini` beside the launcher or AppImage. Destructive confirmations and
expanded drive visibility are never persisted.

## Supported inputs

| Input | Write path | Notes |
|---|---|---|
| Hybrid `.iso` | DD mode | Preserves the supplied disk layout exactly. |
| Eligible UEFI `.iso` | ISO mode | FAT32 or verified UEFI:NTFS; currently UEFI-only. |
| `.img`, `.raw`, `.usb`, `.wic` | DD mode | Treated as raw disk images. |
| SquashFS `.squashfs`, `.sqfs` | DD mode | Validates and reports the standalone SquashFS 4.0 superblock before raw writing. |
| `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst`, `.Z`, single-file `.zip` | Authenticated raw snapshot | The exact expanded bytes are privately allocated, hashed, and confirmed before writing. |
| VHD, VHDX, QCOW, QCOW2 | Convert to authenticated snapshot | Requires `qemu-img`; backing files, QCOW2 external data files, encryption, and corrupt metadata are rejected. |
| Compressed virtual disk | Decode and convert to snapshot | Exactly one supported wrapper; nested compression is rejected. |
| VTSI v1.0 | Sparse restore | Requires an exact-capacity target with 512-byte logical sectors. |
| Additive `.zip` overlay | ISO mode option | One stored/deflated archive; additions only, no overwrites or links. |

Unsupported or ambiguous formats fail closed. Direct FFU/WIM/ESD apply,
Windows To Go, FreeDOS, and general device-facing BIOS/dual-firmware creation
remain roadmap work.

## Windows customization

For recognized Windows installer media, ISOpropyl can generate a transparent
`autounattend.xml` for:

- Windows 11 setup-check bypasses;
- locale, time zone, privacy, and OOBE preferences;
- BitLocker device-encryption prevention and optional Fast Startup suppression;
- carefully gated local/offline account setup; and
- an opt-in Windows 11 quality-of-life profile covering OneDrive, Outlook,
  Teams, Copilot, recommendations, search, news, Start, Edge, and the classic
  context menu.

These options are best-effort and deliberately conservative. Existing answer
files are never replaced or silently merged. Unsupported editions,
architectures, S-mode media, future releases, and ambiguous layouts disable the
stronger paths. Review the generated file before writing; Windows policy and
package names can change.

## Safety by design

ISOpropyl treats every target write as a destructive transaction:

- the root-backed disk is excluded, and internal disks are never eligible;
- removable USB/SD media are shown by default, while USB HDDs/SSDs require an
  explicit session-only reveal;
- source and target identities are frozen and rechecked around unmounting and
  every destructive boundary;
- selected images are bound to descriptor, inode, size, modification time, and
  change time;
- staging data may not live on the destination drive;
- privileged commands use fixed executable paths and argument arrays—never
  constructed shell text;
- destructive workflows use whole-device locks and bounded process control;
  and
- backup, capture, extraction, and staging outputs are created without
  overwriting existing files.

The raw-device broker goes further. Its separate Syslinux and raw/DD profiles
bind the kernel's disk-generation sequence before typed confirmation,
check that generation again through sysfs and `BLKGETDISKSEQ`, and retain one
exclusive target descriptor through writing, durability, cache invalidation,
and read-back. Generic raw writes first deactivate a 1 MiB front guard plus the
source and physical target tail sectors, verify the inactive bulk data, then
activate the source tail and front guard last. A later failure revalidates the
same disk generation before attempting to zero every activation region again.
Linux block `O_EXCL` and `flock` reduce races but do not exclude an uncooperative
raw writer. The GUI now uses this broker exclusively for plain, compressed,
VTSI, virtual, and compressed-virtual raw inputs, but the backend remains alpha
software pending installed-integration VM race/hot-swap tests and representative
physical-media certification.

See [SECURITY.md](SECURITY.md) for the complete threat model and private
vulnerability-reporting guidance.

## Requirements

Core requirements:

- Linux, Python 3.10 or newer, and PyQt6 6.5 through 6.x;
- `lsblk`, `findmnt`, `udisksctl`, `pkexec`, GNU `dd`, and util-linux `flock`
  (`dd` remains used by bounded backup, optical, erase, and constructed-media
  tools, but not by the GUI raw-image writer);
- 7-Zip (`7z`) for bounded ISO cataloging and extraction; and
- `sfdisk` plus `mkfs.vfat` for FAT32 ISO mode, or `mkfs.ntfs` for large-file
  UEFI:NTFS media.

The raw-device broker additionally requires 64-bit Linux, kernel
`diskseq` sysfs data, the `BLKGETDISKSEQ` ioctl, a filesystem supporting strict
anonymous `O_TMPFILE` snapshots, and enough private workspace for a fully
allocated expanded image. It fails closed when any requirement is absent.

Optional tools unlock additional workflows:

| Capability | Tool |
|---|---|
| Windows WIM/ESD inspection, selection, and splitting | `wimlib-imagex` (`wimtools`) |
| VHD/VHDX/QCOW/QCOW2 input and VHD/VHDX backup | `qemu-img` |
| exFAT/UDF/ext restore | `mkfs.exfat`, `mkudffs` 1.1+, `mkfs.ext2/3/4` |
| Surface and fake-capacity tests | `badblocks`, `f3probe` |
| Additional ISO inspection | `xorriso` |
| Zstandard images | Python `zstandard` or `zstd` |
| Legacy Unix `.Z` images | `gzip` |
| Busy-drive process names | `fuser` (`psmisc`) |

ISO mode also needs private temporary space for the extracted tree. WIM
inspection or splitting can require several additional gigabytes. Missing
optional tools disable the relevant path instead of weakening validation.

## Privileged host integration

The GUI raw/DD path transfers only a fully allocated, re-attested anonymous
snapshot to a fixed root-owned helper. It supports images shorter than the
target, mandatory pre-activation verification, optional complete final
verification, and stale physical-tail sanitation. The same helper also contains
a separate backend-only path for a narrowly supported Syslinux FAT32 image.
These privileged paths are:

- not installed by `pip install` or the ordinary `make install` target;
- required for every GUI raw/DD write, with failure closed when the exact host
  integration is missing or unsafe;
- limited to eligible removable or explicitly revealed external USB media and
  512-byte logical sectors (the Syslinux profile additionally requires exact
  matched 6.03/6.04 payloads); and
- still gated on native-helper hardening, an installed PolicyKit integration
  test, QEMU SeaBIOS/OVMF results, and representative physical media.

Distribution integrators can stage the isolated launcher, helper, and two exact
PolicyKit actions with `make install-host-helper PREFIX=/usr`. Source testers
must invoke it with root privileges as shown above. It does not make alpha media
writes risk-free; test with expendable media and keep verification enabled.

## Troubleshooting

- **No destination is listed:** refresh the list and confirm the medium is
  removable. Leave **Show USB hard drives/SSDs** off unless that is truly the
  intended target.
- **ISO mode is unavailable:** open **Plan details…**. The image may lack a safe
  UEFI fallback loader, require a missing host tool, or contain a layout that
  ISOpropyl refuses to reconstruct.
- **A privilege prompt fails:** check `pkexec`, the desktop PolicyKit agent,
  udisks2, and the required formatter.
- **Secure Boot fails:** signature integrity is not a firmware trust verdict.
  UEFI Shell media currently require Secure Boot to be disabled.
- **A write or inspection fails:** open **View log**, then export diagnostics.
  Sensitive drive and image details are omitted by default.

Report reproducible problems through
[GitHub Issues](https://github.com/codebooker/isopropyl/issues). Never attach
secrets, private installer answer files, or unredacted drive data.

## Project status

ISOpropyl is an ambitious alpha. Automated tests cover the non-destructive logic
and mocked destructive boundaries, but CI does not write physical media. Broad
distribution, desktop, Wayland/X11, firmware, Secure Boot, card-reader, and
hardware testing is still required. BIOS controls remain intentionally hidden.

The honest capability audit lives in [FEATURE_MATRIX.md](FEATURE_MATRIX.md);
planned work and release gates live in [ROADMAP.md](ROADMAP.md).

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q isopropyl tests
desktop-file-validate data/io.github.codebooker.isopropyl.desktop
appstreamcli validate --no-net data/io.github.codebooker.isopropyl.metainfo.xml
```

The suite contains more than 1,000 tests and never writes a real `/dev` node.
Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a destructive path.
Brand assets and usage guidance are in [BRANDING.md](BRANDING.md).

## Credits

ISOpropyl is inspired by the clarity and capability of
[Rufus](https://github.com/pbatard/rufus) and is independently implemented for
Linux. Adapted behavior, optional boot payloads, provenance, and licenses are
recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

ISOpropyl is free software under the
[GNU Affero General Public License v3.0 or later](LICENSE).
