<div align="center">

![ISOpropyl — Bootable media, made simple](data/isopropyl-hero.svg)

[![Tests](https://github.com/codebooker/isopropyl/actions/workflows/test.yml/badge.svg)](https://github.com/codebooker/isopropyl/actions/workflows/test.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-F6922E.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-252B35.svg?logo=linux&logoColor=white)](#requirements)
[![Status: alpha](https://img.shields.io/badge/status-alpha-5B6574.svg)](#project-status)

**A capable, safety-first USB image writer for Linux.**

[Install](#installation) · [Quick start](#quick-start) · [Features](#features) · [Safety](#safety-model) · [Roadmap](ROADMAP.md) · [Contribute](CONTRIBUTING.md)

<sub>RAW DD &nbsp;•&nbsp; UEFI ISO MODE &nbsp;•&nbsp; WINDOWS CUSTOMIZATION &nbsp;•&nbsp; READ-BACK VERIFICATION</sub>

</div>

![ISOpropyl inspecting a Windows installer image and a synthetic removable drive](data/screenshot.png)

<p align="center"><sub>Deterministically rendered example with synthetic image and device metadata; no physical drive was written.</sub></p>

ISOpropyl creates bootable USB and SD media without running an entire graphical
application as root. It combines exact DD writing with a filesystem-aware UEFI
ISO workflow, inspection before erasure, best-effort Windows installer
customization, checksums, backups, formatting, media tests, and full read-back
verification when the default verification option remains enabled.

> [!CAUTION]
> **ISOpropyl is destructive alpha software.** There is no packaged release yet,
> and block-device workflows currently have extensive mocked coverage but limited
> physical-media certification. ISO mode is UEFI-only, Secure Boot acceptance is
> not established, and unusual firmware or installer layouts may not boot. Keep
> backups and verify the target model, capacity, path, and serial before writing.

## Why ISOpropyl?

| | What it means |
|---|---|
| **Choose the write method** | DD and ISO mode are explicit. ISOpropyl recommends a compatible path and explains why, but never silently changes your choice. |
| **Inspect before erasing** | Partition tables, boot entries, Windows metadata, EFI payloads, and image identity are examined automatically; opt-in checksums are available before writing. |
| **Keep privilege narrow** | The GUI stays in the desktop session as your user. `pkexec` is requested only for the block-device step. |
| **Prove the result** | With verification enabled, DD mode compares every written image byte; ISO mode SHA-256 verifies every copied file from the finished USB. |
| **Fail closed** | Unsafe transformations and automatic recommendations stop on ambiguous evidence. Explicit byte-for-byte DD may remain available, with warnings, when an exact copy is still meaningful. |

## Installation

ISOpropyl currently has no release tarball, Flatpak, AppImage, or distribution
package. Install Python 3, `python3-venv`, `python3-pip`, and the required host
tools from your distribution first. Debian/Ubuntu package names commonly include
`p7zip-full`, `udisks2`, `util-linux`, `fdisk`, `dosfstools`, `ntfs-3g`,
`wimtools`, and `pkexec`; the desktop session also needs a working PolicyKit
authentication agent. Names vary across distributions. See
[Requirements](#requirements) for which tool unlocks each capability.

For alpha testing, run ISOpropyl from a source checkout in an isolated Python
environment:

```bash
git clone https://github.com/codebooker/isopropyl.git
cd isopropyl
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
isopropyl
```

To work on the source, replace `python -m pip install .` with
`python -m pip install -e .`. After the environment is prepared, the checkout
launchers are also available:

```bash
./isopropyl-gui
./isopropyl-gui path/to/image.iso
```

> [!IMPORTANT]
> Run ISOpropyl as your normal desktop user. Do not launch the GUI with `sudo`.

## Quick start

### Raw, compressed, virtual, or VTSI write

1. Choose or drop a hybrid/raw-write-compatible ISO, raw image, compressed image,
   supported virtual disk, or VTSI sparse image, and follow the write-method
   recommendation.
2. Select a removable target and review its model, capacity, path, and serial.
3. Choose the matching path: **VTSI restore — expand sparse disk image** for
   `.vtsi`, **Virtual disk restore — decode/convert to raw disk** for virtual
   containers, or **DD mode — exact byte-for-byte copy** for raw-compatible
   images.
4. Keep verification enabled, review the final erase warning, and confirm.

### Filesystem-aware ISO write

1. Choose an eligible, structurally validated UEFI ISO and a removable target.
2. Choose **ISO mode — filesystem-aware, UEFI-only** and open **Plan details…**.
3. For recognized Windows media, optionally configure **Windows options…** and
   inspect the generated answer file.
4. Optionally choose **Add ZIP…** to include new files from one bounded archive.
   Review its expanded size and SHA-256; it cannot replace existing ISO content.
5. Review the filesystem, transformations, firmware limitations, temporary-space
   requirement, and exact target identity before confirming.

Keyboard shortcuts: <kbd>Ctrl</kbd>+<kbd>O</kbd> opens an image,
<kbd>Ctrl</kbd>+<kbd>R</kbd> refreshes targets,
<kbd>Ctrl</kbd>+<kbd>L</kbd> opens the log, and <kbd>Esc</kbd> cancels.

For a self-contained copy, launch `isopropyl --portable`. Preferences are kept
in a singly linked `isopropyl.ini` beside the launcher (or beside the outer
AppImage), and that file acts as the marker on later launches. ISOpropyl also
honors an existing AppImage `<AppImage>.config` directory. Destructive
confirmations and expanded drive visibility are never persisted.

## Features

### Write and verify

- **DD mode** streams hybrid ISOs and raw disk images with cancellation and
  byte-for-byte read-back verification.
- **ISO mode** safely extracts eligible UEFI media, selects FAT32 or NTFS,
  handles a sole conventional oversized Windows WIM when possible, and verifies
  every destination file. NTFS media use a release-and-hash-pinned UEFI:NTFS
  bridge after explicit download consent. A bundled, versioned,
  higher-confidence compatibility policy excludes reconstruction for exact
  Manjaro, Proxmox, and Pop!_OS member
  layouts known to need native image handling; these rules never use host filenames,
  volume labels, overlays, or network lookups.
- **Boot-time corruption checking** is an explicit, default-off option for the
  first native UEFI/FAT32 profile. ISOpropyl obtains the exact hash-pinned
  `uefi-md5sum` v1.2 wrapper set, preserves every recognized fallback loader,
  and generates a deterministic manifest from the final private tree before
  the normal full SHA-256 destination read-back. The unsigned MD5 manifest is
  useful for later accidental-damage detection, not authenticity: it is stored
  beside the files it covers and firmware validation is bypassable/fail-open.
  Casper/Ubuntu and UEFI:NTFS media remain excluded pending boot certification.
- **Additive ZIP overlays** can add ordinary files and directories from one
  bounded stored/deflated archive in ISO mode. Identity, SHA-256, CRC, sizes, and
  the final private tree are checked; collisions, traversal, links, special
  files, encryption, fallback `EFI/BOOT/BOOT*.EFI` loaders, and canonical Windows
  install WIM/ESD/SWM payloads are rejected. The digest binds the selected bytes
  but does not authenticate their author.
- Compressed `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst`, legacy `.Z`, and single-file
  ZIP raw images stream without an expanded copy. VHD, VHDX, QCOW, and QCOW2
  inputs—including one supported compression wrapper—use private,
  identity-checked decode and `qemu-img` staging steps. Nested compression,
  encrypted containers, and backing files are rejected.
- **VTSI v1.0 restore** validates a Ventoy sparse-image footer and segment table,
  then streams the complete expanded disk—including verified zero-filled gaps—to
  an exact-capacity drive with 512-byte logical sectors. Full read-back
  verification is mandatory; VTSI metadata checksums do not authenticate its
  payload or author, and physical Ventoy boot certification is still needed.
- Image selection is bound to device, inode, size, modification time, and change
  time so a replacement or mutation cannot quietly become the written image.

### Inspect and customize

- Download the curated Ubuntu 24.04.4 LTS Desktop amd64 ISO on demand. ISOpropyl
  authenticates Ubuntu's signed checksum manifest with the pinned CD Image key,
  verifies the complete ISO, supports safe resume, and atomically publishes
  without overwriting an existing file. No downloaded byte is executed.
- Validate MBR, extended partitions, protective/hybrid MBR, and reciprocal GPT
  metadata at supported sector sizes; malformed or incomplete evidence is shown
  instead of treated as bootable.
- Parse El Torito BIOS/UEFI entries and inspect EFI PE architecture, certificate
  framing, and SBAT. A sealed, resource-limited worker can report embedded
  Authenticode **integrity only**; it does not establish publisher, Microsoft,
  firmware, timestamp, or Secure Boot trust. Separately, an offline advisor
  compares eligible signed **and unsigned** EFI images against all 673
  architecture-specific SHA-256 Authenticode hashes in Microsoft's pinned
  `secureboot_objects` DBX v1.6.5 snapshot. Entries without Microsoft's optional
  flag and entries marked optional are distinguished without inventing additional
  policy semantics. Exact matches receive a default-Cancel warning in DD and ISO
  mode; ISO mode also rechecks the final descriptor-bound staged tree after
  overlays, persistence changes, and generated boot wrappers, plus the selected
  boot-reachable bridge and NTFS driver inside its pinned UEFI:NTFS helper,
  before any target writer runs. Newly introduced matches require a second
  default-Cancel decision.
  Incomplete or ambiguous final analysis also requires explicit default-Cancel
  consent, and “not listed” is explicitly not presented as safe, trusted,
  compatible, or bootable.
- Calculate MD5, SHA-1, SHA-256, and SHA-512 in one cancellable pass and compare a
  pasted checksum without guessing its algorithm.
- Inspect recognized Windows WIM/ESD sources and editions. ISO mode can add a
  transparent `autounattend.xml` for setup-check bypasses, privacy/OOBE choices,
  locale and time-zone settings, BitLocker-device-encryption prevention,
  opt-in Fast Startup suppression, and carefully gated local/offline account
  paths.

Windows customization is best-effort and intentionally conservative. Existing
answer files are never silently combined or replaced; unsupported Home, S-mode,
future-release, architecture, or ambiguous layouts disable the stronger account
paths. The exact gates and residual limitations are documented in the
[feature matrix](FEATURE_MATRIX.md) and [security model](SECURITY.md).

### Maintain removable media

- Save a complete removable drive as an atomic raw, VHD, or VHDX backup, or
  capture readable optical media to ISO without modifying the disc.
- Restore ordinary storage as FAT12/16/32, exFAT, NTFS, UDF 2.01, or ext2/3/4
  using geometry-checked MBR or GPT layouts.
- Run destructive bad-block or F3 fake-capacity tests in separate, heavily
  warned workflows; zero a whole device or only its boundary metadata regions.
- Create a verified GPT/FAT32 UEFI Shell recovery drive for five architectures
  from exact upstream files after explicit networking consent.
- Keep preferences beside a portable launcher or AppImage with `--portable`;
  destructive confirmations and expanded drive visibility remain session-only.
- Export privacy-conscious diagnostics, keep a rotating local activity log, and
  choose decimal or binary display units.

For the implementation-level capability audit and Rufus comparison, see
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).

## Supported inputs

| Input | Path | Important limitation |
|---|---|---|
| Hybrid `.iso` | DD mode | Preserves the image's existing layout exactly. |
| Eligible UEFI `.iso` | ISO mode | UEFI-only; FAT32 or verified UEFI:NTFS depending on file sizes and architecture. |
| Optional `.zip` overlay | Additive ISO mode | One bounded stored/deflated archive; additions only, no overwrites. |
| `.img`, `.raw`, `.usb`, `.wic` | DD mode | Treated as raw disk images, not structured installers. |
| Compressed raw image | Streaming DD | ZIP must contain exactly one regular image. |
| VHD/VHDX/QCOW/QCOW2 | Convert, then DD | Requires `qemu-img`; encrypted containers and backing files are rejected. |
| Compressed VHD/VHDX/QCOW/QCOW2 | Decode, convert, then DD | Exactly one supported wrapper; decoded containers are capped at 64 GiB and staged privately. |
| `.vtsi` v1.0 | Sparse restore | Target capacity must exactly match the expanded disk and report 512-byte logical sectors. |

Unsupported formats fail closed. FFU, Windows To Go, dual BIOS+UEFI
construction, broader persistence profiles, localization, and release packaging
remain on the [roadmap](ROADMAP.md).

## Safety model

Destructive disk software should be predictable. ISOpropyl:

- excludes the disk backing the running root filesystem;
- shows removable USB/SD media by default and hides USB HDDs/SSDs unless revealed;
- accepts only validated whole-device paths beneath `/dev`;
- freezes model, capacity, serial/WWN, transport, major:minor, and logical-sector
  identity, then rechecks it around unmounting and immediately before writes;
- refuses images or staging trees stored on the destination drive;
- uses fixed privileged argument arrays, never constructed shell text;
- coordinates destructive operations with fail-fast whole-device locks;
- time-bounds helper processes and uses bounded terminate/kill/reap cancellation;
- will not overwrite backup, capture, extraction, or staging outputs; and
- keeps erase and destructive media tests outside the normal write button with
  separate confirmations.

Read the complete invariants and vulnerability-reporting policy in
[SECURITY.md](SECURITY.md).

## Requirements

Core application requirements:

- Linux, Python 3.10 or newer, and PyQt6 6.5 through 6.x;
- `lsblk`, `findmnt`, `udisksctl`, `pkexec`, GNU `dd`, and util-linux `flock`;
- 7-Zip (`7z`) for ISO cataloging and safe extraction; and
- `sfdisk` plus `mkfs.vfat` for FAT32 ISO mode, or `mkfs.ntfs` for large-file
  UEFI:NTFS media.

Optional tools unlock additional workflows:

| Capability | Tool |
|---|---|
| Windows WIM/ESD inspection, selection, and splitting | `wimlib-imagex` (`wimtools`) |
| VHD/VHDX/QCOW/QCOW2 input and VHD/VHDX backup | `qemu-img` |
| exFAT/UDF/ext restore | `mkfs.exfat`, `mkudffs` 1.1+, `mkfs.ext2/3/4` |
| Surface and fake-capacity tests | `badblocks`, `f3probe` |
| Additional ISO inspection | `xorriso` |
| Zstandard-compressed images | Python `zstandard` or `zstd` |
| Legacy Unix `.Z` images | `gzip` |
| Busy-drive process names | `fuser` (`psmisc`) |

ISO mode also needs temporary space for its private extracted tree, including
the overlay's complete expanded size when one is selected. WIM edition
inspection or splitting can require several additional gigabytes. Missing
optional tools disable the relevant path rather than weakening its checks.

## Troubleshooting and support

- **No destination is listed:** refresh the device list, confirm the medium is
  removable, and leave **Show USB hard drives/SSDs** off unless that is truly the
  intended target. The root-backed disk is never eligible.
- **ISO mode is unavailable:** open **Plan details…**. The image may lack a safe
  UEFI fallback loader, require an unavailable filesystem/helper, or contain a
  layout ISOpropyl will not transform. For a recognized distro layout, ISOpropyl
  preserves DD as a separate explicit choice only when the ordinary image and
  target safety checks allow it; a compatibility match never declares DD safe.
- **A privilege prompt fails:** check that `pkexec`, a PolicyKit agent, udisks2,
  and the required formatter are installed in the desktop session.
- **Secure Boot fails:** Authenticode integrity is not a firmware trust verdict.
  Review the payload report; unsigned UEFI Shell media explicitly requires
  Secure Boot to be disabled.
- **A write or inspection fails:** open **View log**, then choose
  **Export diagnostics…**. Serial numbers, WWNs, mount paths, volume labels,
  image member names, member-scoped issues, and command lines are omitted by
  default.

Report reproducible problems through [GitHub Issues](https://github.com/codebooker/isopropyl/issues).
Never attach secrets, private installer answer files, or unredacted drive data.

## Project status

ISOpropyl is an ambitious alpha, not yet a feature-for-feature Rufus replacement.
CI currently exercises the non-destructive suite on an Ubuntu x86-64 runner with
Python 3.12; device-facing tests mock block devices and privileged commands and
never write a real drive. Broad distro, desktop, Wayland/X11, firmware, Secure
Boot, card-reader, and physical-media testing is still required.

The detailed, evidence-based status lives in [FEATURE_MATRIX.md](FEATURE_MATRIX.md)
and [ROADMAP.md](ROADMAP.md).

## Development and contributing

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q isopropyl tests
desktop-file-validate data/io.github.codebooker.isopropyl.desktop
appstreamcli validate --no-net data/io.github.codebooker.isopropyl.metainfo.xml
```

The suite contains more than 1,000 tests. See [CONTRIBUTING.md](CONTRIBUTING.md)
before changing any destructive path. Security vulnerabilities should follow the
private-reporting guidance in [SECURITY.md](SECURITY.md), not a public issue.

## Credits and third-party software

ISOpropyl is inspired by the clarity and capability of
[Rufus](https://github.com/pbatard/rufus), but its application code is an
independent Linux-native implementation. Optional UEFI:NTFS and UEFI Shell files
remain under their upstream licenses and are acquired only after explicit user
consent. Dependency licenses and provenance are recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The symbol, repository banner, palette, and naming guidance live in
[BRANDING.md](BRANDING.md).

## License

Copyright is held by ISOpropyl contributors. ISOpropyl is free software under
the [GNU Affero General Public License v3.0 or later](LICENSE).
