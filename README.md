<div align="center">

![ISOpropyl — Bootable media, without the guesswork](https://raw.githubusercontent.com/codebooker/isopropyl/dbde952ddde89e7b4e0b08533c0e2c5014fc6696/data/isopropyl-hero.svg)

[![Tests](https://github.com/codebooker/isopropyl/actions/workflows/test.yml/badge.svg)](https://github.com/codebooker/isopropyl/actions/workflows/test.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-F6922E.svg)](https://github.com/codebooker/isopropyl/blob/main/LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-252B35.svg?logo=linux&logoColor=white)](#requirements)
[![Status: alpha](https://img.shields.io/badge/status-alpha-5B6574.svg)](#project-status)

### Powerful enough for Windows installers. Careful enough for `/dev`.

**A Linux-native image writer with guarded device selection, transparent write
plans, Windows customization, and end-to-end verification.**

[Build & install](#build-a-debianubuntu-alpha-package) · [Quick start](#quick-start) · [Capabilities](#capabilities) · [Safety](#safety-by-design) · [Rufus parity](https://github.com/codebooker/isopropyl/blob/main/FEATURE_MATRIX.md) · [Roadmap](https://github.com/codebooker/isopropyl/blob/main/ROADMAP.md)

<sub>DD &nbsp;•&nbsp; FILESYSTEM-AWARE ISO MODE &nbsp;•&nbsp; WINDOWS CUSTOMIZATION &nbsp;•&nbsp; VERIFIED WRITES</sub>

</div>

![ISOpropyl inspecting a Windows installer image and a synthetic removable drive](https://raw.githubusercontent.com/codebooker/isopropyl/7156e64dc2b585a4fd90bef901db76b7b84889a0/data/screenshot.png)

<p align="center"><sub>Rendered with synthetic image and device metadata. No physical drive was written.</sub></p>

ISOpropyl gives Linux users a polished way to create bootable USB and SD media
without running an entire graphical application as root. It pairs an
approachable Qt interface with explicit write methods, detailed media
inspection, narrow privilege boundaries, and read-back verification.

It is inspired by Rufus, but it is a Linux-native project—not a port and not yet
a feature-for-feature replacement.

> [!CAUTION]
> **ISOpropyl is destructive alpha software.** Native test packages are not yet
> signed releases, and physical-media coverage is still limited. Keep backups,
> leave verification enabled, and check the target model, capacity, path, and
> serial before approving a write.

## Why ISOpropyl

| Inspect first | Keep privilege narrow | Verify the result |
|---|---|---|
| See image structure, boot modes, architectures, checksums, Windows editions, and compatibility warnings before erasing anything. | The Qt app and CLI stay unprivileged. Raw/DD writes and fast zero use fixed project PolicyKit actions; other tools elevate bounded system argument arrays without shell text. | Raw writes use mandatory pre-activation read-back. Full post-write verification is on by default and filesystem-aware writes hash every copied file. |

No unattended confirmation, no internal-disk targets, and no shell-constructed
root commands. Destructive operations name the exact device, revalidate its
identity, and require an explicit confirmation.

## Capabilities

| Capability | What ISOpropyl does |
|---|---|
| **Authenticated raw writing** | Expands every supported raw input into a private anonymous snapshot, shows its SHA-256 and exact target in a typed confirmation, then uses a guarded PolicyKit transaction with mandatory pre-activation read-back and optional full verification. |
| **Terminal raw writing** | Offers the same authenticated raw workflow through `isopropyl-cli`: exact `/dev/...` selection, no unattended mode, full verification by default, signal-safe cancellation, and a second typed warning for fixed USB disks or risky image profiles. |
| **Filesystem-aware ISO mode** | Rebuilds eligible UEFI media as FAT32 or NTFS with a pinned UEFI:NTFS bridge, then SHA-256 verifies every destination file. |
| **Syslinux BIOS developer preview** | For exact supported Syslinux 6.03/6.04 images, an explicit environment-gated preview can add a legacy-BIOS path while retaining the source UEFI files. It uses hash-pinned payloads, a target-bound typed confirmation, MBR-last activation, and mandatory full-device SHA-256 read-back. The normal GUI keeps it hidden pending a native hardened helper and physical-media certification. |
| **Windows installer options** | Selects WIM/ESD editions, splits oversized WIMs when supported, can generate a reviewed `autounattend.xml`, and offers a narrowly profiled Windows 2023-generation installer-boot update for exact supported Microsoft media. |
| **Compressed and virtual images** | Supports common compression formats plus VHD, VHDX, QCOW, and QCOW2 through identity-bound expansion into authenticated anonymous snapshots. |
| **Inspection before erasure** | Examines partition tables, El Torito entries, EFI architecture, Windows metadata, bootloader evidence, and image checksums. |
| **Drive tools** | Backs up drives, restores ordinary filesystems with Quick format, captures optical discs, performs logical zeroing, and runs bad-block or fake-capacity tests. A non-GUI Verified zero + format prototype remains unreleased pending installed VM and physical-media certification; it is not Rufus/Windows slow formatting. |
| **Linux image download** | Downloads the pinned Ubuntu LTS profile from distribution-owned infrastructure and verifies its signed checksum manifest. |
| **Windows image download** | Acquires exact current Windows 11 25H2 v2 English x64 or ARM64 consumer media directly from Microsoft, checks the selected profile's live published hash row, resumes privately, and verifies the complete SHA-256 before use. |
| **FreeDOS image download** | Downloads the official FreeDOS 1.4 LiteUSB or FullUSB archive at runtime, corroborates the project-pinned archive SHA-256 against FreeDOS's live verification page, validates the exact ZIP catalog and reviewed inner image hash, then loads the image into the guarded raw writer. |
| **UEFI recovery media** | Builds a multi-architecture UEFI Shell drive from exact upstream payloads after explicit network consent. |

For the exhaustive, evidence-based Rufus comparison, see the
[feature matrix](https://github.com/codebooker/isopropyl/blob/main/FEATURE_MATRIX.md).

## Build a Debian/Ubuntu alpha package

The repository contains an offline, reproducible `.deb` builder for 64-bit x86
(`amd64`) and ARM (`arm64`). Its dependencies have been checked against **Debian
13 and Ubuntu 24.04/26.04 LTS**. It packages the GUI, terminal writer, manual
pages, desktop integration, and exact PolicyKit helper together, so no separate
privileged install step is needed.

```bash
git clone https://github.com/codebooker/isopropyl.git
cd isopropyl
/usr/bin/python3 -I packaging/debian/build_deb.py --output-dir dist
sudo apt install ./dist/isopropyl_0.1.0-1_amd64.deb
```

On ARM64, the generated filename ends in `_arm64.deb`. The builder uses only
the checked-out source tree and the system's trusted `dpkg` tools; it performs
no network access, refuses unsupported architectures, and will not overwrite an
existing package. CI currently builds and exposes the `amd64` artifact on
successful test runs under **Actions → Artifacts**; build ARM64 locally on an
`arm64` host. Installed VM certification remains pending for both architectures.

> [!NOTE]
> Debian and Ubuntu do not currently package every exact dependency in
> ISOpropyl's pinned Authenticode analysis backend. The native `.deb` therefore
> reports that analysis as unavailable instead of relaxing pins or substituting
> a different trust implementation. Image hashing, DBX advice, Secure Boot
> structure inspection, and write verification remain available.

## Install from source

For a development environment or a distribution without the native test
package, install the host tools listed under [Requirements](#requirements), then
use an isolated Python environment:

```bash
git clone https://github.com/codebooker/isopropyl.git
cd isopropyl
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
isopropyl
```

That installation provides both the Qt application (`isopropyl`) and the
non-Qt raw writer (`isopropyl-cli`). Both remain unprivileged coordinators; the
fixed host helper below owns the narrow root transaction.

Raw/DD writes and verified fast zero use ISOpropyl's fixed privileged host
integration; neither has a pathname-based `dd` fallback. Install that
integration explicitly from the same trusted checkout before testing either
workflow:

```bash
sudo make install-host-helper PREFIX=/usr
```

Re-run that command after changing the helper or its PolicyKit policy. Ordinary
image inspection and non-raw UI exploration do not require it.

The narrow Syslinux BIOS + retained UEFI workflow is intentionally a developer
preview, not a normal alpha feature. After installing the exact host helper, an
experienced tester with expendable media can opt in for one process:

```bash
ISOPROPYL_EXPERIMENTAL_SYSLINUX=1 ./isopropyl-gui
```

Only exact cataloged Syslinux/Isolinux 6.03 or 6.04-pre1 media, a native
single-partition UEFI/FAT32 plan, and kernel-removable USB/SD targets with
512-byte logical sectors and no more than 128 GiB capacity are eligible. The
workflow needs temporary space for the extracted tree plus a fully allocated
image equal to the target capacity. Do not treat the successful SeaBIOS
certificate as physical-device or firmware certification; a native hardened
replacement for the provisional Python helper and installed
VM/OVMF/physical-media coverage remain release gates.

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

### Write from a terminal

List the protected target inventory, then name one exact whole-disk path:

```bash
isopropyl-cli list
isopropyl-cli write path/to/image.iso --target /dev/sdX
```

The CLI performs the same identity-bound inspection, anonymous expansion,
PolicyKit transaction, activation ordering, and read-back as the GUI. It refuses
non-interactive input, target indexes, globs, and automatic confirmation. Full
post-activation SHA-256 verification is enabled by default. The explicit
`--no-final-verification` switch retains mandatory pre-activation read-back but
requires an extra typed warning. Fixed USB HDDs/SSDs require both
`--include-usb-hard-drives` and that same extra warning; internal disks remain
ineligible. `SIGINT` and `SIGTERM` request authenticated cancellation and wait for
the workflow to finish its required cleanup or post-commit verification.

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

### Download a pinned Windows 11 ISO

1. Open **Download official image… → Download Windows ISO…**, then select
   the x64 or ARM64 profile.
2. Click **Open Microsoft download page**. On that matching page, select the
   Windows 11 multi-edition ISO and English, then copy the generated **Download**
   link into ISOpropyl's masked field.
3. Choose the exact official filename and review the release, language,
   architecture, size, SHA-256, destination, Microsoft terms, and license notice.
4. Confirm networking. ISOpropyl rechecks the selected profile's current
   Microsoft hash row,
   validates the 24-hour link without logging it, downloads or safely resumes,
   hashes the whole file, and requires inspection to find exactly the selected
   installer architecture before loading it.

The direct-resolver checkbox is an optional fallback and may be rejected by
Microsoft. It downloads one bounded Microsoft JavaScript response as inert text
but never evaluates or executes it. Fido and PowerShell are neither downloaded
nor run, and ISO contents remain data only. ISOpropyl is not affiliated with
Microsoft, and downloading installation media does not grant a Windows license.
For ARM64 media, [Microsoft notes](https://learn.microsoft.com/en-us/windows/arm/iso)
that some devices need manufacturer-provided drivers for the installation media
to boot successfully; check the target device's support guidance before writing
the drive.

### Download an official FreeDOS 1.4 USB image

1. Open **Download official image… → Download FreeDOS USB image…**, then
   select **LiteUSB** (32 MiB image) or **FullUSB** (1 GiB image) and an exact
   destination filename.
2. Review the edition, fixed image size, x86 firmware limits, archive and image
   SHA-256 values, upstream licensing/non-affiliation notice, and destination.
3. Confirm networking. ISOpropyl downloads the archive directly from FreeDOS,
   requires its exact current SHA-256 row on FreeDOS's verification page, checks
   the complete three-member ZIP catalog, and extracts only the cataloged disk
   image into private staging.
4. After an independent full inner-image hash and structural check, ISOpropyl
   loads the image for the same guarded DD/raw workflow used by local images.

FreeDOS does not provide a detached signature for these archives. The bundled
project pin—recorded from the official verification page—is therefore the trust
anchor; the live exact row is corroboration, not a publisher-signature check.
No FreeDOS media is bundled with ISOpropyl. These fixed MBR images boot only on
Intel-compatible x86 systems using BIOS or UEFI Legacy/CSM mode: they do not
provide native UEFI or Secure Boot support and do not support ARM or RISC-V.
Secure Boot must be disabled, and many newer systems no longer offer CSM.
Writing does not enlarge the image's partition or filesystem. The guarded raw
writer sanitizes the physical final sector, but middle bytes beyond the 32 MiB
LiteUSB or 1 GiB FullUSB image are not erased and may retain previous data. Use
**Drive tools… → Erase drive with zeros… → Full zero pass** first if complete
logical erasure is required.

### Restore a drive as ordinary storage

Open **Drive tools… → Restore drive…** and choose the filesystem, partition
table, allocation or block size, and volume label. The released GUI performs
Quick filesystem creation: it replaces the layout and filesystem metadata
without overwriting every previous data byte.

Verified zero + format is not a released user workflow. Its non-GUI prototype
combines a complete verified logical zero pass with later filesystem creation.
A descriptor-bound privileged transaction and isolated PolicyKit endpoint now
exist, but the desktop workflow and installed VM hot-swap/failure certification
are not complete. It is not Rufus/Windows slow format, Secure Erase,
sanitization, or a bad-block test. Normal users who need logical erasure should
run **Erase drive with zeros**, wait for verified completion, and then run
**Restore drive**.

### Logically zero a drive

1. Open **Drive tools…**, choose **Erase drive with zeros…**, and select **Fast
   zero — scan, skip zero blocks, zero the rest, verify all**.
2. Review the exact target identity and type the displayed authorization phrase.
3. ISOpropyl scans every byte, skips only chunks that are already entirely zero,
   overwrites every other chunk, flushes device caches, and reads the whole drive
   back before reporting success.

Fast zero is a logical overwrite, not ATA/NVMe Secure Erase, sanitization, or a
guarantee against flash-controller remapping. Cancellation after writing begins
durably clears and verifies the first and last 16 MiB when target identity remains
provable; otherwise ISOpropyl reports the target state as unknown.

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
| Downloaded FreeDOS 1.4 LiteUSB/FullUSB `.img` | Authenticated raw snapshot | Exact official x86 BIOS/Legacy/CSM image; fixed 32 MiB or 1 GiB layout is not expanded to fill the target. |
| Additive `.zip` overlay | ISO mode option | One stored/deflated archive; additions only, no overwrites or links. |

Unsupported or ambiguous formats fail closed. Direct FFU/WIM/ESD device apply,
executable Windows To Go (an internal fail-closed layout/capacity preview, a
device-free anonymous-NTFS-image WIM backend certificate, and a non-authorizing
typed Windows BCD differential-evidence contract, experimental Windows collector,
atomic Linux importer, and read-only hive verifier now exist), and general
device-facing BIOS/dual-firmware construction from arbitrary payloads remain
roadmap work. The certification backend explicitly rejects block devices and is
not a claim about hostile same-UID processes, Windows boot, or physical media.
The BCD parser/importer tests currently use synthetic evidence only. The collector
has static and independent GPT/CRC tests but has not run under PowerShell, Hyper-V,
or Windows on this development host; none of these components can create, modify,
publish as trusted, or authorize use of a boot hive.

## Windows customization

For recognized Windows installer media, ISOpropyl can generate a transparent
`autounattend.xml` for:

- Windows 11 setup-check bypasses;
- locale, time zone, privacy, and OOBE preferences;
- BitLocker device-encryption prevention and optional Fast Startup suppression;
- carefully gated local/offline account setup;
- an opt-in Windows 11 quality-of-life profile covering OneDrive, Outlook,
  Teams, Copilot, recommendations, search, news, Start, Edge, and the classic
  context menu;
- for a selected Windows 11 25H2 or 26H1 edition, an opt-in first-logon step
  that copies the installed system's own `SkuSiPolicy.p7b` revocation policy to
  its EFI System Partition.

These options are best-effort and deliberately conservative. Existing answer
files are never replaced or silently merged. Unsupported editions,
architectures, S-mode media, unrecognized releases, and ambiguous layouts
disable the stronger paths. Review the generated file before writing; Windows
policy and package names can change. The revocation-policy option can stop older
Windows, installer, and recovery media from booting, so it requires a separate
recovery and BitLocker-risk acknowledgment—including confirmation that the image
already contains the latest applicable updates—and is never enabled by default.

A separate default-off option can update installer boot files from
`sources/boot.wim` for the exact reviewed Windows 11 25H2 v2 English x64 and
ARM64 Microsoft ISOs. It is limited to direct FAT32 construction, binds the
complete ISO to Microsoft's published SHA-256, extracts only the reviewed
`EFI_EX` and `Fonts_EX` paths, verifies PE architecture and EFI subsystem, and
hashes every replacement before and after committing it to the private staging
tree. It requires an explicit acknowledgment that the target firmware already
trusts Windows UEFI CA 2023; older 2011-only firmware may not boot it. A present
PE certificate table is structural evidence—not certificate-chain,
revocation, signing-time, or target-firmware validation—and the root
`bootmgr_EX.efi` mapping is not described as CA-2023-signed.

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

The raw-device broker goes further. Its separate Syslinux, raw/DD, and fast-zero
profiles bind the kernel's disk-generation sequence before typed confirmation,
check that generation again through sysfs and `BLKGETDISKSEQ`, and retain one
exclusive target descriptor through writing, durability, cache invalidation,
and read-back. Generic raw writes first deactivate a 1 MiB front guard plus the
source and physical target tail sectors, verify the inactive bulk data, then
activate the source tail and front guard last. A later failure revalidates the
same disk generation before attempting to zero every activation region again.
Linux block `O_EXCL` and `flock` reduce races but do not exclude an uncooperative
raw writer. The GUI and CLI use this broker exclusively for plain, compressed,
VTSI, virtual, and compressed-virtual raw inputs, but the backend remains alpha
software pending installed-integration VM race/hot-swap tests and representative
physical-media certification.

See [SECURITY.md](https://github.com/codebooker/isopropyl/blob/main/SECURITY.md)
for the complete threat model and private vulnerability-reporting guidance.

## Requirements

Core requirements:

- Linux, Python 3.10 or newer, and PyQt6 6.5 through 6.x;
- `lsblk`, `findmnt`, `partprobe`, `udevadm`, `udisksctl`, `pkexec`, GNU `dd`,
  and util-linux `flock` (`dd` remains used by bounded backup, optical, erase,
  and constructed-media tools, but not by the GUI or CLI raw-image writer);
- 7-Zip (`7z`) for bounded ISO cataloging and extraction; and
- `sfdisk` plus `mkfs.vfat` for FAT32 ISO mode, or `mkfs.ntfs` for large-file
  UEFI:NTFS media.

The raw-device broker and verified fast zero require 64-bit Linux, kernel
`diskseq` sysfs data, and the `BLKGETDISKSEQ` ioctl. Raw-image writing also
requires a filesystem supporting strict anonymous `O_TMPFILE` snapshots and
enough private workspace for a fully allocated expanded image. Each workflow
fails closed when one of its requirements is absent.

Optional tools unlock additional workflows:

| Capability | Tool |
|---|---|
| Windows WIM/ESD inspection, selection, splitting, and 2023-generation boot-file extraction | `wimlib-imagex` (`wimtools`) |
| VHD/VHDX/QCOW/QCOW2 input and VHD/VHDX backup | `qemu-img` |
| exFAT/UDF/ext restore | `mkfs.exfat`, `mkudffs` 1.1+, `mkfs.ext2/3/4` |
| Surface and fake-capacity tests | `badblocks`, `f3probe` |
| Additional ISO inspection | `xorriso` |
| Authenticated Ubuntu downloads | `gpgv` and the system CA certificate store |
| Zstandard images | Python `zstandard` or `zstd` |
| Legacy Unix `.Z` images | `gzip` |
| Busy-drive process names | `fuser` (`psmisc`) |
| Read-only import/validation of captured Windows BCD hives | Python `hivex` (`python3-hivex`) |

ISO mode also needs private temporary space for the extracted tree. WIM
inspection or splitting can require several additional gigabytes. Missing
optional tools disable the relevant path instead of weakening validation.

## Privileged host integration

The GUI and CLI raw/DD paths transfer only a fully allocated, re-attested
anonymous snapshot to a fixed root-owned helper. They support images shorter
than the target, mandatory pre-activation verification, optional complete final
verification, and stale physical-tail sanitation. The same provisional helper
also contains a separate, default-off developer preview for a narrowly
supported Syslinux FAT32 image.
These privileged paths are:

- not installed by `pip install` or the ordinary `make install` target;
- required for every GUI or CLI raw/DD write, with failure closed when the exact
  host integration is missing or unsafe;
- limited to eligible removable or explicitly revealed external USB media and
  512-byte logical sectors (the Syslinux profile additionally requires exact
  matched 6.03/6.04 payloads); and
- now covered by a device-free QEMU/SeaBIOS boot certificate, while still gated
  on native-helper hardening, an installed PolicyKit integration test, OVMF,
  hot-swap/failure coverage, and representative physical media.

Distribution integrators can stage the isolated launcher, helper, and three
exact PolicyKit actions with `make install-host-helper PREFIX=/usr`. Source testers
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
- **A FreeDOS drive does not boot:** FreeDOS 1.4 LiteUSB and FullUSB are x86
  BIOS images. Disable Secure Boot and enable Legacy/CSM mode if the firmware
  provides it; native UEFI-only, ARM, and RISC-V systems are unsupported.
- **A write or inspection fails:** open **View log**, then export diagnostics.
  Sensitive drive and image details are omitted by default.

Report reproducible problems through
[GitHub Issues](https://github.com/codebooker/isopropyl/issues). Never attach
secrets, private installer answer files, or unredacted drive data.

## Project status

ISOpropyl is an ambitious alpha. Automated tests cover the non-destructive logic
and mocked destructive boundaries, but CI does not write physical media. Broad
distribution, desktop, Wayland/X11, firmware, Secure Boot, card-reader, and
hardware testing is still required. BIOS controls remain hidden in ordinary
launches; the narrowly scoped Syslinux developer preview requires an explicit
per-process environment opt-in and expendable media.

The honest capability audit lives in [FEATURE_MATRIX.md](https://github.com/codebooker/isopropyl/blob/main/FEATURE_MATRIX.md);
planned work and release gates live in [ROADMAP.md](https://github.com/codebooker/isopropyl/blob/main/ROADMAP.md).

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q isopropyl tests
desktop-file-validate data/io.github.codebooker.isopropyl.desktop
appstreamcli validate --no-net data/io.github.codebooker.isopropyl.metainfo.xml
```

The suite contains more than 1,500 tests and never writes a real `/dev` node.
From a source checkout, maintainers with an already extracted, catalog-matching
FreeDOS image can reproduce the device-free SeaBIOS smoke certificate explicitly:

```bash
python3 tools/certify_freedos_boot.py --run /path/to/FD14LITE.img
```

The harness rechecks the exact filename, size, and SHA-256 before and after a
bounded QEMU TCG boot; it passes only a sealed, read-only in-memory snapshot,
uses QEMU's seccomp sandbox and snapshot mode, rejects root or set-ID execution,
disables networking and KVM, and never opens a host block device. This is
emulator evidence, not physical firmware or USB-media certification.

Maintainers can reproduce the Syslinux 6.03 ISO-mode certificate from the exact
official source archive as well:

```bash
python3 tools/certify_syslinux_boot.py --run /path/to/syslinux-6.03.tar.xz
```

The run requires Linux memfd sealing, `qemu-system-x86_64`, `xorriso`, and 7-Zip
(`7zz` or `7z`). Preparation may contact only the catalog-pinned HTTPS sources
for missing Syslinux bundle data; populate the verified cache first for a fully
offline run. The QEMU boot phase itself has networking disabled.

The harness independently pins the official archive and four source members,
requires ISOpropyl's prepared bundles to byte-match the official build outputs,
exercises the production inspection/staging/private-FAT32/patch pipeline, and
boots only the resulting sealed read-only memfd under QEMU TCG and SeaBIOS. It
records the selected QEMU executable's version and SHA-256; the certificate
therefore depends on trusting that recorded emulator binary. It certifies the
BIOS bootstrap and configuration prompt—not UEFI, an operating system, the
privileged device transaction, or physical media. The real integration test is
explicitly opt-in rather than part of the device-free default suite. A locally
reproduced observation is retained as
[`certifications/syslinux-6.03-seabios-2026-08-28.json`](https://github.com/codebooker/isopropyl/blob/main/certifications/syslinux-6.03-seabios-2026-08-28.json).

Maintainers with `wimlib-imagex`, `mkntfs`, and the ntfs-3g inspection tools can
also reproduce the unprivileged, device-free WIM apply certificate:

```bash
python3 tools/certify_wim_apply_backend.py --run
```

The harness drops active capability sets, sets Linux `no_new_privs`, rejects
every root UID and any set-ID/file-capability-bearing tool, locks down its
descriptor owner, creates only an anonymous 128 MiB regular NTFS image, and
verifies the exact applied file and clean volume metadata. It never accepts or
discovers a block device.

Maintainers can also compare four Windows-captured BCD hives with their exact
canonical oracle fixtures after installing `python3-hivex`:

```bash
python3 tools/validate_windows_bcd_capture.py \
  --baseline baseline.json baseline.BCD \
  --disk-guid disk-guid.json disk-guid.BCD \
  --esp-guid esp-guid.json esp-guid.BCD \
  --windows-guid windows-guid.json windows-guid.BCD
```

The Debian package also installs the isolated
`isopropyl-validate-windows-bcd-capture` command with the same arguments.

The command pins eight distinct regular-file descriptors, validates the entire
one-GUID-at-a-time cohort before parsing any hive, copies each BCD into a sealed
anonymous snapshot, and compares every typed registry value and store digest.
It never edits a hive or device, and success is evidence matching—not Windows
provenance, BCD-generation authority, boot certification, or permission to run
the Windows To Go write path. No authentic Windows capture is bundled yet. Hive
bytes and returned collections are bounded, but the optional native parser runs
in-process without a wall-clock deadline or crash isolation; use this maintainer
tool only on disposable copies and never as a privileged service boundary.

An experimental maintainer collector now builds the four raw captures inside
disposable fixed VHD files on Windows. Run it only in a throwaway Windows 11 VM
from an elevated PowerShell 7.4 `-NoProfile` session with Hyper-V enabled, an
absolute ISO path, and a new output name beneath a pre-existing local NTFS
directory whose protected DACL grants full control only to Administrators and
SYSTEM:

```powershell
pwsh.exe -NoProfile -File .\tools\capture_windows_bcd_oracle.ps1 `
  -IsoPath C:\Images\Windows11.iso -ImageIndex 1 `
  -OutputDirectory C:\ISOpropylCaptureRoot\capture-1
```

The conservative collector needs roughly 128 GiB of free working space, creates
one 64 GiB fixed VHD plus one sequential full clone, accepts no physical-disk
identifier, and emits exactly seven evidence files. Its PowerShell/C# and
Hyper-V behavior is not yet runtime-certified. Copy that seven-file directory
to Linux, create an owner-only destination parent (`chmod 700`), and import it:

```bash
mkdir -m 700 imported-captures
isopropyl-import-windows-bcd-capture windows-capture imported-captures/capture-1
```

The importer pins seven distinct singly linked regular files, independently
parses all four hives through sealed snapshots, derives the canonical JSON
cohort, rehashes every source and copy, and publishes eleven files with
no-replace atomic rename. It rejects group/other-writable destination parents.
Hostile processes running as the same Linux effective UID are outside its
namespace threat model. Import success remains explicitly non-authorizing and
does not establish authentic Windows provenance or bootability.

Read [CONTRIBUTING.md](https://github.com/codebooker/isopropyl/blob/main/CONTRIBUTING.md) before changing a destructive path.
Brand assets and usage guidance are in [BRANDING.md](https://github.com/codebooker/isopropyl/blob/main/BRANDING.md).

## Credits

ISOpropyl is inspired by the clarity and capability of
[Rufus](https://github.com/pbatard/rufus) and is independently implemented for
Linux. Adapted behavior, optional boot payloads, provenance, and licenses are
recorded in [THIRD_PARTY_NOTICES.md](https://github.com/codebooker/isopropyl/blob/main/THIRD_PARTY_NOTICES.md).

## License

ISOpropyl is free software under the
[GNU Affero General Public License v3.0 or later](https://github.com/codebooker/isopropyl/blob/main/LICENSE).
