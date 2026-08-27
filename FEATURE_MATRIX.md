# Rufus → ISOpropyl feature audit

This is the live product-parity audit for ISOpropyl. It compares the current
Linux implementation with Rufus master commit
[`2368e49a`](https://github.com/pbatard/rufus/tree/2368e49a82e854d3e702f824648cc723953dbb53)
(2026-08-24, including Rufus 4.15 changes). ISOpropyl is an independent
AGPL-3.0-or-later implementation and contains no Rufus source code.

Status meanings:

- **Done** — implemented with automated non-destructive coverage. Physical-media
  certification may still be required for release confidence.
- **Partial** — a useful subset exists, or the backend is not yet fully exposed.
- **Planned** — feasible Linux work remains.
- **Research** — design, provenance, licensing, or hardware evidence is unresolved.
- **Policy** — an intentional safety/product rule.
- **Inapplicable** — a Windows implementation detail with no Linux counterpart.

## Core media, formats, and utilities

| Rufus capability | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| Raw `.img`/DD writing | **Done** | Selection-to-consent image identity binding includes ctime; one no-follow descriptor is streamed through privileged DD without a pathname reopen. Target identity binding, cancellation, progress, optional byte read-back verification, and power-off ship. A validated image/target logical-sector mismatch—or a selected target with unknown sector size—leaves structured DD available only as an explicit warned choice. Plain MBR uses the conventional assumed 512-byte interpretation. |
| Bootable hybrid ISO writing | **Done** | DD mode preserves the supplied disk layout; non-hybrid optical ISOs receive a warning. |
| Rufus-style ISO extraction mode | **Partial** | Reachable UEFI-only GPT/FAT32 and GPT/NTFS+UEFI:NTFS paths safely stage, format, copy, and SHA-256 read-back verify every file; the raw helper receives a separate full read-back check. BIOS, dual firmware, links, and embedded El Torito images remain. |
| Restore USB as ordinary storage | **Done** | MBR/GPT plus FAT12, FAT16, FAT32, exFAT, NTFS, UDF 2.01, ext2, ext3, or ext4 with filesystem-specific label validation, logical-sector binding, exact safe allocation/block-size controls where supported, and identity rechecks. Full-capacity MBR is filtered by its 32-bit sector fields; GPT becomes the default when reported geometry proves MBR cannot represent the target. Unknown-sector discovery remains provisional until the pre-unmount check. |
| FAT/FAT32 formatting | **Done** | Explicit FAT12/FAT16/FAT32 creation ships with conservative size and geometry envelopes plus exact sector-aligned allocation-unit choices. The FAT32 whole-device cap is 2 TiB, leaving its aligned partition below that boundary. |
| NTFS and exFAT formatting | **Done** | Available in the separate restore workflow through trusted system mkfs tools, with geometry-filtered allocation-unit choices. Automatic is offered only when the modeled exfatprogs/mkntfs default is safe; otherwise the UI requires an explicit valid size. |
| ext2/ext3/ext4 formatting | **Done** | All three are exposed in the separate restore workflow through their exact trusted `mkfs.ext*` tools, with MBR/GPT Linux partition types, 16-byte label validation, and portable 1/2/4 KiB block-size choices. Automatic uses a conservative cross-profile envelope because host `mke2fs.conf` can alter defaults. |
| UDF formatting | **Done** | Single-partition UDF 2.01 restore uses trusted `mkudffs`, bounded label/size/sector validation, and repeated geometry checks. Partitioned UDF is generally not auto-mounted by macOS. |
| ReFS formatting | **Inapplicable** | No mature supported native Linux creation stack. |
| Super-floppy layout | **Research** | Whole-device filesystem compatibility needs an explicit hardware matrix. |
| Removable USB/SD/card readers | **Partial** | USB/MMC removable devices are recognized; broad reader/SDXC certification is not claimed. |
| USB HDD/SSD targets | **Done** | Hidden by default, explicitly revealable, second warning; internal and root disks remain forbidden. |
| Compressed images | **Done** | Streaming gzip, bzip2, xz/lzma, zstd, legacy `.Z`, and single-file ZIP/ZIP64 through one no-follow, descriptor-bound source. Inspection has cooperative reselection/close cancellation, a five-minute limit checked between in-process decoder reads and while waiting for external decoder output, a 64 TiB expanded-size ceiling, bounded prefix/tail capture, and a pre-parse ZIP catalog bound; destructive writer expansion is target-bounded. Decoder-library working memory and the duration of one in-process decoder call are not claimed to be globally bounded. Legal tables outside the bounded metadata capture are reported as incomplete and never auto-recommended rather than mislabeled malformed. |
| Raw `.usb`/`.wic` aliases | **Done** | Both extensions are explicit raw-disk aliases in inspection and the image chooser, with fixtures covering case-insensitive admission; structured apply formats remain rejected. |
| VHD/VHDX/QCOW/QCOW2 input | **Done** | Identity-bound `qemu-img` inspection/conversion; backing files, encryption, corruption metadata, and unsafe output are rejected. |
| Compressed virtual containers | **Planned** | Explicitly rejected until decode→inspect→convert can be safely chained. |
| FFU and VTSI input | **Planned** | Explicitly rejected rather than raw-written; requires real format/platform validation. |
| Direct WIM/ESD input | **Planned** | Explicitly rejected; belongs to Windows To Go/apply, never raw DD. |
| Windows installer ISO | **Partial** | UEFI/FAT32 and UEFI:NTFS construction, WIM split, WIM/ESD edition/index selection, and answer-file injection ship; BIOS/dual construction and hardware certification remain. |
| Save drive as raw image | **Done** | Exact-length privileged read to a new, atomically published user file with cancellation and free-space checks. |
| Save drive as VHD/VHDX/FFU | **Partial** | VHD and VHDX ship: a private exact raw capture is converted by identity-bound `qemu-img`, exact virtual size and safe metadata are checked, guest-visible contents are compared, and the result is atomically published without overwrite. FFU remains planned. |
| Save optical disc as ISO | **Done** | Read-only sector capture with source identity, size/free-space checks, cancellation, and atomic publication. |
| Save USB/VHD as UDF ISO | **Planned** | Separate authoring workflow not implemented. |
| Linux persistence | **Partial** | A hardened executor transforms a recognized UEFI GRUB line only in private staging, creates an exact up-front GPT/FAT32 + ext4 `writable` layout on 512- or 4096-byte logical sectors, formats both filesystems before copying, revalidates complete source/target/partition identities around every destructive boundary, and read-back verifies data files. Guarded GUI plumbing exists for candidate remasters whose catalog exposes a recognized GRUB config path; private staging performs the final eligible-line check before any target change. Current official Ubuntu 20.04.6/22.04.5/24.04.3 desktop catalogs do not expose that path (24.04 also changed squashfs layout), so they correctly receive no persistence control. Embedded-config support, broader profiles, and physical certification remain. |
| MD5/SHA-1/SHA-256/SHA-512 | **Done** | One-pass calculation plus strict pasted-provider comparison. |
| Bad-block passes | **Done** | Separate destructive `badblocks` workflow with 1–4 patterns, typed confirmation, progress, and identity rechecks. |
| Fake-capacity detection | **Done** | Separate destructive `f3probe` workflow; availability depends on the system F3 package. |
| Full zero | **Done** | Exact full-device zero pass with cancellation and revalidation. |
| Rufus fast-zero | **Partial** | Boundary zero clears first/last 16 MiB; it is not Rufus’s whole-device scan that skips already-zero blocks. |
| FreeDOS boot media | **Planned** | Prefer lawful FreeDOS payloads before considering MS-DOS. |
| MS-DOS boot media | **Research** | Microsoft binary acquisition/licensing constraints apply. |
| Microsoft ISO downloader | **Planned** | Must use official metadata without executing remote Fido-style scripts. |
| UEFI Shell downloader | **Planned** | Official releases, architecture selection, checksum/signature validation. |
| Curated Linux downloader | **Planned** | Distribution-owned URLs, signed metadata, resumability, and explicit consent. |

## Boot, filesystem, and trust analysis

| Rufus behavior | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| MBR marker/boot-code analysis | **Done** | Under the conventional 512-byte-LBA interpretation, validates primary entries, overlaps, bounds, boot flags, mandatory protective fields, hybrid rules, and bounded EBR chains; classifies empty, Windows, GRUB, Syslinux, and unrecognized boot code. |
| GPT detection | **Done** | Validates 512/4096-byte-sector primary and backup headers, exact revision/reserved fields, reciprocal locations, header and array CRC32, matching arrays, GUIDs, entry size/attributes, 16 KiB reservations, usable ranges, entry bounds/overlaps, and exact protective/hybrid MBR mirroring. |
| ISO 9660 and volume label | **Done** | Primary volume descriptor and label inspection. |
| Joliet/Rock Ridge/UDF contents | **Partial** | 7-Zip catalogs/extracts the tested ISO/UDF media safely; ISO mode rejects links rather than materializing them, and expert toggles are absent. |
| El Torito catalogs | **Done** | Strict bounded validation entry, sections, platforms, emulation, boot flags, LBAs, extents, overlap, and identity checks. Embedded filesystems are not parsed. |
| BIOS/UEFI path detection | **Done** | Combines member paths with El Torito evidence. Construction remains UEFI-only. |
| UEFI fallback architectures | **Done** | x86, x64, ARM, ARM64, RISC-V64, and LoongArch64 fallback names. ISO execution requires a recognized non-empty fallback loader. |
| GRUB/GRUB2 identity | **Partial** | Bounded payload inspection reports exact downstream build when evidence permits; no construction/download caller. |
| Syslinux/Isolinux identity | **Partial** | Exact release/custom-build conflicts detected; no C32 compatibility/executor integration. |
| Windows Boot Manager | **Partial** | Detects installer paths and UEFI payloads; WIM/ESD metadata and edition/index selection are exposed. Offline BCD construction and cryptographic trust remain. |
| UEFI PE architecture/subsystem | **Done** | Strict structural parser for selected EFI payloads. |
| Authenticode signature reporting | **Partial** | Reports certificate-table structure as `present-unverified`; no cryptographic chain or signer trust. |
| SBAT policy | **Partial** | Parses bounded SBAT sections and can evaluate a supplied generation policy; no authenticated live policy feed. |
| DBX/SVN/CA 2023 revocation | **Planned** | Requires authenticated, versioned policy data and Windows-specific loader handling. |
| Runtime UEFI media validation | **Planned** | No generation/update of image-specific firmware-time checksum manifests yet. |
| Image/staging stored on target | **Done** | Refused before destructive work, then rechecked in constructed execution. |
| Conflicting-process diagnostics | **Planned** | Current errors report unmount failure but do not identify the owning process. |
| Distro-specific DD-only rules | **Planned** | Needs a versioned compatibility catalog and fixtures. |
| Automatic GRUB/Syslinux downloads | **Planned** | Verified-download infrastructure exists, but there is no user-facing GRUB/Syslinux caller or release catalog yet. UEFI:NTFS uses the same underlying safety model but is a separate payload family. |

## Windows-specific construction and customization

| Rufus Windows feature | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| Detect WIM edition/build/architecture/index | **Partial** | Strict bounded `wimlib-imagex info --xml` inspection is integrated and identity-bound, but the GUI still requires exactly one `install.wim`/`install.esd`; Rufus can select among multiple source images. |
| Split `install.wim` over FAT32 limit | **Done** | Integrated private `wimlib-imagex split`, validates complete numbered parts, atomically commits staging. |
| UEFI-only install media | **Partial** | Executable GPT/FAT32 and GPT/NTFS+UEFI:NTFS paths with per-file verification; physical firmware and Secure Boot testing remain. |
| BIOS-only and dual BIOS+UEFI | **Planned** | Exact Windows/GRUB/Syslinux boot code and layouts required. |
| UEFI:NTFS / dual partition | **Partial** | Exact 512-byte-sector GPT/MBR geometry, NTFS data partition, pinned 1 MiB upstream FAT12 helper image, x64/x86/ARM64 payload validation, conditional CA2011 warning, raw and file read-back verification, identity rechecks, and cancellation. ARM32 and RISC-V64 require an explicit unsigned-payload consent with Secure Boot disabled; LoongArch64 remains incomplete. Physical certification remains. |
| Windows 11 RAM/TPM/Secure Boot bypass | **Done** | Transparent opt-in answer-file registry commands; applied only through ISO mode. |
| Hide online Microsoft-account screen | **Partial** | OOBE settings ship; current Windows versions may require more version-aware mechanisms. |
| Local administrator | **Partial** | Validated username and no collected secret; the account starts blank and a single sequential first-logon command mandates replacement and applies the chosen expiration policy. The GUI warns that this is best-effort and unsupported in S mode. |
| Locale, language, keyboard, time zone | **Done** | Explicit validated Linux-side fields, not host-Windows settings replication. |
| Privacy-question/Express settings | **Done** | Opt-in OOBE privacy settings. |
| Prevent automatic BitLocker encryption | **Done** | Transparent opt-in unattend/registry behavior. |
| Existing answer file protection | **Done** | Root `autounattend.xml` and `sources/$OEM$/$$/Panther/unattend.xml` are detected case-insensitively; customization refuses to combine with or replace either. |
| Windows To Go | **Planned** | WIM apply, ESP/MSR/NTFS layout, offline BCD, SAN policy, and driver/hardware caveats. |
| Internal disks offline for Windows To Go | **Planned** | Belongs to future offline SAN/BCD configuration. |
| Windows CA 2023 / `SkuSiPolicy.p7b` | **Planned** | Security-sensitive, versioned validation required. |
| S Mode-aware customization | **Partial** | UI warns first-logon commands do not run in S Mode; no complete alternative path. |
| Quality-of-life/debloating options | **Research** | Subjective and fast-changing; separate install necessities from preferences. |
| Silent install to first disk | **Research** | Future expert-only profile with severe target-PC warnings, never default. |
| In-place upgrade bypass wrapper | **Research** | Not USB creation; high maintenance and security burden. |

## Main UI, settings, and workflow

| Rufus UI/workflow | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| Device model, capacity, path, serial/WWN | **Done** | Deterministic size/model/path sorting and explicit identity display. |
| Bounded background device refresh | **Done** | `lsblk` runs off the Qt thread with a 15-second timeout, a 2 MiB combined-output ceiling, normalized failures, generation tokens that discard stale results, and write controls disabled while target state is refreshing. |
| Ignore selected USB devices | **Done** | Persistent stable-ID denylist and reset controls. |
| Show USB hard drives/SSDs | **Done** | Visible explicit opt-in; root/internal disks remain excluded. |
| Partition scheme selector | **Partial** | MBR/GPT available for restore; current ISO profile fixes GPT. |
| Target firmware selector | **Partial** | Planner models automatic/BIOS/UEFI/both; GUI executes explicit UEFI-only. |
| Filesystem selector | **Partial** | Restore offers FAT12/FAT16/FAT32/exFAT/NTFS/UDF/ext2/ext3/ext4; ISO mode automatically selects FAT32 or NTFS+UEFI:NTFS from image constraints rather than exposing an unsafe arbitrary choice. |
| Cluster-size selector | **Partial** | Restore exposes exact geometry-filtered allocation-unit choices for FAT12/16/32, exFAT, and NTFS plus portable ext2/3/4 block sizes. UDF deliberately follows the logical sector, and ISO mode retains profile-selected automatic sizing. Physical-media compatibility testing remains. |
| Volume label | **Done** | Filesystem-specific validation in restore; ISO mode uses `ISOPROPYL`. |
| Quick format | **Done** | Restore and ISO construction use quick mkfs; full zero is separate. |
| Persistence-size slider | **Partial** | The capacity-bounded aligned control and transaction wiring ship, but it appears only for a candidate remastered Ubuntu profile with an exposed recognized UEFI GRUB config path; final private staging validates its contents. Current official Ubuntu desktop media correctly remain ineligible pending embedded-config support. |
| ISO mode versus DD mode | **Done** | The main screen exposes both executable choices, recommends from inspected image evidence, names compatibility limits, resets on a new image, re-plans against the selected target at dispatch, and never silently falls back. ISO mode forces verification. |
| Image checksums | **Done** | Dedicated dialog with copy and strict compare. |
| Save-drive action | **Done** | Separate read-only raw/VHD/VHDX workflow with conservative free-space checks and no-overwrite publication. |
| Progress, speed, ETA, cancellation | **Done** | 64-bit counters, stage-aware rolling rate/ETA, cross-thread cancellation. |
| Recoverable I/O retries | **Planned** | Never retry identity changes or ambiguous device failures. |
| Activity log | **Done** | Rotating local log with copy and diagnostics export. |
| Privacy-conscious diagnostics | **Done** | Sensitive identifiers, mount paths, member lists, and log require explicit opt-in. |
| Dark/light appearance | **Done** | Persistent palettes. System/high-contrast following remains polish. |
| Settings persistence/reset | **Done** | Appearance, display-unit family, and denylist persist; risky visibility/confirmations reset; full reset ships. |
| Keyboard shortcuts | **Done** | Open, refresh, log, cancel. |
| Command-line image argument | **Done** | Installed entry point and working-tree launcher accept one path. |
| Drag-and-drop | **Done** | One local regular image while idle. |
| Headless CLI writing | **Planned** | Must preserve all GUI identity and confirmation invariants. |
| Update checks | **Research** | Prefer package-manager channels; portable builds need signed opt-in metadata. |
| Portable settings | **Planned** | Needed for AppImage-style distribution. |
| ZIP overlay | **Planned** | Must reuse no-traversal/collision validation. |
| Preserve extracted timestamps | **Planned** | Not guaranteed by the current per-member safe extractor. |
| Decimal/binary unit preference | **Done** | Settings switches dynamic capacities, progress, rates, estimates, confirmations, and device labels between SI MB/GB/TB and IEC MiB/GiB/TiB. |
| Old-BIOS fixes | **Research** | Requires precise Linux equivalents and real hardware fixtures. |

## Advanced modes and platform decisions

| Rufus advanced behavior | Status | ISOpropyl position |
|---|---:|---|
| Blank Syslinux/GRUB/Grub4DOS/ReactOS/UEFI:NTFS media | **Planned** | After verified payload catalog and construction profiles. |
| Rufus MBR / “press any key” toggles | **Planned** | Belongs to Windows BIOS construction. |
| Cycle/reset selected USB port | **Research** | Only if UDisks/sysfs semantics are safe and portable. |
| Delete downloaded boot files | **Done** | Settings inventories only exact catalog-known cache paths and deletes explicitly confirmed, filesystem-safe regular files through no-follow directory descriptors. Unknown, linked, or changed entries remain untouched; corrupt or incomplete copies can be safely cleared. |
| Dual BIOS+UEFI Windows mode | **Planned** | Normal future profile, not a hidden cheat key. |
| List internal/non-removable disks | **Policy** | Internal disks remain rejected; eSATA/Thunderbolt may need narrowly tested rules. |
| List loop/NBD/virtual targets | **Policy** | Kept out of the physical target picker. |
| Toggle SHA-512 | **Done** | All four hashes are calculated together. |
| Force DD / ignore boot marker | **Partial** | DD remains available after explicit warning; unsafe size overflow is never allowed. |
| Toggle Joliet/Rock Ridge | **Planned** | Expert extracted-mode control only if safety is preserved. |
| Force large FAT32 | **Policy** | ISOpropyl will not bypass FAT32’s real per-file limit. |
| NTFS compression | **Research** | Low Linux-user value and boot compatibility risk. |
| Dump optical media | **Done** | Normal visible tool. |
| ESP/basic-data partition type toggle | **Research** | Current constructed GPT type needs firmware evidence; not a casual toggle. |
| Zero/fast zero | **Partial** | Full zero and boundary metadata zero ship; see semantic difference above. |
| Erase application settings | **Done** | Visible settings action. |
| Preserve logs | **Done** | Rotating logs persist in XDG state. |
| Disable size safety checks | **Policy** | Never supported. |
| Windows VDS/drive-letter/registry/autorun/indexing switches | **Inapplicable** | Linux-native device, mount, settings, and package behavior replaces them. |

## Security and distribution

| Measure | Status | ISOpropyl position |
|---|---:|---|
| Hide system/internal disks | **Done** | Root backing device excluded; whole-device safety model enforced. |
| Revalidate device identity | **Done** | Path, size, model, serial/WWN, transport, and major:minor around destructive boundaries. |
| Bind partition-node identity | **Done** | Multi-partition workflows bind every direct child path to kernel parent and major:minor identity, verify the block node with `lstat`, and repeat exact geometry and identity checks before each filesystem creation. |
| Exclusive target ownership | **Partial** | Every destructive child command now fails fast behind a whole-device cooperative `flock`; `sfdisk` uses its native nonblocking lock. This coordinates lock-aware tools but remains advisory and per-command. A privileged transaction broker/private namespace is still required for stronger end-to-end ownership, and no unsafe bypass will be exposed. |
| Fixed privileged argv/no shell | **Done** | Absolute trusted tools and bounded child processes. |
| Verified boot components | **Partial** | A release-bundled catalog pins the UEFI:NTFS source commit, exact size, and SHA-256; explicit consent, identity-safe cache binding, in-memory privileged transfer, and full read-back are integrated. GRUB/Syslinux catalogs and signed ISOpropyl release metadata remain. |
| No unsigned remote scripts | **Policy** | ISOpropyl will never execute a downloaded installer/downloader script. |
| Opt-in network use | **Policy** | UEFI:NTFS acquisition requires explicit confirmation; no remote code or script is executed. Future downloads require the same explicit action and pinned provenance. |
| Reproducible builds | **Partial** | Standard package metadata and CI exist; locked inputs and reproduction attestations remain. |
| Signed releases | **Planned** | Sigstore/minisign and package-native signatures. |
| Desktop/AppStream metadata | **Done** | Validated application, icon, and metainfo files. |
| Flatpak/AppImage/native packages | **Planned** | Block-device/polkit integration must be designed per sandbox/package. |
| Localization/accessibility | **Planned** | Qt translations, screen-reader QA, high-contrast/system theme. |
| Telemetry | **Policy** | None. Diagnostics are local and sensitive fields default off. |
| License | **Done** | AGPL-3.0-or-later with per-file SPDX identifiers. |

## Priority order

1. Add privileged exclusive target ownership across every destructive transaction.
2. Hardware-certify current UEFI/FAT32 and UEFI:NTFS modes and failure cleanup.
3. Implement BIOS and dual-firmware construction with exact payload handling.
4. Hardware-certify the narrow immutable Casper layout and add only fixture-backed profiles.
5. Add Windows To Go through wimlib and offline boot configuration.
6. Add cryptographic Secure Boot trust and authenticated revocation data.
7. Complete FFU/VTSI/direct WIM/ESD and image-output formats.
8. Add signed opt-in downloaders, FreeDOS, UEFI Shell, and audited GRUB/Syslinux
   payload catalogs.
9. Finish localization, conflict diagnostics, signed reproducible packaging, and
   physical certification of safe expert format controls.

## Primary Rufus sources reviewed

- [README feature list](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/README.md#features)
- [Current ChangeLog](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/ChangeLog.txt)
- [FAQ advanced features](https://github.com/pbatard/rufus/wiki/FAQ#list-of-rufus-advanced-features-and-cheat-modes)
- [Usage Notes](https://github.com/pbatard/rufus/wiki/Usage-Notes)
- [Security](https://github.com/pbatard/rufus/wiki/Security)
- [ISO/DD selection](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/rufus.c#L1550-L1590)
- [GRUB/Syslinux dependency workflow](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/rufus.c#L1782-L2000)
- [Persistence mutation](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/iso.c#L494-L553)
- [Ubuntu 20.04.6 desktop ISO file list](https://releases.ubuntu.com/20.04/ubuntu-20.04.6-desktop-amd64.list)
- [Ubuntu 22.04.5 desktop ISO file list](https://releases.ubuntu.com/22.04/ubuntu-22.04.5-desktop-amd64.list)
- [Ubuntu 24.04.3 desktop ISO file list](https://releases.ubuntu.com/24.04/ubuntu-24.04.3-desktop-amd64.list)
- [UEFI:NTFS layout](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/drive.c#L2284-L2512)
- [Windows customization](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L140-L540)
- [Windows To Go](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L930-L1115)
- [Fido downloader](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/net.c#L779-L924)
- [DBX updater](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/net.c#L444-L520)
