# Rufus → ISOpropyl feature audit

This is the live product-parity audit for ISOpropyl. It compares the current
Linux implementation with Rufus master commit
[`2368e49a`](https://github.com/pbatard/rufus/tree/2368e49a82e854d3e702f824648cc723953dbb53)
(2026-08-24, including Rufus 4.15 changes). ISOpropyl is a Linux-native
AGPL-3.0-or-later implementation. Adapted data or behavior with upstream
copyright significance is identified in [third-party notices](THIRD_PARTY_NOTICES.md).

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
| Rufus-style ISO extraction mode | **Partial** | Reachable UEFI-only GPT/FAT32 and GPT/NTFS+UEFI:NTFS paths safely stage, format, copy, and SHA-256 read-back verify every file; the raw helper receives a separate full read-back check. One bootable EFI/no-emulation El Torito image is also reconstructed when it contains a strict direct FAT12/16/32 filesystem or an active first FAT partition in an otherwise empty MBR wrapper. BIOS/dual-firmware construction, links, non-FAT and hard-disk-emulation images, multiple eligible embedded images, and physical certification remain. |
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
| Compressed virtual containers | **Done** | One `.gz`, `.gzip`, `.bz2`, `.bzip2`, `.xz`, `.lzma`, `.zst`, `.zstd`, legacy `.Z`/`.z`, or single-file ZIP wrapper around VHD/VHDX/QCOW/QCOW2 is decoded once into a bounded private stage, format-checked through an inherited descriptor, converted to raw, and rebound to the confirmed outer identity, virtual format, and guest size. Nested compression and unsupported apply formats remain rejected. |
| FFU input | **Planned** | Explicitly rejected rather than raw-written; requires a reviewed Linux apply backend plus real format/platform validation. |
| VTSI v1.0 input | **Partial** | Strictly parses the bound Ventoy sparse-image footer and segment table, synthesizes every zero gap into a deterministic full-disk stream, and uses the existing cancellation and full read-back path. Selection is limited to an exact-capacity target that freshly reports 512-byte logical sectors. Physical Ventoy boot certification remains. |
| Direct WIM/ESD input | **Planned** | Explicitly rejected; belongs to Windows To Go/apply, never raw DD. |
| Windows installer ISO | **Partial** | UEFI/FAT32 and UEFI:NTFS construction, WIM split, WIM/ESD edition/index selection, and answer-file injection ship; BIOS/dual construction and hardware certification remain. |
| Save drive as raw image | **Done** | Exact-length privileged read to a new, atomically published user file with cancellation and free-space checks. |
| Save drive as VHD/VHDX/FFU | **Partial** | VHD and VHDX ship: a private exact raw capture is converted by identity-bound `qemu-img`, exact virtual size and safe metadata are checked, guest-visible contents are compared, and the result is atomically published without overwrite. FFU remains planned. |
| Save optical disc as ISO | **Done** | Read-only sector capture with source identity, size/free-space checks, cancellation, and atomic publication. |
| Save USB/VHD as UDF ISO | **Planned** | Separate authoring workflow not implemented. |
| Linux persistence | **Partial** | A hardened executor transforms a recognized UEFI GRUB line only in private staging, creates an exact up-front GPT/FAT32 + ext4 `writable` layout on 512- or 4096-byte logical sectors, formats both filesystems before copying, revalidates complete source/target/partition identities around every destructive boundary, and read-back verifies data files. Guarded GUI plumbing exists for candidate remasters whose catalog exposes a recognized GRUB config path; private staging performs the final eligible-line check before any target change. Current official Ubuntu 20.04.6/22.04.5/24.04.3 desktop catalogs do not expose that path (24.04 also changed squashfs layout), so they correctly receive no persistence control. Embedded-config support, broader profiles, and physical certification remain. |
| MD5/SHA-1/SHA-256/SHA-512 | **Done** | One cancellable pass over a no-follow descriptor bound to the exact inspected device/inode/size/mtime/ctime identity, with mutation and pathname-replacement refusal plus strict pasted-provider comparison. |
| Bad-block passes | **Done** | Separate destructive `badblocks` workflow with 1–4 patterns, typed confirmation, progress, and identity rechecks. |
| Fake-capacity detection | **Done** | Separate destructive `f3probe` workflow; availability depends on the system F3 package. |
| Full zero | **Done** | Exact full-device zero pass with cancellation and revalidation. |
| Rufus fast-zero | **Partial** | Boundary zero clears first/last 16 MiB; it is not Rufus’s whole-device scan that skips already-zero blocks. |
| FreeDOS boot media | **Planned** | Prefer lawful FreeDOS payloads before considering MS-DOS. |
| MS-DOS boot media | **Research** | Microsoft binary acquisition/licensing constraints apply. |
| Microsoft ISO downloader | **Planned** | Must use official metadata without executing remote Fido-style scripts. |
| UEFI Shell downloader | **Partial** | An explicit-consent GUI acquires the exact upstream 26H1 AA64, IA32, LoongArch64, RISC-V64, and X64 release files as one no-partial-return bundle, rechecks independently pinned size/SHA-256 and PE architecture/subsystem, stages canonical fallback paths, and writes target-bound GPT/FAT32 media after typed confirmation with complete file read-back. The executables are unsigned and require Secure Boot disabled. Physical firmware certification remains. |
| Curated Linux downloader | **Done** | The explicit **Download Linux…** flow currently pins Ubuntu 24.04.4 LTS Desktop amd64 from its distribution-owned HTTPS release path. It independently pins and authenticates the exact `SHA256SUMS`/signature pair with Ubuntu's CD Image signing key, requires the one signed filename/hash, validates exact response/range lengths, resumes only through a private bound partial, performs a final full descriptor hash, and atomically publishes without overwrite. The catalog is intentionally narrow and downloaded bytes are never executed. |

## Boot, filesystem, and trust analysis

| Rufus behavior | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| MBR marker/boot-code analysis | **Done** | Under the conventional 512-byte-LBA interpretation, validates primary entries, overlaps, bounds, boot flags, mandatory protective fields, hybrid rules, and bounded EBR chains; classifies empty, Windows, GRUB, Syslinux, and unrecognized boot code. |
| GPT detection | **Done** | Validates 512/4096-byte-sector primary and backup headers, exact revision/reserved fields, reciprocal locations, header and array CRC32, matching arrays, GUIDs, entry size/attributes, 16 KiB reservations, usable ranges, entry bounds/overlaps, and exact protective/hybrid MBR mirroring. |
| ISO 9660 and volume label | **Done** | Primary volume descriptor and label inspection. |
| Joliet/Rock Ridge/UDF contents | **Partial** | A trusted system 7-Zip catalogs tested ISO/UDF media through the bound image descriptor with a 16 MiB/65,536-member ceiling, cancellation, a 20-second subprocess deadline, and bounded terminate/kill/reap; ISO mode separately rejects links rather than materializing them, and expert toggles are absent. |
| El Torito catalogs and embedded EFI FAT | **Partial** | Strict bounded validation covers the validation entry, sections, platforms, emulation, boot flags, LBAs, extents, overlap, logical-volume bounds, and source identity. One bootable EFI/no-emulation direct FAT12/16/32 image—or an active first FAT partition in an otherwise empty MBR wrapper—is parsed with FAT-copy consistency, VFAT, chain, cross-link, collision, checksum, and resource bounds. Sector counts 0/1 use validated filesystem geometry. Every embedded file is SHA-256-bound, materialized with no-follow/exclusive descriptors, merged without replacement, and exact-tree revalidated. Multiple eligible images, non-FAT layouts, and hard-disk emulation remain unsupported. |
| BIOS/UEFI path detection | **Done** | Combines member paths with El Torito evidence. Device-facing construction remains UEFI-only; the Syslinux regular-file harness described below is deliberately unreachable from the GUI. |
| UEFI fallback architectures | **Done** | x86, x64, ARM, ARM64, IA64, RISC-V64, LoongArch64, and EBC fallback names. ISO execution requires a recognized non-empty fallback loader with matching PE architecture. |
| GRUB/GRUB2 identity | **Partial** | Bounded, descriptor-bound payload inspection reports an exact downstream build when evidence permits; unsafe candidate names, candidate overflow, read failure, oversized payload, or timeout disables dependency matching. Hash-pinned 2.06/2.12/2.14 Rufus-built `core.img` files exist only as dormant blank-media research bundles: they deliberately do not satisfy detected-image dependencies, no BIOS construction caller is enabled, and downstream builds are never prefix-matched. |
| Syslinux/Isolinux identity and patching | **Partial** | Exact release/custom-build conflicts are detected through descriptor-bound reads; unsafe candidate names, candidate overflow, read failure, oversized payload, or timeout fails closed. A non-destructive consumer independently re-pins exact `6.03-2014-10-06` and `6.04-pre1` bundles, builds the two checksummed ADV sectors, applies the upstream extent/patch/checksum format, and merges boot code while preserving the FAT32 BPB. Its descriptor-only regular-file mapper binds primary/backup VBRs, FSInfo, `BPB_HiddSec`, every consulted entry in both FAT copies, an unaliased root `ldlinux.sys`, its exact cluster/sector chain, and whole-file SHA-256 before and after a test patch. A second pure boundary pins the 440-byte Syslinux 6.02 MBR bootstrap used by Rufus, validates one active FAT32-LBA partition from the same live descriptor, and preserves bytes 440–511. A third witnessed policy accepts only one exact Isolinux/config association, re-identifies and hashes the exact source member bytes, rejects recursive/module-loading directives, root collisions, and every foreign C32, generates a canonical root redirect when needed, and independently re-pins both the matching config-local `ldlinux.c32` and the complete unpatched root `ldlinux.sys` output. The ISO staging backend can opt in only with both caller-supplied immutable bundle roles and performs no network access: it rebuilds the descriptor-bound base-ISO decision, validates extracted bytes, exclusively creates the redirect/module/root placeholder, verifies read-back, and binds their catalog, accounting, and free-space cost. A final exact-byte pass precedes publication; existing final-tree validation covers later transformations. Overlay/embedded-origin Syslinux evidence fails closed. Synthetic fragmented/forgery vectors and optional offline real-payload golden outputs pass. The GUI supplies neither bundle. Remaining gates are integration of this tree with the existing descriptor-only mapper and pure patch plans in one verified regular-file target transaction, then a privileged writer, QEMU/SeaBIOS, and physical certification. |
| Windows Boot Manager | **Partial** | Detects installer paths and UEFI payloads; WIM/ESD metadata and edition/index selection are exposed. Offline BCD construction and cryptographic trust remain. |
| UEFI PE architecture/subsystem | **Done** | Strict structural parser for selected EFI payloads. |
| Authenticode signature reporting | **Partial** | A sealed, isolated Signify 0.9.2 worker resolves its host crypto backend before accepting PE input, then applies CPU/address-space/process/file limits and verifies the file digest plus one embedded SHA-256/384/512 signer signature. It enforces current certificate validity/code-signing use and reports only `integrity-valid-untrusted`. Certificate-table structure remains independently `present-unverified`, and the result cannot authorize a write. Microsoft/firmware trust, certificate revocation, signing timestamps, live platform policy, and Secure Boot acceptance remain unimplemented. |
| SBAT policy | **Partial** | Parses bounded SBAT sections and can evaluate a supplied generation policy; no authenticated live policy feed. |
| DBX/SVN/CA 2023 revocation | **Partial** | A strict, network-inactive catalog projects Microsoft `secureboot_objects` v1.6.5 (commit `798cdc513e0c…`) into 389 unflagged and 284 optional architecture-specific Authenticode SHA-256 hashes. “Unflagged” means only that Microsoft's source did not mark an entry optional. Eligible signed and unsigned EFI payloads are measured only when Microsoft's catalog method, the UEFI/TianoCore method, and Rufus's FileAlignment-rounded PE256 method agree; exact matches produce a separate default-Cancel warning in both DD and direct ISO flows. ISO mode also assesses the final descriptor-bound constructed tree after overlays, Casper changes, runtime wrappers, and supported embedded El Torito FAT trees. For UEFI:NTFS, the selected architecture's bridge and NTFS driver are sliced from exact offset/length records in the already SHA-pinned helper image, independently content-hashed, and included in the same decision. A newly introduced match or incomplete final coverage requires another default-Cancel decision before the target writer runs, and source drift still aborts in writer preflight. Selection overflow, aliasing, unsupported or ambiguous embedded images, read/parser failure, unsupported architectures, ambiguous PE layouts, or catalog corruption remain `unknown`; RISC-V64 helper assessment is unknown because the snapshot has no applicable hash set. “Not listed” is snapshot-scoped and never a safety verdict. The target firmware DBX, certificate/SVN entries, SBAT policy, and authenticated live updates are not yet evaluated. |
| Runtime UEFI media validation | **Partial** | A default-off native UEFI/FAT32 path acquires the exact six-architecture `uefi-md5sum` v1.2 release bundle only after explicit consent; rechecks pinned size/SHA-256, PE architecture/subsystem, and signature-table state; wraps every recognized fallback loader in a final descriptor-bound private tree; regenerates canonical lowercase `md5sum.txt`; and rehashes every manifest entry before the constructed-media planner performs its normal full SHA-256 destination read-back. The GUI explicitly describes MD5 as unsigned, replaceable, bypassable/fail-open accidental-corruption detection—not authentication. Casper/Ubuntu and UEFI:NTFS are conservatively excluded until installer, QEMU, firmware, and Secure Boot testing is complete. |
| Image/staging stored on target | **Done** | Refused before destructive work, then rechecked in constructed execution. |
| Conflicting-process diagnostics | **Done** | When an unmount fails, two bounded, read-only optional `fuser` snapshots identify stable visible owners by sanitized process name, PID, and numeric UID across raw writing, backup, restore, erase, media test, optical capture, ISO construction, persistence, and UEFI:NTFS paths. Pipe reads stop at the shared output/deadline ceiling; ISOpropyl never asks `fuser` to kill an owner, trusts no command-line arguments from `/proc`, and preserves the original failure when the probe is unavailable or incomplete. |
| Distro-specific ISO-mode exclusions | **Done** | A bundled, strict, versioned, network-inactive catalog recognizes three exact original-image member layouts: Manjaro's root regular `.miso`, a regular direct child of root `proxmox/`, and Pop!_OS `filesystem.squashfs` directly under a `casper…pop-os…` root directory. These are deliberately narrower than Rufus's basename/dirname heuristics to avoid directory, link, compatibility-character, and unrelated-name false positives. Complete optical-image catalog evidence is required; host filenames, volume labels, overlays, directories alone, nested near-misses, and ambiguous member facts cannot match. Before extraction, staging relists the descriptor-bound source and requires an exact complete-catalog match; executor validation checks the resulting witness and rederives the exclusion. A rule can only remove extracted ISO mode, never enable or bless DD. Nobara and openSUSE remain deferred until unique structural evidence and representative fixtures exist. |
| Automatic GRUB/Syslinux downloads | **Partial** | A release-bundled v2 catalog pins exact immutable upstream URLs, sizes, SHA-256 digests, purpose-specific bundle membership, licenses, and provenance for selected GRUB/Syslinux payloads. Preparation uses no-follow cache directories, detects parent-path replacement, is cancellable, progress-aware, deadline-bounded across connection/download/cache reads/binding, exact-match-only, and returns no partial set or mutable cache path. Only exact Syslinux identities have dependency mappings; the GRUB entries remain blank-media research inputs. The new pure Syslinux patch consumer accepts independently re-pinned immutable bytes, but BIOS construction and its opt-in GUI caller remain disabled, so normal writes never download them. |

## Windows-specific construction and customization

| Rufus Windows feature | Status | ISOpropyl evidence and remaining work |
|---|---:|---|
| Detect WIM edition/build/architecture/index | **Done** | Strict bounded `wimlib-imagex info --xml` inspection is identity-bound. The GUI supports an explicit choice among up to four exact regular canonical/nested `install.wim` sources, or the sole canonical `sources/install.esd`, then scopes editions to that source. Stale asynchronous results cannot replace or tear down a newer inspection. |
| Split `install.wim` over FAT32 limit | **Done** | Integrated private `wimlib-imagex split` for a sole conventional `sources/install.wim`, validates complete numbered parts, and atomically commits staging. Nested or multi-source oversized WIMs remain path-stable on NTFS. |
| UEFI-only install media | **Partial** | Executable GPT/FAT32 and GPT/NTFS+UEFI:NTFS paths with per-file verification; physical firmware and Secure Boot testing remain. |
| BIOS-only and dual BIOS+UEFI | **Planned** | Exact Windows/GRUB/Syslinux boot code and layouts required. |
| UEFI:NTFS / dual partition | **Partial** | Exact 512-byte-sector GPT/MBR geometry, NTFS data partition, pinned 1 MiB upstream FAT12 helper image, x64/x86/ARM64 payload validation, selected bridge/NTFS-driver content and DBX assessment, conditional CA2011 warning, raw and file read-back verification, identity rechecks, and cancellation. ARM32 and RISC-V64 require an explicit unsigned-payload consent with Secure Boot disabled; RISC-V64 DBX coverage is unknown and LoongArch64 remains incomplete. Physical certification remains. |
| Windows 11 RAM/TPM/Secure Boot bypass | **Done** | Transparent opt-in answer-file registry commands; applied only through ISO mode. |
| Hide/bypass online Microsoft-account flow | **Partial** | General OOBE screen suppression ships. A separate fixed `BypassNRO` specialize command is available only after selecting a recognized non-Home x64/ARM64 Windows 11 21H2–24H2 edition; it implies the OOBE hiding settings and advises offline OOBE. Home, x86, 25H2/26H1, unknown editions, and obvious normalized S-mode/cloud markers fail closed. Because WIM metadata cannot prove that localized or offline-serviced media has no S-mode policy, enabling the option also requires an explicit limitations acknowledgment. |
| Local administrator | **Partial** | Validated username and no collected secret; the account starts blank and a single sequential first-logon command mandates replacement and applies the chosen expiration policy. The GUI warns that this is best-effort and unsupported in S mode. |
| Locale, language, keyboard, time zone | **Done** | Explicit validated Linux-side fields, not host-Windows settings replication. |
| Privacy-question/Express settings | **Done** | Opt-in OOBE privacy settings. |
| Prevent automatic BitLocker encryption | **Done** | Transparent opt-in unattend/registry behavior. |
| Disable Windows Fast Startup | **Done** | A standalone opt-in writes the fixed machine-level `HiberbootEnabled=0` setting during the `specialize` pass. The GUI discloses that full shutdown replaces hybrid shutdown and startup may be slower. |
| Existing answer file protection | **Done** | Root `autounattend.xml` and `sources/$OEM$/$$/Panther/unattend.xml` are detected case-insensitively; customization refuses to combine with or replace either. The frozen staging plan binds the typed options and architecture, regenerates the answer file, and requires exact UTF-8 byte equality before extraction. |
| Windows To Go | **Planned** | WIM apply, ESP/MSR/NTFS layout, offline BCD, SAN policy, and driver/hardware caveats. |
| Internal disks offline for Windows To Go | **Planned** | Belongs to future offline SAN/BCD configuration. |
| Windows CA 2023 / `SkuSiPolicy.p7b` | **Planned** | Security-sensitive, versioned validation required. |
| S Mode-aware customization | **Partial** | UI warns first-logon commands do not run in S Mode; no complete alternative path. |
| Quality-of-life/debloating options | **Done** | A transparent default-off Windows 11 bundle emits six fixed `specialize` commands to disable OneDrive synchronization and remove provisioned/installed OneDrive, Outlook, and Teams components, plus seventeen ordered first-logon commands for Fast Startup, Copilot, recommendations, search, device metadata, news/feeds, chat, Edge first-run, Start shortcuts, and the classic context menu. It requires a validated selected x64/ARM64 Windows 11 WIM/ESD edition, rejects obvious S-mode/cloud editions, and requires a separate limitations acknowledgment. No command contains user text, networking, disk selection, `DiskConfiguration`, `InstallTo`, or `WillWipeDisk`; the frozen staging plan regenerates and byte-compares the complete XML. Package/policy drift and physical Windows validation remain product limitations. |
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
| Persistence-size slider | **Partial** | The capacity-bounded aligned control and transaction wiring ship, but it appears only for a candidate remastered Ubuntu profile with an exposed recognized UEFI GRUB config path; final private staging validates its contents. Embedded El Torito FAT trees are now safely reconstructable, but persistence profile discovery and mutation do not yet consume an embedded GRUB configuration, so current official Ubuntu desktop media remain ineligible. |
| ISO mode versus DD mode | **Done** | The main screen exposes both executable choices, recommends from inspected image evidence, names compatibility limits, resets on a new image, re-plans against the selected target at dispatch, and never silently falls back. ISO mode forces verification. |
| Image checksums | **Done** | Dedicated copy/compare dialog, 64-bit progress, cancellation, exact inspected-image identity binding, and generation-scoped workers so stale progress or completion cannot alter a newer selection or operation. |
| Save-drive action | **Done** | Separate read-only raw/VHD/VHDX workflow with conservative free-space checks and no-overwrite publication. |
| Progress, speed, ETA, cancellation | **Done** | 64-bit counters, stage-aware rolling rate/ETA, cross-thread cancellation. |
| Recoverable I/O retries | **Planned** | Never retry identity changes or ambiguous device failures. |
| Activity log | **Done** | Rotating local log with copy and diagnostics export. |
| Privacy-conscious diagnostics | **Done** | Volume labels, image member paths, member-scoped issues, and UEFI payload details are always reduced to structural counts. Serial/WWN, mount/partition paths, and the activity log require explicit opt-in. |
| Dark/light appearance | **Done** | Persistent palettes. System/high-contrast following remains polish. |
| Settings persistence/reset | **Done** | Appearance, display-unit family, and denylist persist; risky visibility/confirmations reset; full reset ships. |
| Keyboard shortcuts | **Done** | Open, refresh, log, cancel. |
| Command-line image argument | **Done** | Installed entry point and working-tree launcher accept one path. |
| Drag-and-drop | **Done** | One local regular image while idle. |
| Headless CLI writing | **Planned** | Must preserve all GUI identity and confirmation invariants. |
| Update checks | **Research** | Prefer package-manager channels; portable builds need signed opt-in metadata. |
| Portable settings | **Done** | `--portable` uses a singly linked `isopropyl.ini` beside the launched program (or outer AppImage), and that adjacent file remains the opt-in marker for later launches. An existing real `<AppImage>.config` directory follows the AppImage convention. Startup appearance and the window share one settings instance; risky drive visibility and confirmations remain deliberately session-only. |
| ZIP overlay | **Done** | One bounded, identity- and SHA-256-bound stored/deflated ZIP can add ordinary files and directories through ISO mode. The asynchronous GUI selector, effective-catalog preview/replanning, target-residency checks, cancellable private staging, DD omission warning, and frozen final confirmation ship. Traversal, links, special files, encryption, parser disagreement, collisions, unexplained records, fallback `EFI/BOOT/BOOT*.EFI` loaders, and canonical Windows install WIM/ESD/SWM payload changes fail closed; no ISO file is overwritten. Physical installer testing remains. |
| Preserve extracted timestamps | **Done** | A conservative timezone-safe FAT-compatible UTC range from the bounded 7-Zip catalog is carried through private extraction and the final FAT32/NTFS copy. Files and explicit directories are updated through already-open no-follow descriptors, transformed directories are restored deepest-first from their first observed workspace value, and staging representability is checked before any target change. Normalization must be smaller than one workspace/destination filesystem tick; subsequent read-back must exactly match that observed value. Malformed/out-of-range times and all link times are ignored or rejected; permissions and ownership are never imported. |
| Decimal/binary unit preference | **Done** | Settings switches dynamic capacities, progress, rates, estimates, confirmations, and device labels between SI MB/GB/TB and IEC MiB/GiB/TiB. |
| Old-BIOS fixes | **Research** | Requires precise Linux equivalents and real hardware fixtures. |

## Advanced modes and platform decisions

| Rufus advanced behavior | Status | ISOpropyl position |
|---|---:|---|
| Blank Syslinux/GRUB/Grub4DOS/ReactOS/UEFI:NTFS media | **Partial** | Five-architecture UEFI Shell recovery media ships as a separate, verified GPT/FAT32 profile. Syslinux, GRUB, Grub4DOS, ReactOS, and blank UEFI:NTFS profiles remain planned behind audited consumers and lawful payload catalogs. |
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
| Verified boot components | **Partial** | A release-bundled catalog pins UEFI:NTFS, selected Syslinux/GRUB bundles, the five-architecture UEFI Shell 26H1 set, and all six `uefi-md5sum` v1.2 wrappers by immutable source release/commit, exact size, SHA-256, license, and provenance. UEFI:NTFS has explicit consent, identity-safe cache binding, in-memory privileged transfer, and full read-back. UEFI Shell additionally enforces exact PE architecture, EFI-application subsystem, unchanged unsigned state, descriptor-safe private staging, target-bound construction, typed erase confirmation, and full file read-back. Runtime validation applies the same structural payload checks, preserves originals, creates and revalidates the final MD5 manifest, and remains expressly non-authenticating. Other generic bundles bind singly linked no-follow files into immutable bytes but have no privileged consumer. Project-owned signed ISOpropyl release metadata remains. |
| No unsigned remote scripts | **Policy** | ISOpropyl will never execute a downloaded installer/downloader script. |
| Opt-in network use | **Policy** | UEFI:NTFS, UEFI Shell, and boot-time-validation acquisition each require an explicit user action and confirmation. Downloads are release-pinned and no remote executable or script is run on Linux; ordinary image writes never trigger these network paths. |
| Reproducible builds | **Partial** | Standard package metadata and CI exist; locked inputs and reproduction attestations remain. |
| Signed releases | **Planned** | Sigstore/minisign and package-native signatures. |
| Desktop/AppStream metadata | **Done** | Validated application, icon, and metainfo files. |
| Flatpak/AppImage/native packages | **Planned** | Block-device/polkit integration must be designed per sandbox/package. |
| Localization/accessibility | **Planned** | Qt translations, screen-reader QA, high-contrast/system theme. |
| Telemetry | **Policy** | None. Diagnostics are local and sensitive fields default off. |
| License | **Done** | AGPL-3.0-or-later with per-file SPDX identifiers. |

## Priority order

1. Add privileged exclusive target ownership across every destructive transaction.
2. Hardware-certify current UEFI/FAT32, UEFI:NTFS, and optional boot-time-validation modes and failure cleanup.
3. Complete the started Syslinux BIOS/dual-firmware profile by integrating the
   exact unpatched root `ldlinux.sys` now materialized by the private-tree
   transform with the existing descriptor-only mapper and pure patch plans in a
   verified regular-file target transaction. Then add the bounded device
   transaction and pass QEMU/SeaBIOS/OVMF gates plus physical certification.
4. Hardware-certify the narrow immutable Casper layout and add only fixture-backed profiles.
5. Add Windows To Go through wimlib and offline boot configuration.
6. Add cryptographic Secure Boot trust and authenticated revocation data.
7. Complete FFU/VTSI/direct WIM/ESD and image-output formats.
8. Add project-owned signed manifests and corresponding-source-compliant hosting,
   then audited BIOS consumers for the dormant GRUB/Syslinux payloads; physically
   certify the explicit-consent UEFI Shell workflow and add signed opt-in FreeDOS
   acquisition.
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
- [Runtime-validation eligibility](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/rufus.c#L747-L765)
- [Runtime-validation finalizer](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/hash.c#L2461-L2589)
- [`uefi-md5sum` v1.2 design and limits](https://github.com/pbatard/uefi-md5sum/blob/6195f2ef754c2ad390bda6590628708f410d55f6/README.md#L13-L72)
- [Persistence mutation](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/iso.c#L494-L553)
- [El Torito embedded FAT detection and extraction](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/iso.c#L1770-L1975)
- [Ubuntu 20.04.6 desktop ISO file list](https://releases.ubuntu.com/20.04/ubuntu-20.04.6-desktop-amd64.list)
- [Ubuntu 22.04.5 desktop ISO file list](https://releases.ubuntu.com/22.04/ubuntu-22.04.5-desktop-amd64.list)
- [Ubuntu 24.04.3 desktop ISO file list](https://releases.ubuntu.com/24.04/ubuntu-24.04.3-desktop-amd64.list)
- [UEFI:NTFS layout](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/drive.c#L2284-L2512)
- [Windows customization](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L140-L540)
- [Windows To Go](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L930-L1115)
- [Fido downloader](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/net.c#L779-L924)
- [DBX updater](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/net.c#L444-L520)
