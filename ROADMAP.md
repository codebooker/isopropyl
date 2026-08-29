# ISOpropyl roadmap

ISOpropyl is moving toward Rufus-class capability through Linux-native,
fail-closed implementations. “Implemented” means code and non-destructive tests
exist; release confidence additionally requires physical-media and firmware
evidence.

## Release gate: certify what already exists

1. Exercise UEFI/FAT32 and UEFI:NTFS ISO mode on Windows 10/11 and representative
   Linux ISOs across x64 and ARM64 firmware, Secure Boot policies, 512e/4Kn media
   where supported, USB flash drives, SD readers, and explicitly enabled USB
   SSDs.
   Include the optional `uefi-md5sum` path on clean, corrupted, missing-manifest,
   cancelled, signed-wrapper, and unsigned-wrapper boots; keep Casper/Ubuntu and
   UEFI:NTFS disabled for that option until their separate compatibility runs pass.
2. Test unplug, cancellation, authentication refusal, short writes, full disks,
   mount conflicts, overlay mutation/CRC/decompression failure, target-resident
   overlay refusal, VTSI expansion and exact-capacity restore, and cleanup failures
   without weakening identity checks.
3. Certify the shipped GUI/CLI raw broker's retained same-descriptor ownership,
   PREPARED/COMMIT boundary, cache handling, and failure recovery. Include the
   fast-zero profile's 32 MiB scan/skip behavior, complete all-zero read-back,
   authenticated post-COMMIT cancellation, and identity-gated first/last 16 MiB
   cleanup on representative flash, USB SSD, SD, 512e, and 4Kn media. Then extend
   that privileged broker/private-namespace design across the other destructive
   transactions. Continue describing Linux BSD locks as advisory rather than
   claiming they exclude uncooperative privileged writers, and never present
   logical zeroing as ATA/NVMe sanitization or hardware secure erase.
4. Confirm the GPT partition type and removable-media fallback loaders across a
   documented firmware matrix.
5. Ship reproducible native packages and at least one portable format with signed
   release artifacts and installation documentation.

## Next capability milestones

### Windows installer workflow

- Continue refining the implemented first-class ISO/DD selector as new executable
  firmware profiles become available; never silently change the user's choice.
- Broaden the implemented, default-off x64 Windows BIOS+UEFI construction only
  after the current exact FAT32/active-MBR profile is physically certified. Its
  project-authored boot code, anonymous-image transaction, and exact generated
  answer-file composition are implemented; retain a customized KVM/SeaBIOS+OVMF
  observation before promoting customization coverage, then add BIOS-only,
  NTFS/UEFI:NTFS dual-firmware, and other architectures behind equally narrow
  provenance and firmware evidence.
- Expand the implemented UEFI:NTFS path beyond 512-byte logical sectors only
  after upstream payload and firmware evidence supports it.
- Physically validate the implemented, separately acknowledged installed-system
  `SkuSiPolicy.p7b` workflow on supported Windows 11 25H2/26H1 x64/ARM64 systems,
  including missing-policy, copy-failure, recovery, and BitLocker scenarios.
  Physically certify the implemented, default-off Windows 2023-generation
  installer boot-file transform for the exact reviewed Windows 11 25H2 v2
  English x64/ARM64 profiles. Its whole-ISO binding, literal bounded WIM
  extraction, PE architecture/subsystem and structural certificate-table
  checks, private atomic replacements, and read-back receipts are implemented;
  certificate-chain/revocation/signing-time evaluation and firmware fixtures
  remain. Track
  S Mode and post-24H2 online-account behavior without silently extending the
  current exact-build `BypassNRO` policy.
- Keep the standalone Fast Startup switch and the implemented Windows 11
  quality-of-life bundle separate, default-off, and explicitly disclosed. Track
  package/policy drift through release fixtures without adding downloaded or
  user-supplied commands, and physically validate the fixed bundle on supported
  x64/ARM64 Windows 11 releases.

### Linux boot and persistence

- Move the reviewed GRUB/Syslinux bundle metadata to project-owned signed
  release manifests and a corresponding-source-compliant artifact service;
  keep exact-match-only immutable preparation.
- Certify and package the narrowly scoped Syslinux MBR/FAT installer. The exact ADV,
  extent, checksum, FAT32 VBR merge, descriptor-only FAT mapping, partition
  offset binding, regular-file before/after read-back harness, and exact
  provenance-bound 440-byte MBR bootstrap merge are implemented. A pure,
  exact-version config/C32/root staging policy is also implemented, including
  collision rejection and independent pins for `ldlinux.c32` and the complete
  unpatched root `ldlinux.sys` plus blank ADV output. Its environment-gated
  developer ISO transform requires both exact bundle roles, revalidates descriptor-bound
  source and extracted-tree bytes, creates missing files exclusively, reads
  them back, and binds its Syslinux-adjusted planned catalog/accounting before
  the existing final-tree validation. It currently accepts Syslinux evidence
  only from the base ISO. A descriptor-only transaction now integrates that
  exact root with the live FAT mapper and pure patch plans on an owner-only
  anonymous image. It witnesses every write, preserves partial-sector slack,
  activates MBR last, verifies every durability barrier/read-back, and proves an
  exact whole-image posthash. A production-owned, deterministic MBR/FAT32
  builder now precedes it on an anonymous `O_TMPFILE`; source/tree hashing,
  complete preallocation, independent allocation/tree parsing, full-image
  posthashing, fail-closed poisoning, and descriptor-safe streaming require no
  formatter, mount, loop device, named scratch file, or subprocess. Matching
  pre/post-publication manifests now authenticate the published ISO tree, and a
  witnessed composite binds that receipt, exact bundles/config/root loader, and
  private plan before returning only a patched-attested image owner. A separate
  clone-resistant process-local receipt binds that exact composite to a
  freshly reproduced complete removable-device observation and descendant
  topology, live block identity, exact capacity, 512-byte sector geometry,
  fail-closed source/workspace non-residency, mandatory read-back, warnings, and
  typed confirmation and the kernel disk generation before preparation. A
  separately installed, fixed PolicyKit coordinator now transfers only the
  re-attested anonymous descriptor over an authenticated local packet socket.
  The root helper repeats sysfs, mount/swap, geometry, removability, topology,
  source-residency, and `BLKGETDISKSEQ` checks; uses an in-band PREPARED →
  COMMIT/CANCEL boundary; retains one block descriptor through writes, cache
  flushes, and mandatory full SHA-256 read-back; clears stale GPT boundary
  metadata before streaming; proves sector zero remains inactive immediately
  before activation; and activates the new MBR last. An authoritative one-shot
  app workflow now owns exact preparation, confirmation, execution, cancellation,
  and cleanup, but ordinary launches keep it hidden; experienced testers must set
  `ISOPROPYL_EXPERIMENTAL_SYSLINUX=1` and use expendable media. A retained,
  locally reproduced 2026-08-28 device-free observation pins the official
  Syslinux 6.03 archive and source members, requires the project bundles to
  byte-match them, exercises the production pipeline, and reaches the Syslinux
  prompt under sealed, networkless QEMU TCG/SeaBIOS while recording the trusted
  emulator's version and SHA-256. Remaining gates are a native hardened helper,
  an installed PolicyKit/SCM_RIGHTS VM test,
  OVMF retained-UEFI coverage, hot-swap/failure tests, and physical certification.
  Keep the general BIOS planner blocker and normal GUI exposure intact until those
  gates pass. GRUB
  BIOS follows only after
  its prefix, module set, filesystem, and boot-region layout can be reproduced
  and verified without executing downloaded code.
- Do not treat the implemented bounded El Torito FAT parser as an Ubuntu
  persistence solution: official Ubuntu 20.04.6, 22.04.5, and 24.04.4 embedded
  EFI images contain EFI binaries but no recognized text `grub.cfg`, and the
  older images duplicate those files in the base ISO. Research an evidence-backed
  configuration path for current official media without replacing embedded
  binaries, then hardware-certify the immutable Casper workflow across 512- and
  4096-byte logical-sector media. Expand profiles only through release-specific
  fixtures and hardware results.
- Expand the shipped distro-specific ISO-mode exclusion catalog only through
  unique structural evidence and representative fixtures, and add tested
  BIOS/UEFI construction profiles. Nobara and openSUSE remain deferred because
  their currently documented names/layouts do not provide safe unique matches.

### Trust, formats, and advanced media

- Extend the implemented integrity-only Authenticode check and pinned offline
  Microsoft DBX image-hash advisor with independently authenticated live
  firmware policy, certificate revocation, signing-time validation, SBAT, SVN,
  and coverage for El Torito layouts outside the strict FAT subset. Keep runtime
  media validation distinct from static analysis and never promote a snapshot
  miss or an embedded-only result into boot trust.
- Firmware-test the implemented default-off `uefi-md5sum` v1.2 transformation,
  including every fallback architecture, manifest failure/cancellation behavior,
  Secure Boot acceptance or rejection, and post-write corruption. Expand beyond
  native FAT32 only after Casper/Ubuntu and UEFI:NTFS regressions are excluded.
- Complete the internal non-executable Windows To Go preview. It already binds
  selected x64 Windows 8+ WIM metadata and expanded size to Rufus-compatible
  512-byte-sector GPT geometry (260 MiB ESP, 128 MiB MSR, remaining NTFS).
  A candidate serializer/parser records the 88-byte qualified-partition hive
  layout used by two independent open-source implementations, but Microsoft's
  public WMI style values conflict with that internal mapping. A separate strict
  typed evidence envelope now models actual BCD registry kinds, derives graph and
  boot semantics from captured values, binds the complete frozen GPT geometry and
  Microsoft command provenance, and requires a four-run one-GUID-at-a-time
  differential set. A strict registry-free RAW schema, developer-only fixed-VHD
  PowerShell collector, and descriptor-bound atomic Linux importer now implement
  the evidence handoff. The importer derives registry evidence through hivex,
  verifies the entire cohort before output, and publishes exact source copies plus
  canonical fixtures without replacement. Its unit fixtures remain synthetic;
  the collector has independent GPT/CRC and static safety tests but has not run on
  Windows here. An authentic Windows capture, native hivex construction, and QEMU
  still gate any hive use. A
  read-only verifier now pins each captured hive descriptor, snapshots it into a
  sealed memfd, decodes its typed registry tree with optional hivex, binds the
  complete store digest/size, and compares a four-hive cohort without exposing a
  write API. This is read-back evidence only and does not trust the fixtures.
  A candidate non-executable
  WIM-apply request contract now carries strictly validated claims for the
  parent, exact child geometry, WIM snapshot, edition index/expanded size, and
  plan receipts. A device-free backend now certifies the exact inherited-fd
  `wimlib` apply against a fresh anonymous regular NTFS image while the owner is
  non-dumpable, the target is advisory-locked, the source is kernel-leased, and
  all complete hashes are cancellable and time-bounded. It explicitly rejects
  block devices and does not claim resistance to a hostile same-UID process.
  Physical execution still requires privileged topology/mount
  re-attestation, PREPARED → COMMIT, block-target contamination recovery,
  complete image-native BCD construction/read-back, offline SAN policy,
  explicit internal-disk behavior,
  and QEMU/OVMF plus physical certification.
- Physically certify the strict VTSI v1.0 restore path on representative Ventoy
  media; keep its exact-capacity and 512-byte logical-sector requirements. Add
  FFU/direct WIM/ESD input and FFU/UDF-image authoring output only after format
  parsers and size/platform checks fail closed. Continue hardening and physically
  certifying the implemented VHD/VHDX drive-backup path.
- Hardware-test additive overlays with representative Windows and Linux installer
  layouts. Additional archive formats or multiple ordered overlays remain out of
  scope until they preserve the same bounded, no-overwrite namespace and exact-byte
  binding.
- Firmware-test the implemented explicit-consent five-architecture UEFI Shell
  workflow and every fallback path with Secure Boot disabled. Physically certify
  the implemented official FreeDOS 1.4 LiteUSB/FullUSB acquisition and guarded
  raw-write handoff on representative x86 BIOS and UEFI Legacy/CSM systems, with
  Secure Boot disabled and both exact fixed image sizes. Keep native UEFI,
  Secure Boot, ARM, RISC-V, image expansion, and advanced blank-bootloader
  construction out of scope until each has an independently verifiable design.
- Expand the implemented signed, resumable Ubuntu LTS download profile only with
  distribution-owned signing metadata and maintained release fixtures. Expand
  the implemented hash-pinned Windows 11 25H2 v2 English x64/ARM64 downloader
  only through reviewed language/release profiles, official live hash provenance,
  and sanitized service fixtures. Keep the browser-assisted route available,
  treat connector drift as a hard stop, and never execute remotely supplied
  scripts. Expand FreeDOS only through exact official archives with separately
  reviewed archive catalogs and inner image hashes; retain the project-pinned
  archive digest plus live official-row corroboration, and adopt a detached
  publisher signature if FreeDOS makes one available.

## Product quality

- Extend the implemented safety-equivalent `isopropyl-cli` beyond raw/DD only
  when a filesystem-aware ISO transaction can preserve the same exact target,
  staging-residency, transformation-review, and typed-confirmation invariants.
  Keep unattended destructive confirmation, target indexes, globs, and substring
  matching out of scope.
- Continue applying the bounded-worker and stale-result pattern used by device
  discovery to any future host probes that could delay the UI.
- Localization, system/high-contrast appearance, keyboard and screen-reader QA.
- Extend the implemented retained-descriptor positional-I/O retry policy to the
  remaining mounted constructed-media and backup/optical paths only where exact
  offsets, zero-progress errors, identity guards, and cancellation semantics can
  be proved. The shipped read-only conflicting-process diagnostic must remain
  optional and non-killing.
- Physically certify the implemented geometry-filtered restore allocation/block
  sizes, then consider exposing profile-safe sizing in ISO construction.
- Additional filesystem, partition-layout, and volume-label controls where the
  selected boot profile can support them safely.
- Promote the implemented reproducible Debian/Ubuntu `amd64`/`arm64` alpha
  package through installed VM certification, lintian/piuparts/autopkgtest,
  independent reproduction attestations, and signed releases. Add official
  distro packaging, Flatpak/AppImage feasibility work, and SBOMs. Portable
  settings already support adjacent launchers and AppImage's `.config`
  convention.

The exhaustive capability-by-capability status is maintained in
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).
