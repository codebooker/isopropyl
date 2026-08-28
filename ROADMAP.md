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
3. Evolve the shipped fail-fast, per-command cooperative whole-device locks into
   a privileged broker/private-namespace design that can retain ownership across
   the complete destructive transaction. Continue describing Linux BSD locks as
   advisory rather than claiming they exclude uncooperative privileged writers.
4. Confirm the GPT partition type and removable-media fallback loaders across a
   documented firmware matrix.
5. Ship reproducible native packages and at least one portable format with signed
   release artifacts and installation documentation.

## Next capability milestones

### Windows installer workflow

- Continue refining the implemented first-class ISO/DD selector as new executable
  firmware profiles become available; never silently change the user's choice.
- Add BIOS and dual BIOS+UEFI construction with exact, provenance-bound boot code.
- Expand the implemented UEFI:NTFS path beyond 512-byte logical sectors only
  after upstream payload and firmware evidence supports it.
- Track Windows CA 2023, `SkuSiPolicy.p7b`, S Mode, and post-24H2 online-account
  behavior without silently extending the current exact-build `BypassNRO` policy.
- Keep the standalone Fast Startup switch and the implemented Windows 11
  quality-of-life bundle separate, default-off, and explicitly disclosed. Track
  package/policy drift through release fixtures without adding downloaded or
  user-supplied commands, and physically validate the fixed bundle on supported
  x64/ARM64 Windows 11 releases.

### Linux boot and persistence

- Move the reviewed GRUB/Syslinux bundle metadata to project-owned signed
  release manifests and a corresponding-source-compliant artifact service;
  keep exact-match-only immutable preparation.
- Complete the narrowly scoped Syslinux MBR/FAT installer. The exact ADV,
  extent, checksum, FAT32 VBR merge, descriptor-only FAT mapping, partition
  offset binding, regular-file before/after read-back harness, and exact
  provenance-bound 440-byte MBR bootstrap merge are implemented. A pure,
  exact-version config/C32/root staging policy is also implemented, including
  collision rejection and independent pins for `ldlinux.c32` and the complete
  unpatched root `ldlinux.sys` plus blank ADV output. Its opt-in backend-only ISO
  transform requires both exact bundle roles, revalidates descriptor-bound
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
  formatter, mount, loop device, named scratch file, or subprocess. Remaining
  gates are witnessed production ISO-plan integration, bounded privileged
  device streaming/read-back, QEMU/SeaBIOS plus OVMF, and physical
  certification. Do not expose payloads or remove a BIOS blocker before those
  gates pass. GRUB BIOS follows only after
  its prefix, module set, filesystem, and boot-region layout can be reproduced
  and verified without executing downloaded code.
- Integrate the implemented bounded El Torito FAT tree with persistence-profile
  discovery and safe mutation of the embedded UEFI GRUB configuration used by
  current official Ubuntu media. Then hardware-certify the immutable Casper
  workflow across 512- and 4096-byte logical-sector media and expand profiles
  only through release-specific fixtures and hardware results.
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
- Add Windows To Go through `wimlib` apply, offline BCD/SAN policy, and explicit
  internal-disk behavior.
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
  workflow and every fallback path with Secure Boot disabled. Add FreeDOS and
  advanced blank bootloader workflows with lawful, verified payload sources.
- Expand the implemented signed, resumable Ubuntu LTS download profile only with
  distribution-owned signing metadata and maintained release fixtures. Add a
  signed opt-in Microsoft ISO downloader separately; never execute remotely
  supplied scripts.

## Product quality

- Continue applying the bounded-worker and stale-result pattern used by device
  discovery to any future host probes that could delay the UI.
- Localization, system/high-contrast appearance, keyboard and screen-reader QA.
- Narrowly bounded I/O retries where idempotence can be proven; the shipped
  read-only conflicting-process diagnostic must remain optional and non-killing.
- Physically certify the implemented geometry-filtered restore allocation/block
  sizes, then consider exposing profile-safe sizing in ISO construction.
- Additional filesystem, partition-layout, and volume-label controls where the
  selected boot profile can support them safely.
- Flatpak/AppImage feasibility work, native distro packages, release signatures,
  SBOMs, and reproducibility attestations. Portable settings already support
  adjacent launchers and AppImage's `.config` convention.

The exhaustive capability-by-capability status is maintained in
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).
