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

### Linux boot and persistence

- Move the reviewed GRUB/Syslinux bundle metadata to project-owned signed
  release manifests and a corresponding-source-compliant artifact service;
  keep exact-match-only immutable preparation.
- Add a narrowly scoped, read-back-verified Syslinux MBR/FAT installer before
  exposing the dormant payload bundles or removing any BIOS blocker. GRUB BIOS
  follows only after its prefix, module set, filesystem, and boot-region layout
  can be reproduced and verified without executing downloaded code.
- Add bounded support for the embedded UEFI GRUB configuration used by current
  official Ubuntu media, rather than assuming a synthetic extracted path. Then
  hardware-certify the immutable Casper workflow across 512- and 4096-byte
  logical-sector media and expand profiles only through release-specific
  fixtures and hardware results.
- Add distro-specific DD-only rules and tested BIOS/UEFI construction profiles.

### Trust, formats, and advanced media

- Extend the implemented integrity-only Authenticode check with independently
  authenticated Microsoft/firmware trust policy, signing-time validation, and
  DBX/SBAT/SVN revocation data; keep runtime media validation distinct from
  static analysis and never promote an embedded-only result into boot trust.
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
- Add signed opt-in Microsoft ISO and curated Linux distribution downloads; never
  execute remotely supplied scripts.

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
- Flatpak/AppImage feasibility work, native distro packages, portable settings,
  release signatures, SBOMs, and reproducibility attestations.

The exhaustive capability-by-capability status is maintained in
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).
