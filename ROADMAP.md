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
   mount conflicts, and cleanup failures without weakening identity checks.
3. Add a privileged exclusive whole-target ownership primitive that remains held
   across the complete destructive transaction, without an unsafe bypass.
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
- Track Windows CA 2023, `SkuSiPolicy.p7b`, S Mode, and version-specific online
  account behavior without silently applying stale tweaks.

### Linux boot and persistence

- Populate GRUB/Syslinux catalog entries only with license-reviewed,
  upstream-provenanced payloads, signed release metadata, exact sizes and hashes;
  preserve the same consent and pre-use checks already used by UEFI:NTFS.
- Add cache inspection/deletion UI for verified boot artifacts.
- Add bounded support for the embedded UEFI GRUB configuration used by current
  official Ubuntu media, rather than assuming a synthetic extracted path. Then
  hardware-certify the immutable Casper workflow across 512- and 4096-byte
  logical-sector media and expand profiles only through release-specific
  fixtures and hardware results.
- Add distro-specific DD-only rules and tested BIOS/UEFI construction profiles.

### Trust, formats, and advanced media

- Cryptographically verify Authenticode signers and authenticated DBX/SBAT/SVN
  revocation data; keep runtime media validation distinct from static analysis.
- Add Windows To Go through `wimlib` apply, offline BCD/SAN policy, and explicit
  internal-disk behavior.
- Add FFU/VTSI/direct WIM/ESD input and VHD/VHDX/FFU/UDF output only after format
  parsers and size/platform checks fail closed.
- Add FreeDOS, UEFI Shell, and advanced blank bootloader workflows with lawful,
  verified payload sources.
- Add signed opt-in Microsoft ISO and curated Linux distribution downloads; never
  execute remotely supplied scripts.

## Product quality

- Continue applying the bounded-worker and stale-result pattern used by device
  discovery to any future host probes that could delay the UI.
- Localization, system/high-contrast appearance, keyboard and screen-reader QA.
- Conflicting-process diagnostics and narrowly bounded I/O retries.
- Cluster size, filesystem, partition-layout, and volume-label controls where the
  selected boot profile can support them safely.
- Flatpak/AppImage feasibility work, native distro packages, portable settings,
  release signatures, SBOMs, and reproducibility attestations.

The exhaustive capability-by-capability status is maintained in
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).
