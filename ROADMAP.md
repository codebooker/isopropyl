# ISOpropyl roadmap

ISOpropyl is moving toward Rufus-class capability through Linux-native,
fail-closed implementations. “Implemented” means code and non-destructive tests
exist; release confidence additionally requires physical-media and firmware
evidence.

## Release gate: certify what already exists

1. Exercise UEFI/FAT32 ISO mode on Windows 10/11 and representative Linux ISOs
   across x64 and ARM64 firmware, 512e/4Kn media, USB flash drives, SD readers,
   and explicitly enabled USB SSDs.
2. Test unplug, cancellation, authentication refusal, short writes, full disks,
   mount conflicts, and cleanup failures without weakening identity checks.
3. Confirm the GPT partition type and removable-media fallback loaders across a
   documented firmware matrix.
4. Ship reproducible native packages and at least one portable format with signed
   release artifacts and installation documentation.

## Next capability milestones

### Windows installer workflow

- Expose WIM/ESD build, edition, architecture, and index metadata in the GUI.
- Make ISO/DD selection first-class rather than placing ISO mode in a secondary
  plan dialog.
- Add BIOS and dual BIOS+UEFI construction with exact, provenance-bound boot code.
- Add an audited NTFS or FAT-ESP-plus-NTFS path and signed multi-architecture
  UEFI:NTFS payloads.
- Track Windows CA 2023, `SkuSiPolicy.p7b`, S Mode, and version-specific online
  account behavior without silently applying stale tweaks.

### Linux boot and persistence

- Populate the GRUB/Syslinux artifact catalog only with license-reviewed,
  upstream-provenanced payloads, signed release metadata, exact sizes and hashes.
- Integrate explicit download consent, cache inspection/deletion, and pre-use
  revalidation.
- Execute persistence for a narrow, versioned Ubuntu/Mint/Debian/Kali matrix,
  including partition creation, `persistence.conf`, and boot-config mutation.
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

- Localization, system/high-contrast appearance, keyboard and screen-reader QA.
- Conflicting-process diagnostics and narrowly bounded I/O retries.
- Cluster size, filesystem, partition-layout, and volume-label controls where the
  selected boot profile can support them safely.
- Flatpak/AppImage feasibility work, native distro packages, portable settings,
  release signatures, SBOMs, and reproducibility attestations.

The exhaustive capability-by-capability status is maintained in
[FEATURE_MATRIX.md](FEATURE_MATRIX.md).
