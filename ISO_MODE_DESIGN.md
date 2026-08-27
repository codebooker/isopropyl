# Filesystem-aware ISO mode

ISOpropyl has two distinct write paths:

- **DD mode** copies the selected image byte-for-byte and preserves its existing
  partition table and boot records. It is appropriate for raw images and hybrid
  ISOs.
- **ISO mode** constructs new media from validated ISO filesystem contents. The
  executable profile currently supports UEFI-only, one GPT/FAT32 partition, and
  a recognized non-empty `EFI/BOOT/BOOT*.EFI` fallback loader.

The paths remain separate because filesystem extraction is not a harmless
variation of `dd`: it changes layout, filenames, boot behavior, capacity
accounting, and the security boundary.

## Implemented UEFI/FAT32 pipeline

1. **Analyze without privilege.** ISOpropyl catalogs ISO members, layouts,
   Windows setup content, boot paths and architectures; parses El Torito; and
   structurally inspects selected UEFI PE/SBAT payloads.
2. **Build an immutable plan.** The plan binds the member catalog, UEFI-only
   firmware target, FAT32 constraints, transformations, capacity, and source
   identity. An oversized `sources/install.wim` is the only accepted FAT32
   over-limit transformation.
3. **Prepare a private staging tree.** Safe extraction rejects absolute and
   parent paths, links, special files, case/Unicode collisions, unexpected
   output, hard links, and source changes. Publication uses Linux
   `renameat2(RENAME_NOREPLACE)`.
4. **Apply explicit transformations.** A trusted system `wimlib-imagex` can split
   `install.wim`; opted-in Windows options add a validated `autounattend.xml`
   only when the ISO has no existing answer file.
5. **Build a target-bound media plan.** The staged tree, fallback loader, target
   identity, GPT/FAT32 format plan, required capacity, and absolute trusted tool
   paths are frozen before device work.
6. **Revalidate and format.** The executor rechecks source and target before and
   after formatting, validates the exact new child partition and vfat mount, and
   refuses staging stored on the target.
7. **Copy and verify.** Files are opened relative to no-follow directory file
   descriptors, created exclusively, SHA-256 hashed during copy, then completely
   read back and compared before cleanup and power-off.

Every privileged command uses a fixed argument array. Cancellation propagates to
the active extractor, WIM splitter, formatter, or constructed-media executor.

## Current limits

- No BIOS or dual BIOS+UEFI construction.
- No NTFS, UEFI:NTFS, dual-partition, symlink, or hardlink materialization.
- No embedded El Torito image extraction or bootloader repair/installation.
- No Windows edition/index selection or Windows To Go.
- Automated device tests are mocked; physical firmware boot testing remains a
  release gate.
- The GPT FAT32 partition currently uses the formatter's Microsoft Basic Data
  type. Firmware compatibility must be validated before changing or promising a
  broader profile.

## Bootloader dependency policy

`isopropyl/data/bootloaders-v1.json` is deliberately empty. Resolver code can
enforce HTTPS origin/redirect hosts, cataloged size, SHA-256, atomic caching, and
pre-use verification, but no production caller downloads a boot artifact today.

A future catalog entry requires documented upstream provenance, license review,
exact version/custom-build compatibility, size and digest review, explicit user
consent, and protection by the same signed reproducible release process as the
application. A host `grub-install` binary is never treated as a substitute for an
image payload such as `core.img`.
