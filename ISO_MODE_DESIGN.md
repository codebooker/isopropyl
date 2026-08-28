# Filesystem-aware ISO mode

ISOpropyl has two distinct write paths:

- **DD mode** copies the selected image byte-for-byte and preserves its existing
  partition table and boot records. It is appropriate for raw images and hybrid
  ISOs.
- **ISO mode** constructs new media from validated ISO filesystem contents. The
  executable profile supports UEFI-only GPT/FAT32 media or, when a file exceeds
  FAT32's limit, GPT/NTFS plus an exact raw UEFI:NTFS helper partition. Both
  require a recognized non-empty `EFI/BOOT/BOOT*.EFI` fallback loader.

The paths remain separate because filesystem extraction is not a harmless
variation of `dd`: it changes layout, filenames, boot behavior, capacity
accounting, and the security boundary.

## Implemented UEFI pipeline

1. **Analyze without privilege.** ISOpropyl catalogs ISO members, layouts,
   Windows setup content, boot paths and architectures; parses El Torito; and
   structurally inspects selected UEFI PE/SBAT payloads.
2. **Build an immutable plan.** The plan binds the member catalog, UEFI-only
   firmware target, filesystem constraints, boot strategy, transformations,
   capacity, and source identity. An oversized `sources/install.wim` can be
   split for FAT32; otherwise the planner can select NTFS+UEFI:NTFS.
3. **Prepare a private staging tree.** Safe extraction rejects absolute and
   parent paths, links, special files, case/Unicode collisions, unexpected
   output, hard links, and source changes. Publication uses Linux
   `renameat2(RENAME_NOREPLACE)`.
4. **Apply explicit transformations.** A trusted system `wimlib-imagex` can
   inspect `install.wim`/`install.esd`, bind an explicitly selected edition
   index, and split a large WIM for FAT32. Opted-in Windows options add a
   validated `autounattend.xml` only when the ISO has no existing answer file.
5. **Build a target-bound media plan.** The staged tree, fallback loader, target
   identity, exact partition geometry, required capacity, and absolute trusted
   tool paths are frozen before device work. UEFI:NTFS also binds the verified
   1 MiB artifact bytes and exact architecture payload pair.
6. **Revalidate and format.** The executor rechecks source and target before and
   after formatting, validates every new child partition and expected mount
   filesystem, and refuses staging stored on the target.
7. **Copy and verify.** Files are opened relative to no-follow directory file
   descriptors, created exclusively, SHA-256 hashed during copy, then completely
   read back and compared before cleanup and power-off. The UEFI:NTFS helper is
   written from bound memory through privileged standard input and receives a
   separate full raw read-back/hash comparison.

Every privileged command uses a fixed argument array. Cancellation propagates to
the active extractor, WIM splitter, formatter, or constructed-media executor.

## Current limits

- No device-facing BIOS or dual BIOS+UEFI construction; the witnessed Syslinux
  backend and target receipt remain non-executable.
- No arbitrary symlink or hardlink materialization.
- Embedded El Torito extraction is limited to one strictly validated FAT12/16/32
  filesystem, either direct or in an otherwise empty active-first-partition MBR
  wrapper. Multiple images, non-FAT filesystems, hard-disk emulation, and general
  bootloader repair/installation remain unsupported.
- No Windows To Go.
- Automated device tests are mocked; physical firmware boot testing remains a
  release gate.
- UEFI:NTFS is currently limited to 512-byte logical sectors. Secure Boot on its
  signed x64/x86/ARM64 payloads additionally depends on Microsoft UEFI CA 2011
  third-party trust and revocation state. ARM32 unsigned payloads, RISC-V64, and
  LoongArch64 fail closed in the normal GUI path.
- The GPT FAT32 partition and the UEFI:NTFS helper both use deliberate,
  profile-specific types. Firmware compatibility must be physically validated
  before promising a broader profile.

## Bootloader dependency policy

`isopropyl/data/bootloaders-v2.json` contains the working UEFI:NTFS v2.8 image,
exact Syslinux `6.03-2014-10-06` and `6.04-pre1` payload sets, and dormant GRUB
2.06/2.12/2.14 blank-media research bundles. All entries are pinned to immutable
upstream snapshots with exact sizes, SHA-256 digests, license identifiers, and
provenance. Resolver code enforces HTTPS origin/redirect hosts, purpose-specific
bundle membership, no-follow descriptor-bound atomic caching, parent-path
revalidation, and pre-use verification under one caller-visible deadline. The
UEFI:NTFS GUI obtains explicit consent before acquisition, and its privileged
writer consumes verified in-memory bytes instead of the cache path. No GUI or
device-facing BIOS executor consumes the GRUB/Syslinux bundles. A backend-only,
device-unreachable Syslinux composite can consume the exact two supported bundle
roles only after authenticated ISO staging. A non-executable target authorization
layer can bind that composite to an exact 512-byte-sector, equal-capacity removable
disk and typed phrase, but no privileged BIOS executor consumes it; GRUB bundles
deliberately do not satisfy detected-image dependency keys.

Every additional catalog entry requires documented upstream provenance, license
review, exact version/custom-build compatibility, size and digest review,
explicit user consent, and protection by the same signed reproducible release
process as the application. A host `grub-install` binary is never treated as a
substitute for an image payload such as `core.img`.
