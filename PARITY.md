# Linux / macOS / Windows parity

The native macOS and Windows backends now implement the Linux user workflows,
including the advanced and experimental profiles listed below. Unsupported or
unfinished Linux features remain unsupported; parity does not mean arbitrary
ISOs, arbitrary firmware or Windows To Go are certified.

| Workflow | Implementation and validation |
|---|---|
| Compact interface and media options | Shared visual constants; Auto/DD/ISO, FAT32/NTFS, MBR/GPT, UEFI/BIOS/both, labels, allocation units, persistence and ZIP controls |
| Raw/compressed/sparse/virtual inputs | Bound source staging, mandatory pre-activation read-back and activation-last MBR/GPT; all shared compression types including UNIX `.Z`; VTSI exact-size policy; QEMU conversion and independent comparison |
| Filesystem ISO mode | Portable private-tree extraction, shared path/collision/distro policies, embedded El Torito EFI FAT reconstruction, independently parsed filesystem construction |
| Windows installers | Shared edition/options/XML logic; verified WIM splitting and ESD conversion; exact supported BootEx transform on both native hosts; experimental exact x64 BIOS profile |
| UEFI:NTFS and Syslinux | Pinned shared artifacts/trust rules; exact experimental Syslinux 6.03/6.04 staging, sector mapping, patching and independent read-back |
| Persistence and overlays | Exact Ubuntu 20.04/22.04/24.04 amd64 Casper profiles, shared boot-configuration transforms, ext4 persistence; additive ZIP transforms with reserved-file/collision checks |
| Inspection and planning | Source MD5/SHA-1/SHA-256/SHA-512, complete file catalog, partition/El Torito/bootloader evidence, EFI/Authenticode/DBX reports and read-only target-specific plans |
| Downloads | Shared Ubuntu/Windows/FreeDOS catalogs; pinned signature authority; resumable verified artifacts and FreeDOS archive reuse after cancellation |
| Backup and optical capture | Read-only native descriptors, sparse raw/VHD/VHDX, full independent source reread, no-overwrite publication and changed-media refusal |
| Restore | FAT12/16/32, exFAT, NTFS, UDF, ext2/3/4; MBR/GPT, labels, 512/1024/2048/4096-byte logical sectors and geometry-aware allocation choices; independently checked metadata, Quick and full overwrite paths |
| Zeroing and media tests | Full zero, fast zero, sampled alias/capacity checks, configurable 1–4 address-specific surface passes and combined testing |
| Boot tools | Shared pinned multi-architecture UEFI Shell and experimental GRUB 2.14 rescue profile |
| Settings and diagnostics | Native/portable settings, dark/light orange palettes, SI/IEC units, stable ignored-drive IDs, logs, individual helper-cache controls and preserved elevation state |
| Packaging | Architecture-specific helper executables, provenance/hashes/licenses, declared crypto/filesystem dependencies and offline Windows x86-64/ARM64 runtime bundles |

## Validation

Tests operate on regular files or mock disks and never write physical drives.
The new backend tests cover source/target mutation, failed verification,
cancellation, aliasing, no-overwrite publication, filesystem parsing, boot-sector
patches and GUI settings/elevation behavior. Native CI includes macOS ARM64,
Windows x86-64 and Windows ARM64; Linux CI includes both architectures.

Local validation includes a real 5.1-GB Windows installer ISO through extraction,
customization, actual WIM splitting, independently verified FAT32 construction
and an 8-GiB MBR image; actual Syslinux payload patching; native filesystem
construction with independent parsers; UDF label/root/anchor/CRC checks;
nonzero-content virtual-disk round trips and QCOW2 Zstandard comparisons.
The UNIX compress fixtures cover 10/12/16-bit dictionary growth and CLEAR resets.

The original macOS Windows installer flow was tested on a physical USB and booted
a laptop. Newly expanded workflows still need representative physical USB,
firmware and installation-through testing. Unit/image preparation success is
reported separately from hardware certification. Packages remain unsigned test
builds until signed release distribution and that release testing are complete.
