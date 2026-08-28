# Third-party notices

ISOpropyl's application code is licensed under AGPL-3.0-or-later. The optional
version-specific boot payload bundles below are not part of the Python package;
the package contains their pinned catalog metadata. The exception is the small
MIT-licensed Syslinux 6.02 MBR bootstrap embedded in `isopropyl/syslinux.py` and
documented in its own section below. UEFI:NTFS and the optional boot-time
corruption validator are obtained only after explicit user consent. GRUB entries
remain dormant preparation inputs. Syslinux bundles have a private-tree/device
consumer, but ordinary writes do not download them; only the explicitly
environment-gated developer preview can request both exact bundle roles after
separate consent.

## Rufus Windows experience command manifest

- Upstream source: Rufus [`src/wue.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L266-L468)
  at commit `2368e49a82e854d3e702f824648cc723953dbb53`
- Boot-file mapping source: Rufus [`src/wue.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/wue.c#L1352-L1415)
  at the same commit, cross-checked against Microsoft's
  [`Make2023BootableMedia.ps1`](https://github.com/microsoft/secureboot_objects/blob/798cdc513e0c192fe90e99637105748ed3bb4ca5/scripts/windows/Make2023BootableMedia.ps1)
- Copyright © 2022–2026 Pete Batard `<pete@akeo.ie>`
- License: GPL-3.0-or-later; the upstream license text is available as
  [`LICENSE.txt`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/LICENSE.txt)

The fixed Windows 11 quality-of-life command selection, order, registry values,
opaque `VisiblePlaces` payload, and installed-system `SkuSiPolicy.p7b` deployment
effect in `isopropyl/windows.py`, plus the reviewed `_EX` boot-file and font
mapping in `isopropyl/windows_bootex.py`, are adapted from that source. For the policy
deployment, ISOpropyl replaces Rufus's fixed `S:` mount with a unique directory
and a `try/finally` cleanup sequence. ISOpropyl represents the manifest in
Python, adds descriptions and noninteractive PowerShell switches, and surrounds
it with independent WIM/ESD gating, disclosure, XML generation, staging identity
checks, and no-wipe validation. The GPL-3.0-or-later option is compatible with
AGPL-3.0-or-later through GPLv3/AGPLv3 section 13. Each covered component retains
its license, and the AGPL network-source requirements apply to the combination.
Rufus and ISOpropyl provide these commands without warranty.

## Fido Microsoft download protocol reference

- Reviewed source: Fido [`Fido.ps1`](https://github.com/pbatard/Fido/blob/3d47260b8915385c58e20c73e24b36e9a9536f3f/Fido.ps1#L593-L812)
  at commit `3d47260b8915385c58e20c73e24b36e9a9536f3f`
- Copyright © 2019–2026 Pete Batard and contributors
- License: GPL-3.0-or-later

Fido's fixed Microsoft request sequence and exact endpoint behavior informed
ISOpropyl's independently written, fail-closed Python resolver. ISOpropyl does
not bundle, download, import, or execute Fido or PowerShell. Microsoft's
`mdt.js` response is handled only as bounded untrusted text and is never
evaluated. The GPL-3.0-or-later reference is compatible with this project's
AGPL-3.0-or-later license through GPLv3/AGPLv3 section 13.

The Windows catalog records public factual release metadata and a SHA-256 from
[Microsoft's Windows 11 download page](https://www.microsoft.com/en-us/software-download/windows11).
Microsoft retains all rights in Windows and its services. ISOpropyl downloads
media directly from Microsoft on the user's machine, does not redistribute it,
does not grant a Windows license, and is not affiliated with or endorsed by
Microsoft. Microsoft's terms apply.

## Ubuntu CD Image signing key

ISOpropyl embeds the public `ubuntu-keyring-2012-cdimage.gpg` keyring solely to
authenticate signed checksum metadata for its explicit curated Ubuntu ISO
download. The keyring is taken byte-for-byte from Ubuntu's official
[`ubuntu-keyring` 2023.11.28.1 source package](https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/),
whose copyright file states that the public keys in `keyrings` do not fall under
copyright. Its SHA-256 is
`192b3782ba2e00e05b6521371fbe67847efad3fdd1cfb87621882d833c8703fa`
and the required signing fingerprint is
`843938DF228D22F7B3742BC0D94AA3F0EFE21092`. The key is data, not executable
code, and no downloaded image or script is executed.

## FreeDOS 1.4 USB images

ISOpropyl contains no FreeDOS media. When the user explicitly starts and
confirms **Download official image… → Download FreeDOS USB image…**, it
downloads one unmodified archive directly
from the [official FreeDOS 1.4 download service](https://www.freedos.org/download/)
for local extraction and use with ISOpropyl's existing guarded DD/raw writer:

- `FD14-LiteUSB.zip`: 17,671,175 bytes, SHA-256
  `857dcd2ebf9d3d094320154db5fb5b830acba6fb98f981a95a0ca7ab3350338b`;
  its exact catalog is `FD14LITE.img`, `FD14LITE.vmdk`, and `readme.txt`.
  The independently reviewed 33,554,432-byte `FD14LITE.img` SHA-256 is
  `f539d456b792594bc3ca59d4e0f4c23d4f1fee73370c1390b2da245400718d36`.
- `FD14-FullUSB.zip`: 668,803,454 bytes, SHA-256
  `cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff`;
  its exact catalog is `FD14FULL.img`, `FD14FULL.vmdk`, and `readme.txt`.
  The independently reviewed 1,073,741,824-byte `FD14FULL.img` SHA-256 is
  `42648c500166de117beb4520968b2eddd4604826fe9284c29959792a19a07d86`.

The outer archive digests are project pins recorded from FreeDOS's
[official checksum page](https://www.freedos.org/download/verify.txt), whose
one exact matching row must still be present after network consent. FreeDOS
does not provide a detached publisher signature for these archives, so that
live HTTPS row corroborates the bundled project pin but does not replace a
signature. ISOpropyl additionally enforces the complete reviewed ZIP catalog,
including member order, type, mode, size, compressed size, and CRC, extracts
only the image member, and verifies the independent inner-image digest before
publication. See the official [FreeDOS 1.4 release report](https://download.freedos.org/1.4/report.html)
and the archive's `readme.txt` for upstream release and license information.

The official images are fixed-size Intel-compatible x86 MBR media for BIOS or
UEFI Legacy/CSM boot. They do not provide native UEFI, Secure Boot, ARM, or
RISC-V support, and ISOpropyl does not enlarge their partitions to consume a
larger drive. The FreeDOS name is used descriptively to identify the upstream
project and its official media. ISOpropyl is independent of, and is not
affiliated with, sponsored by, or endorsed by the FreeDOS Project; all names,
marks, copyrights, and component licenses remain with their respective holders.

## UEFI Shell release payloads

- Upstream release: [UEFI Shell 26H1](https://github.com/pbatard/UEFI-Shell/releases/tag/26H1)
- License: BSD-2-Clause-Patent
- `shellaa64.efi`: 1,093,632 bytes, SHA-256
  `1569b6db4e391c3c59194aa3319a3945efb800fb25349eb9d36ff3d258517ea6`
- `shellia32.efi`: 1,009,408 bytes, SHA-256
  `54ae3a8f58b6fe7123fd948d0773c88e8c26834e39acd3874732c96cbe7c0dd5`
- `shellloongarch64.efi`: 1,230,272 bytes, SHA-256
  `d6c97ae52707ebbad4eda063cb0aefc467ec942b07461a6d6d1119cad0ac3e9c`
- `shellriscv64.efi`: 1,522,752 bytes, SHA-256
  `ccdb9523276d470277f7676d6534916534cd70218ea5c4cc5ac302e149f65196`
- `shellx64.efi`: 1,137,728 bytes, SHA-256
  `4ea080ddd576117cd04f5c02d16712ea5d9249c0752214d8e4055e460d7b11e0`

The Python package includes metadata only; the optional executables are acquired
when the user explicitly starts and confirms **Create UEFI Shell…**. Normal image
writes never acquire them. The unmodified executables are not Secure Boot signed
and require Secure Boot disabled; ISOpropyl does not claim certificate-chain or
Secure Boot trust for them.

## UEFI boot-time media validator

- Upstream release: [uefi-md5sum v1.2](https://github.com/pbatard/uefi-md5sum/releases/tag/v1.2)
- Exact source snapshot:
  [`6195f2ef`](https://github.com/pbatard/uefi-md5sum/tree/6195f2ef754c2ad390bda6590628708f410d55f6)
- License: GPL-2.0-or-later
- `bootaa64_signed.efi`: 50,704 bytes, SHA-256
  `799b64e8d32cbe5829b2f81c96a1a4936935da31df7ce70c0e6ae68ffdaf23bd`
- `bootarm.efi`: 27,232 bytes, SHA-256
  `10eadb8e80f446ebd62568f9275d6a328cfdc399ef8b2ee71857c3d2f7134f28`
- `bootia32_signed.efi`: 40,280 bytes, SHA-256
  `089190606ad0e16b58b208aa262533c941f11a9a27a48fade672efcca3a720c1`
- `bootloongarch64.efi`: 35,712 bytes, SHA-256
  `0085afb9ca64ac5f922b21d541344b3ff140e13acf596041ff6ce7b7d71c229e`
- `bootriscv64.efi`: 38,656 bytes, SHA-256
  `3e53e975fad71c7e30ac35bfc83ba5b31fad7e6d9deaaee14f77dab820ed2c7a`
- `bootx64_signed.efi`: 40,536 bytes, SHA-256
  `9b0b326ca3da0693fc99789f73e548c3dc69a2cd654bd7abcd1a92ba900878cc`

The executables are downloaded only after the user explicitly enables and
confirms boot-time corruption checking. They are frozen into immutable bytes
after exact size, SHA-256, PE architecture, EFI subsystem, and signature-table
state checks, and are never executed on Linux. The x64, x86, and ARM64 files are
the upstream Secure-Boot-signed variants; firmware acceptance still depends on
Microsoft UEFI CA 2011 third-party trust and revocation state. ARM32, RISC-V64,
and LoongArch64 are unsigned and require Secure Boot disabled.

The generated on-media `md5sum.txt` is intentionally compatible with upstream
uefi-md5sum and detects accidental media damage at boot. MD5 and this unsigned
local manifest do not authenticate the image, resist malicious replacement, or
provide verified boot. Upstream validation can be cancelled, a reported
mismatch can be bypassed by the person at the machine, and a missing or malformed
manifest does not prevent chainloading. Corresponding source and build/test
instructions are available at the exact source snapshot linked above.

## Python Authenticode analysis

- [Signify 0.9.2](https://pypi.org/project/signify/), licensed MIT, is used to
  parse and verify Authenticode integrity in the isolated analysis worker. The
  complete resolved backend is pinned: `asn1crypto` 1.5.1, `certvalidator`
  0.11.1, and `oscrypto` 1.3.0 are MIT; `typing_extensions` 4.16.0 is PSF-2.0;
  and `mscerts` 2026.7.1 is MPL-2.0.
- Dependency license files must be retained by downstream bundles. Because the
  `certvalidator` 0.11.1 wheel omits its license file, ISOpropyl carries the
  upstream copyright and MIT text in
  [`licenses/CERTVALIDATOR-MIT.txt`](licenses/CERTVALIDATOR-MIT.txt).
- ISOpropyl applies a narrow runtime compatibility shim while importing the
  pinned `oscrypto` 1.3.0 backend. It changes only that release's exact
  single-digit OpenSSL/LibreSSL version-pattern lookup so host versions such as
  OpenSSL 3.0.16 and LibreSSL 3.10.2 can be recognized, then restores Python's
  standard regex functions before parsing any inspected data. No oscrypto source
  file is redistributed or modified in place.

Signify normally offers a Microsoft certificate store through `mscerts`, but
ISOpropyl never passes that store to verification. It supplies only the
certificates embedded in the inspected signature, disables fetching, and labels
success as integrity-valid-untrusted. This is not a Microsoft, firmware,
revocation, timestamp, DBX, or Secure Boot trust decision.

## Microsoft Secure Boot DBX image-hash snapshot

- Upstream release: [`secureboot_objects` v1.6.5](https://github.com/microsoft/secureboot_objects/releases/tag/v1.6.5)
- Exact source commit: [`798cdc513e0c`](https://github.com/microsoft/secureboot_objects/tree/798cdc513e0c192fe90e99637105748ed3bb4ca5)
- Canonical source: [`PreSignedObjects/DBX/dbx_info_msft_latest.json`](https://github.com/microsoft/secureboot_objects/blob/798cdc513e0c192fe90e99637105748ed3bb4ca5/PreSignedObjects/DBX/dbx_info_msft_latest.json)
- Source size: 394,305 bytes
- Source SHA-256:
  `1020f0ef865f8cf22740298d928a01355ab51cb1d8d473b637fd6d83f74eb3f5`
- License: BSD-2-Clause-Patent; the retained complete text is in
  [`licenses/MICROSOFT-SECUREBOOT-OBJECTS-BSD-2-CLAUSE-PATENT.txt`](licenses/MICROSOFT-SECUREBOOT-OBJECTS-BSD-2-CLAUSE-PATENT.txt)

ISOpropyl's package contains a deterministic compact projection, not Microsoft's
signed DBX update binaries: 389 entries without an `isOptional` flag and 284
entries marked optional, all SHA-256 Authenticode image hashes, separated across
x64, IA32, AArch64, and ARM exactly as published. Arrays are lowercase, sorted,
and retain architecture scope; one source hash occurs in both the x64 and IA32
groups and is preserved in both. The compact JSON's independently
pinned SHA-256 is
`7019eb890a75e0ab3a1ff8e137ee66c6bc4f40644ddfc216fd0fdb74e7926874`.

This snapshot is used only for offline advice. It does not represent the selected
machine's installed firmware DBX, and ISOpropyl does not claim that an unlisted
image is safe or that a listed image is present in every firmware policy.

## UEFI:NTFS boot helper

- Artifact: `uefi-ntfs.img`
- Upstream snapshot: Rufus commit
  [`2368e49a`](https://github.com/pbatard/rufus/tree/2368e49a82e854d3e702f824648cc723953dbb53/res/uefi)
- ISOpropyl catalog name: `2.8-rufus-2368e49a`
- Exact size: 1,048,576 bytes
- SHA-256:
  `72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e`
- Image contents and build notes:
  [Rufus `res/uefi/readme.txt`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/res/uefi/readme.txt)

The image contains several independently licensed Free Software components:

- [UEFI:NTFS 2.8](https://github.com/pbatard/uefi-ntfs/tree/v2.8), licensed
  GPL-2.0-or-later. ISOpropyl's normal x64, x86, and ARM64 path uses its signed
  chain-loader binaries.
- [ntfs-3g UEFI drivers](https://github.com/pbatard/ntfs-3g), licensed under
  GPLv2. These are used for the supported NTFS path.
- [EfiFs drivers](https://github.com/pbatard/efifs), licensed under GPLv3.
  These are present in the upstream image for other filesystem/architecture
  combinations but are not selected by ISOpropyl's normal NTFS GUI path.

Before a target write, ISOpropyl binds the selected architecture's bridge and
NTFS driver to fixed offset, length, and SHA-256 records inside this exact
whole-image digest, then applies the same offline Microsoft DBX image-hash
advice used for staged EFI files. This is not a certificate-chain, live
firmware-policy, or Secure Boot acceptance verdict.

Copyright remains with the respective upstream authors and contributors. The
components are provided without warranty under their licenses. Corresponding
source and license texts are available from the linked repositories. ISOpropyl
does not modify the downloaded image.

## Syslinux payload bundles

- Cataloged exact builds: `6.03-2014-10-06` and `6.04-pre1`
- Artifacts: matching `ldlinux.bss` and `ldlinux.sys`; separately cataloged
  `ldlinux.c32` for each exact build's blank-media groundwork
- Immutable catalog snapshot: Rufus web commit
  [`e6e2182d`](https://github.com/pbatard/rufus-web/tree/e6e2182d325ae95ac15166ea2ee750cebccff3c1/files)
- Upstream provenance: the snapshot readmes identify the
  [official Syslinux archives](https://www.kernel.org/pub/linux/utils/boot/syslinux/)
- License: GPL-2.0-or-later, as identified by Rufus's bundled license notice

Each file has its own exact size and SHA-256 in `bootloaders-v2.json`. A matched
bundle is accepted only when every named artifact resolves at the same exact
version. ISOpropyl does not use Rufus's version-suffix or prefix fallback.
The pure staging policy in `isopropyl/syslinux_staging.py` independently
re-pins each exact `ldlinux.c32` size, SHA-256, license, and provenance. It also
re-pins both matched BIOS artifacts and the final unpatched root `ldlinux.sys`
size/SHA-256 after the two exact blank ADV sectors are appended. The optional
private-tree consumer requires both same-version bundle roles and materializes or
validates the C32 module and unpatched root file as data only after source and
extracted-tree validation; neither component executes a downloaded payload on
the Linux host.
The private-tree root alone is not a boot claim. The separate anonymous
regular-file transaction performs the FAT location patch and VBR/MBR writes.
Its block-device path is default-off and available only through the warned
`ISOPROPYL_EXPERIMENTAL_SYSLINUX=1` developer workflow.

The device-free Syslinux 6.03 certificate additionally pins the official
`syslinux-6.03.tar.xz` archive at SHA-256
`26d3986d2bea109d5dc0e4f8c4822a459276cf021125e8c9f23c3cca5d8c850e`
and independently pins `isolinux.bin`, `ldlinux.bss`, `ldlinux.sys`, and
`ldlinux.c32` inside it. The certification harness requires the three prepared
catalog artifacts to byte-match those official source-release members before it
builds and boots a sealed private image. The source archive is evidence input
only and is not shipped in the Python package.

The backend implementation in `isopropyl/syslinux.py` adapts the on-disk
ADV, extent, patch-area checksum, first-sector-pointer, and FAT VBR merge formats
from Syslinux's GPL-2.0-or-later installer and Rufus's corresponding integration:
[`setadv.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/syslinux/libinstaller/setadv.c),
[`syslxmod.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/syslinux/libinstaller/syslxmod.c),
[`fs.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/syslinux/libinstaller/fs.c),
and [`syslinux.c`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/syslinux.c).
It also embeds the 440-byte Syslinux 6.02 `mbr.bin` bootstrap identified by
Rufus's ms-sys integration at pinned
[`mbr_syslinux.h`](https://github.com/pbatard/rufus/blob/2368e49a82e854d3e702f824648cc723953dbb53/src/ms-sys/inc/mbr_syslinux.h),
SHA-256 `4746f74bc9b9d3d579c41988a4a29bb7ac932ad1c70470ea779ea161eb799b64`.
An independent rebuild from official Syslinux 6.02 commit `67aaaeeb` using the
immutable [`mbr.S`](https://git.kernel.org/pub/scm/boot/syslinux/syslinux.git/plain/mbr/mbr.S?id=67aaaeeb22832a0b82e5043877d26d1a9602bf2a)
and [`adjust.h`](https://git.kernel.org/pub/scm/boot/syslinux/syslinux.git/plain/mbr/adjust.h?id=67aaaeeb22832a0b82e5043877d26d1a9602bf2a)
sources produced the same bytes; the official `syslinux-6.02.tar.xz` release
archive has SHA-256
`afa31b7cbf72e1c0c1752a0636ba724ce01c0e374366e46e61db6862b4685478`.
The corresponding `mbr/mbr.S` and `mbr/adjust.h` source files carry their own
MIT permission grant; its exact copyright and permission notice is reproduced
in [`licenses/SYSLINUX-MBR-MIT.txt`](licenses/SYSLINUX-MBR-MIT.txt).
ISOpropyl replaces only the bootstrap region and preserves the existing MBR
metadata tail.
ISOpropyl reimplements those formats in Python with stricter consumer-local
hash/provenance pins, overlap and width checks, a descriptor-only FAT32 mapper,
and an anonymous regular-file transaction with ordered durability barriers,
complete read-back, and whole-image pre/post hashes. No version-specific `ldlinux` payload
is included in the Python package or wheel; the small MIT-licensed MBR bootstrap
is. The full GPL-2.0 text and source-release archives are available from the
[official Syslinux distribution](https://www.kernel.org/pub/linux/utils/boot/syslinux/),
while the exact acquired binary provenance remains pinned to the immutable Rufus
web snapshot above. No downloaded payload is executed on Linux, and no
ordinary device-facing BIOS path is enabled. The GPL-2.0-or-later payloads may be used
under their GPL-3.0-or-later option, which is compatible with
AGPL-3.0-or-later through GPLv3/AGPLv3 section 13. Each covered component retains
its license, and the AGPL network-source requirements apply to the combination.

## GRUB BIOS core-image bundles

- Cataloged builds: GRUB 2.06, 2.12, and 2.14 `core.img`
- Immutable catalog snapshot: Rufus web commit
  [`e6e2182d`](https://github.com/pbatard/rufus-web/tree/e6e2182d325ae95ac15166ea2ee750cebccff3c1/files)
- Build provenance and module/prefix details:
  [2.06](https://github.com/pbatard/rufus-web/blob/e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/grub-2.06/readme.txt),
  [2.12](https://github.com/pbatard/rufus-web/blob/e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/grub-2.12/readme.txt), and
  [2.14](https://github.com/pbatard/rufus-web/blob/e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/grub-2.14/readme.txt)
- Upstream release archives: [GNU GRUB](https://ftp.gnu.org/gnu/grub/). The
  cataloged files were assembled by Rufus with the module/prefix choices in the
  pinned readmes; ISOpropyl does not yet host a reproducible, project-owned
  corresponding-source build for those exact bytes.
- License: GPL-3.0-or-later

These images are not generic replacements for a distribution's GRUB build.
ISOpropyl never truncates an exact downstream build identifier to make a catalog
entry fit, and does not yet write these payloads to media.
