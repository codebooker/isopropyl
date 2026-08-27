# Third-party notices

ISOpropyl's application code is licensed under AGPL-3.0-or-later. The optional
boot artifacts below are not part of the Python package. The package contains
only pinned catalog metadata. UEFI:NTFS is obtained only after explicit user
consent. The GRUB and Syslinux entries are dormant preparation inputs: normal
writes do not download them and no BIOS executor consumes them yet.

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
