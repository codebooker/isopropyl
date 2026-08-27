# Third-party notices

ISOpropyl's application code is licensed under AGPL-3.0-or-later. The optional
boot artifact below is not part of the Python package: ISOpropyl obtains it only
after explicit user consent, verifies pinned metadata, and writes the verified
bytes to the selected medium.

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
