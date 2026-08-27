# Security policy

ISOpropyl operates on whole block devices, so target selection, privilege boundaries,
download provenance, and archive extraction are treated as security boundaries.

## Reporting

Please report a suspected vulnerability privately through GitHub's security
advisory feature for `codebooker/isopropyl`. Do not include private drive
contents, serial numbers, complete logs, or a working destructive exploit in a
public issue. If the private advisory form is unavailable, open a minimal public
issue requesting a private contact channel without disclosing the vulnerability.

## Current guarantees and limits

- The disk backing `/` is excluded, internal disks are rejected, and fixed USB
  disks are hidden by default.
- Whole-device path, capacity, serial/WWN, model, transport, and major:minor
  identity are bound and revalidated around unmounting and before privileged
  reads, writes, verification, and power-off. Exact UEFI:NTFS layouts also bind
  a freshly observed 512-byte logical-sector size before destructive consent
  and recheck it before partitioning; 4Kn media fail closed.
- Privileged commands use fixed argument arrays; ISOpropyl does not build shell
  text or run downloaded scripts.
- Destructive tools take a nonblocking BSD lock on the whole target for each
  command. This coordinates with systemd-udevd and other lock-aware storage
  software, but Linux locks are advisory: they do not exclude an uncooperative
  privileged writer and are not a transaction-wide ownership lease.
- UEFI ISO mode extracts into a private tree, rejects traversal, links, special
  files and case collisions, atomically publishes staging, then formats and
  copies through an independently identity-bound plan. It supports either one
  FAT32 partition or an exact NTFS plus raw UEFI:NTFS helper layout on
  512-byte-logical-sector media.
- DD, constructed-media, backup, optical-capture, formatting, erasure, and media
  test workers bound retained diagnostic output. Newly audited formatting,
  UEFI:NTFS, WIM, and persistence paths time-bound their local command wrappers
  and use bounded terminate/kill/reap handling; a future dedicated privileged
  helper remains the stronger process-control boundary.
- The boot-artifact catalog contains one release-pinned UEFI:NTFS v2.8 image.
  Network acquisition requires explicit consent; the resolver restricts HTTPS
  origins and redirects, checks exact length and SHA-256, publishes the cache
  atomically, and verifies it again before every use. The privileged writer
  receives already-bound bytes through standard input and never opens a
  user-controlled cache pathname. Cache management considers only exact
  catalog-known paths opened through no-follow directory descriptors; deletion
  skips links, multiply linked files, and anything whose identity or metadata
  changes between inspection and unlink. Corrupt catalog-known regular files
  remain removable so a failed download cannot become permanent cache debris.
- Windows customization can be injected only through the UEFI ISO staging path;
  an existing answer file is never overwritten. A selected WIM/ESD index is
  re-inspected and bound to its source catalog, size, architecture, and edition
  set before `/IMAGE/INDEX` metadata is emitted; ISOpropyl never emits an
  automatic target-disk wipe instruction for Windows Setup.
- A generated local administrator initially has a blank password. ISOpropyl
  emits one sequential first-logon command that requests password replacement
  and applies the chosen expiration policy, but Windows S mode does not run
  FirstLogonCommands and other setup policy can prevent it. The GUI therefore
  treats this account option as an explicit, warned, best-effort customization.
- PE certificate-table and SBAT inspection is structural. ISOpropyl does not yet
  cryptographically establish signer trust or check an authenticated DBX/SVN
  revocation feed.
- Automated device-facing tests use mocks and regular files. Hardware-backed
  write, boot, Secure Boot, cancellation, and failure-recovery testing is still
  required before the alpha label can be removed.
- Diagnostics omit drive identifiers, mount paths, ISO member lists, and logs by
  default. ISOpropyl contains no telemetry.

## UEFI:NTFS trust boundary

The catalog pins `uefi-ntfs.img` from a specific Rufus source commit at exactly
1,048,576 bytes with SHA-256
`72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e`.
ISOpropyl verifies the raw partition with a full privileged read-back after
writing, then rechecks both partition geometry and target identity.

The x64, x86, and ARM64 bridge payloads depend on Microsoft UEFI CA 2011
third-party trust. A valid embedded signature does not guarantee that a machine
will accept it: firmware configuration and DBX revocation policy still apply.
ARM32 is blocked unless a caller explicitly opts into unsigned payloads. The
pinned image's broken RISC-V64 name pair and incomplete LoongArch64 pair are
rejected. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and
license information.

## Supported versions

Security fixes are applied to the current development branch. There is no stable
release series yet; old alpha snapshots may not receive backports.
