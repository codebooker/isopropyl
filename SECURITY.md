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
  reads, writes, verification, and power-off.
- Privileged commands use fixed argument arrays; ISOpropyl does not build shell
  text or run downloaded scripts.
- UEFI ISO mode extracts into a private tree, rejects traversal, links, special
  files and case collisions, atomically publishes staging, then formats and
  copies through an independently identity-bound plan. It currently supports
  one FAT32 partition only.
- DD, constructed-media, backup, optical-capture, formatting, erasure, and media
  test workers terminate privileged children on cancellation and bound retained
  diagnostic output.
- The boot-artifact catalog is empty. No boot component is downloaded or executed.
- Windows customization can be injected only through the UEFI ISO staging path;
  an existing answer file is never overwritten.
- PE certificate-table and SBAT inspection is structural. ISOpropyl does not yet
  cryptographically establish signer trust or check an authenticated DBX/SVN
  revocation feed.
- Automated device-facing tests use mocks and regular files. Hardware-backed
  write, boot, Secure Boot, cancellation, and failure-recovery testing is still
  required before the alpha label can be removed.
- Diagnostics omit drive identifiers, mount paths, ISO member lists, and logs by
  default. ISOpropyl contains no telemetry.

## Supported versions

Security fixes are applied to the current development branch. There is no stable
release series yet; old alpha snapshots may not receive backports.
