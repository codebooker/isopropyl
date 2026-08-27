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
  and recheck it before partitioning; 4Kn media fail closed. Restore formatting
  binds and repeatedly rechecks a supported 512/1024/2048/4096-byte logical
  sector size before unmounting and filesystem creation (FAT12/16 narrow that
  set to 512/4096), and validates any explicit allocation size against the exact
  resulting partition geometry. A full-capacity MBR plan must also fit its
  32-bit start/count sector fields; otherwise it is rejected before unmounting
  and the restore dialog selects GPT when reported geometry makes that conclusion
  possible. Missing sector metadata remains provisional until the pre-unmount
  discovery check.
- The image pathname selected in the UI is bound by device, inode, size, mtime,
  and ctime to the completed inspection, rechecked after final DD consent, and
  passed as an expected identity into the writer's one `O_NOFOLLOW` descriptor.
  Raw and compressed bytes are streamed from that descriptor, never reopened by
  privileged `dd`; external decoders receive only a passed `/proc/self/fd`
  handle. Descriptor metadata is checked after every read and before its bytes
  are yielded. Compressed inspection has cooperative cancellation, a five-minute
  limit checked between in-process decoder reads and while waiting for external
  decoder output, a 64 TiB expanded-size ceiling, bounded prefix/tail capture,
  and a pre-parse ZIP central-directory bound. Decoder-library working memory and
  the duration of one in-process decoder call are not represented as globally
  bounded. Destructive decompression is bounded by the selected target. Legal
  middle metadata outside the capture is reported as incomplete and is never
  automatically recommended for DD.
- A compressed VHD/VHDX/QCOW/QCOW2 source retains that bound outer descriptor
  while exactly one wrapper is decoded into an `O_EXCL`, mode-0600 regular file
  inside a mode-0700 private directory. The decoded container is limited to
  64 GiB; decoding and raw conversion each preserve a 64 MiB staging-filesystem
  reserve. The decoded file is fsynced and must
  remain single-linked with an exact descriptor/path identity. `qemu-img`
  inspection and raw conversion receive only inherited `/proc/self/fd` handles;
  the confirmed outer identity, filename-implied format, detected qemu format,
  and guest-visible size are rebound before writing. Backing, encryption,
  corruption, nested compression, multiple ZIP members, and suffix/format
  disagreement fail closed. Cancellation terminates and reaps qemu inspection
  or conversion, and cleanup removes only the exact private files and
  directories allocated by the operation. Closing the window during inspection
  is deferred until the worker acknowledges that cancellation cleanup finished.
- VTSI v1.0 sources use the same single, no-follow descriptor and add link
  count to their immutable identity. The parser accepts only the exact 512-byte
  footer/table layout, zero reserved bytes and padding, valid footer and table
  checksums, 1–128 in-range segments with contiguous catalog-order source data,
  and non-overlapping disk extents. Official non-monotonic disk order is
  preserved; overlap rejection is ISOpropyl's additional fail-closed policy.
  The footer disk-signature field is treated as opaque metadata, not an integrity
  or provenance check. Random reads and the
  destructive stream synthesize zero gaps without allocating the declared disk;
  source identity and cancellation are checked around every bounded read. A VTSI
  restore is offered only when the selected drive capacity exactly equals the
  expanded disk size and it freshly reports 512-byte logical sectors. Those
  constraints are rechecked before and after unmounting and after the write, and
  GUI full read-back verification is mandatory. The VTSI checksums cover only
  its footer and segment table—not stored disk payload bytes or authorship—so
  read-back proves restoration fidelity, not provenance. This does not yet
  constitute physical Ventoy boot certification.
- Checksum calculation separately opens the inspected image once with
  `O_NOFOLLOW`, requires its bound device/inode/size/mtime/ctime identity, and
  revalidates descriptor metadata around every read plus the pathname at EOF.
  It is cancellable before and between reads. Image reselection invalidates its
  generation token, so stale progress or completion cannot publish a digest or
  tear down a newer operation. MD5 and SHA-1 are included only for comparison
  with legacy provider manifests; prefer SHA-256 or SHA-512 for trust decisions.
- A structurally valid MBR/GPT image whose logical-sector interpretation differs
  from the discovered target is not automatically recommended for DD; neither is
  structured DD when the target omits logical-sector metadata. An expert exact
  copy remains available only after a specific compatibility warning. Plain MBR
  comparisons are explicitly the conventional assumed 512-byte interpretation.
- Privileged commands use fixed argument arrays; ISOpropyl does not build shell
  text or run downloaded scripts.
- Read-only ISO/UDF catalog inspection invokes only trusted-path `7z`, passes a
  bound image descriptor through `/proc/self/fd`, caps listing output at 16 MiB
  and 65,536 members, observes image-reselection cancellation and a 20-second
  deadline, and uses bounded terminate/kill/reap cleanup.
- A failed unmount may trigger an optional, unprivileged, three-second `fuser`
  probe with a fixed argument vector. Two snapshots share one deadline and pipe
  reads stop as soon as their combined output reaches 64 KiB. Results are limited
  to stable visible PIDs plus descriptor-bound `/proc` process names and numeric
  UIDs; command lines are not displayed, and ISOpropyl never asks `fuser` to
  signal or kill an owner process. Probe failure never replaces the original
  unmount error.
- Destructive tools take a nonblocking BSD lock on the whole target for each
  command. This coordinates with systemd-udevd and other lock-aware storage
  software, but Linux locks are advisory: they do not exclude an uncooperative
  privileged writer and are not a transaction-wide ownership lease.
- UEFI ISO mode extracts into a private tree, rejects traversal, links, special
  files and case collisions, atomically publishes staging, then formats and
  copies through an independently identity-bound plan. It supports either one
  FAT32 partition or an exact NTFS plus raw UEFI:NTFS helper layout on
  512-byte-logical-sector media.
- Distro compatibility exclusions come from one bundled, strict, versioned JSON
  catalog and perform no network access. Matching uses only the complete,
  identity-bound original ISO member catalog: never the host filename, volume
  label, ZIP overlay, or effective merged catalog. Current predicates require
  exact regular-file structure for Manjaro, Proxmox, and Pop!_OS and are
  deliberately narrower than the motivating Rufus path heuristics; Unicode
  compatibility characters do not alias ASCII markers. Normalization ambiguity,
  malformed policy data, or unsafe member evidence blocks ISO mode.
  Staging relists the descriptor-bound source before extraction, requires the
  complete catalog to match exactly, and seals that result into the validated
  staging plan. Source and extraction bindings include device, inode, size,
  mtime, and ctime; executor validation checks the witness and rederives the policy.
  A match can only subtract filesystem-aware ISO mode and does not establish
  that DD is bootable, safe for the target geometry, or recommended.
- ZIP overlays are untrusted installer/media content, not authenticated
  software. SHA-256 binds the exact selected archive across planning and staging
  but establishes no publisher or provenance trust; its files can intentionally
  alter the resulting booted environment.
- One no-follow, singly linked regular overlay ZIP is limited to 8 GiB compressed
  and expanded, 4,096 members, 16 MiB central/local metadata, and a 65,536-entry
  effective catalog. Only classic/ZIP64 stored or deflated files/directories are
  accepted. Encryption, multidisk/SFX archives, NUL/parser disagreement,
  overlaps, unexplained records, traversal, links, special files, FAT-unsafe
  aliases, collisions, and reserved fallback/install payloads fail closed.
  Directories may merge; files never overwrite. Extraction uses canonical target
  paths, no-follow descriptors, exclusive creation, CRC/size/source-identity
  checks, and a final exact staging scan. Permissions, ownership, links, and ZIP
  timestamps are not imported. Cancellation and deadlines are cooperative
  between decoder reads; one in-process deflate read is not preempted.
- ISO/UDF modification times are untrusted metadata. ISOpropyl accepts only a
  conservative timezone-safe FAT-compatible UTC range from the bounded catalog,
  carries the value in the catalog digest, and applies file and explicit-directory
  times only through already-open no-follow descriptors. Directories are applied
  after their descendants and restored after private WIM/customization mutations.
  A coarse temporary workspace may normalize by less than FAT's two-second tick;
  the first observed value is then identity-bound and carried forward. Every
  staging time is checked for portable representability before a target changes.
  The destination may normalize by less than its FAT32 or NTFS tick, after which
  read-back must match the observed value exactly. Link times, ownership,
  permissions, and other archive attributes are never imported.
- DD, constructed-media, backup, optical-capture, formatting, erasure, and media
  test workers bound retained diagnostic output. Newly audited formatting,
  UEFI:NTFS, WIM, and persistence paths time-bound their local command wrappers
  and use bounded terminate/kill/reap handling; a future dedicated privileged
  helper remains the stronger process-control boundary.
- The boot-artifact catalog contains the release-pinned UEFI:NTFS v2.8 image,
  dormant exact Syslinux `6.03-2014-10-06`/`6.04-pre1` payload sets, and GRUB
  2.06/2.12/2.14 blank-media research bundles, plus the exact upstream UEFI
  Shell 26H1 AA64, IA32, LoongArch64, RISC-V64, and X64 release set and the exact
  six-architecture `uefi-md5sum` v1.2 runtime-validation set. It records
  immutable upstream
  URLs, exact length, SHA-256, purpose-specific bundle membership, license, and
  provenance. Generic bundle preparation has cancellation, aggregate progress,
  a shared connection/download/cache-read/binding deadline, exact-version
  matching, and no partial return; every cache directory and object is opened
  no-follow, the parent pathname is revalidated against its bound descriptor,
  and every stable singly linked regular file is rehashed and frozen as immutable
  bytes. GRUB entries never satisfy a detected-image dependency. No production
  BIOS executor consumes these bundles. The UEFI Shell backend independently
  rechecks the five exact hashes and sizes, PE architecture, EFI application
  subsystem, and unchanged unsigned state before it can create a new mode-0700
  private staging tree. It writes canonical fallback names through no-follow,
  exclusive descriptors, handles short writes, and returns a manifest only
  after an exact descriptor-based hash/identity pass. Its GUI requires explicit
  network consent, hands only the bound private tree and selected target to the
  constructed-media planner, and requires the exact displayed `WRITE /dev/…`
  phrase before its GPT/FAT32 write. Every copied file is read back. The upstream
  Shell files are unsigned and require Secure Boot disabled. No downloaded
  executable or script runs on Linux, and version-prefix fallback is
  forbidden. The working UEFI:NTFS path separately requires explicit consent;
  its resolver restricts HTTPS origins and redirects, checks exact length and
  SHA-256, publishes the cache atomically, and verifies it again before every
  use. Its privileged writer receives already-bound bytes through standard input
  and never opens a user-controlled cache pathname. Cache management considers
  only exact
  catalog-known paths opened through no-follow directory descriptors; deletion
  skips links, multiply linked files, and anything whose identity or metadata
  changes between inspection and unlink. Corrupt catalog-known regular files
  remain removable so a failed download cannot become permanent cache debris.
- The curated Linux downloader is network-inactive until the user chooses
  **Download Linux…**, a catalog entry, an exact destination filename, and final
  consent. The initial catalog pins Ubuntu 24.04.4 LTS Desktop amd64 plus the
  exact release URL, size, SHA-256, signed checksum manifest, detached signature,
  and Ubuntu CD Image signing fingerprint. A fixed root-owned `gpgv` is invoked
  through an inherited descriptor with a bundled hash-pinned official public
  keyring; the signed manifest must name the exact ISO exactly once. HTTP status,
  final URL, content encoding, lengths, and resume ranges are strict. A bounded
  private `0700` stage retains only a `0600`, singly linked partial; free space,
  cancellation, source/destination identities, a final full descriptor hash,
  and no-overwrite publication are rechecked. Downloaded bytes are data only and
  are never executed. Catalog expansion requires new distribution-owned signing
  provenance rather than mirror trust or remote scripts.
- Windows customization can be injected only through the UEFI ISO staging path;
  an existing answer file is never overwritten. A selected WIM/ESD index is
  re-inspected through one inherited no-follow descriptor and bound to its exact
  source catalog path, size, architecture, edition set, ctime, and link count
  before `/IMAGE/INDEX` metadata is emitted. Nested or multi-source WIM answer
  files also receive an `InstallFrom/Path` value validated against that catalog;
  a forged path, alias, stale result, or ambiguous ESD selection fails closed.
  The staging plan retains the frozen typed customization and generator
  architecture, regenerates the complete answer file before extraction, and
  requires exact UTF-8 byte equality; structurally valid extra commands,
  comments, or whitespace changes are rejected. The fixed `BypassNRO` command
  contains no user-derived text and is enabled only for an explicitly selected,
  recognized non-Home x64/ARM64 Windows 11 build in the 21H2–24H2 allowlist.
  Home, x86, newer, unknown, and obvious normalized English S-mode/cloud markers
  fail closed. WIM metadata cannot prove the absence of a localized or
  offline-serviced S-mode policy, so the GUI requires a separate explicit
  acknowledgment of that residual uncertainty before it can emit the command.
  The separate Fast Startup option emits only the fixed machine-level
  `HiberbootEnabled=0` registry command during `specialize`; it is default-off
  and discloses that full shutdowns may make startup slower.
  This is an ISOpropyl construction invariant, not a claim that every unusual
  booted Windows Setup launch context has been physically certified. ISOpropyl
  never emits an automatic target-disk wipe instruction for Windows Setup.
- A generated local administrator initially has a blank password. ISOpropyl
  emits one sequential first-logon command that requests password replacement
  and applies the chosen expiration policy, but Windows S mode does not run
  FirstLogonCommands and other setup policy can prevent it. The GUI therefore
  treats this account option as an explicit, warned, best-effort customization.
- PE certificate-table and SBAT parsing remains structural. For exactly one
  revision-2 PKCS#7 `WIN_CERTIFICATE`, ISOpropyl additionally passes the same
  bounded in-memory PE bytes through a sealed Linux memory file to an isolated
  Python worker. Before parsing arguments or PE bytes, that isolated interpreter
  checks the exact pinned dependency set and lets oscrypto resolve the host
  `libcrypto`; this cold-start step may use a short-lived local library probe.
  During that trusted, single-threaded import only, ISOpropyl widens oscrypto
  1.3.0's exact single-digit OpenSSL/LibreSSL version regex to accept multi-digit
  numeric components. The standard regex functions are restored in a `finally`
  block before any PE or PKCS#7 parsing, and every unrelated lookup is unchanged.
  It then applies CPU, address-space, file, descriptor, and no-descendant-process
  limits before accepting the PE. Verification is limited to 256 MiB PE input,
  8 MiB PKCS#7 data, 32 embedded certificates, SHA-256/384/512, one
  embedded/nested signature, eight seconds, and bounded output. Cancellation and
  the ISO inspection's overall deadline terminate and reap it. The limited
  worker independently revalidates the PE Security Directory and
  `WIN_CERTIFICATE` framing before Signify checks the file digest, signer
  signature, current certificate validity, code-signing EKU, and optional
  digital-signature key usage.
- A successful check is always `integrity-valid-untrusted`. Its temporary
  certificate store contains only certificates embedded in that signature;
  Signify's Microsoft root store is never consulted, network fetching is
  disabled, and countersignatures/signing timestamps and revocation are not
  evaluated. The result is presentation-only and cannot change the structural
  `present-unverified` state, ISO plan, payload trust class, Secure Boot warning,
  unsigned-payload consent, or write authorization. ISOpropyl does not yet
  authenticate Microsoft/firmware roots or a DBX/SVN revocation feed, and a
  matching integrity result does not predict firmware acceptance.
- Automated device-facing tests use mocks and regular files. Hardware-backed
  write, boot, Secure Boot, cancellation, and failure-recovery testing is still
  required before the alpha label can be removed.
- Diagnostics omit drive identifiers, mount paths, ISO member lists, and logs by
  default. ISOpropyl contains no telemetry.

## Boot-time corruption-check boundary

The default-off boot-time option is deliberately narrower than its payload
bundle. The GUI enables it only for an executable native UEFI/FAT32 ISO plan
with a recognized removable-media fallback loader. Casper/Ubuntu trees,
persistence, UEFI:NTFS, and an additive overlay that supplies root
`md5sum.txt` are excluded until separately certified. Declining the explicit
network-and-limitations prompt aborts the requested write. At dispatch, an
ineligible check that remains selected aborts rather than being silently
omitted; ordinary mode or option changes visibly clear the now-incompatible
checkbox.

After extraction, overlays, WIM splitting, and Windows answer-file generation
finish in a private tree, ISOpropyl freshly rescans that tree through no-follow
directory descriptors. Links, special files, hardlinks, cross-device entries,
case/Unicode aliases, unsafe names, parser-limit violations, identity drift,
pre-existing chainload originals, and malformed or architecture-mismatched EFI
fallback loaders fail closed. Every recognized loader is preserved as its
canonical `boot*_original.efi`; the matching immutable v1.2 wrapper replaces
the fallback name. A failure after the first mutation invalidates the entire
private workspace, so no partial result can reach target planning.

ISOpropyl then replaces lowercase root `md5sum.txt` with a deterministic final
manifest. It covers ordinary final files and renamed original loaders, excludes
the manifest and wrapper applications themselves, and treats uppercase
`MD5SUMS` as an ordinary covered file. The implementation enforces the upstream
64 MiB, 100,000-line, and path limits; hashes every covered file through a bound
descriptor; performs a fresh post-hash tree rescan; verifies every recorded MD5
again before returning a stage witness; and repeats that validation before the
constructed-media planner rescans the tree. The finished USB still receives
ISOpropyl's stronger mandatory per-file SHA-256 read-back.

This feature is not verified boot or image authentication. MD5 is
collision-broken, the manifest is unsigned and writable beside the content,
and an attacker able to alter the USB can replace both. The firmware application
also intentionally permits bypass/fail-open paths: missing or malformed
manifests and user cancellation chainload the original loader, while validation
errors can be continued past. Signed x64, x86, and ARM64 wrappers still depend
on Microsoft UEFI CA 2011 third-party trust and current firmware/DBX policy;
ARM, RISC-V64, and LoongArch64 wrappers are unsigned and require Secure Boot
disabled. The option is useful only for detecting accidental damage on later
boots and adds boot latency.

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
