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
- The image pathname selected in the GUI or CLI is bound by device, inode, size, mtime,
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
- A supported embedded El Torito EFI image is parsed directly from the same
  no-follow, five-field identity-bound ISO descriptor. The accepted subset is
  one bootable EFI/no-emulation image containing either direct FAT12/16/32 or an
  active first FAT partition in an otherwise empty MBR wrapper. The parser
  bounds filesystem/FAT/directory sizes, entries, depth, paths, and clusters;
  requires FAT copies to match when multiple are present; validates BPB geometry,
  VFAT chains, portable aliases, cluster chains, cross-links, and ISO/catalog
  overlap; and hashes every file. Sector counts 0/1 are expanded only from
  validated filesystem geometry.
  Planning, execution, and final-tree validation independently recheck source
  identity, the El Torito/FAT manifest, file hashes, and the no-overwrite merge.
  Unsupported, ambiguous, multiple-image, non-FAT, hard-disk-emulation, or
  colliding layouts do not silently contribute files and leave relevant UEFI or
  DBX evidence incomplete.
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
- The Windows To Go WIM-apply backend is currently a device-free certification
  primitive, not a device writer. It accepts only a fresh owner-only, unlinked
  regular-file NTFS image and rejects block devices. The descriptor owner is
  non-dumpable, the target is held under an advisory lock, the source is held
  under a kernel read lease, both inherited descriptors and the complete
  source/fresh-target digests are re-attested with cancellation and attestation
  deadlines, primary and backup NTFS boot sectors are frozen, and wimlib runs in
  a new process group with a fixed argv, allowlisted environment, bounded
  diagnostics, descendant-aware terminate/kill/reap, and
  failure-as-contamination semantics. The opt-in certification first drops and
  then rejects all active capability sets, sets Linux `no_new_privs`, rejects
  set-ID or file-capability-bearing tools and any real/effective/saved/fs root
  UID, proves an empty fresh root, reads the exact applied fixture bytes
  through ntfs-3g, and verifies clean NTFS metadata before and after. It does not
  claim resistance to a hostile same-UID process attacking the short-lived
  external tool. None of this authorizes physical media: privileged topology,
  mount, GPT/NTFS, PREPARED → COMMIT, cancellation-recovery, and physical-boot
  gates remain unimplemented.
- The Windows BCD oracle module is a non-authorizing evidence contract, not an
  editor or trust decision. It accepts only canonical, bounded
  JSON; models BCD values with their actual registry kinds; derives references,
  boot paths, devices, inheritance, and recovery-disabled byte `00` from typed
  elements; binds a disposable fresh-store GPT layout and hash-verified Microsoft
  tool transcripts; and requires a four-run one-GUID-at-a-time differential
  cohort. The four-capture tool's optional read-only verifier accepts caller-pinned
  readable regular-file descriptors, duplicates without seeking or reopening
  them, copies each source into a sealed anonymous memfd, invokes hivex with
  writing and unsafe parsing disabled, and rechecks source identity plus a
  complete SHA-256 before publishing detached typed evidence. A separate
  no-follow path entry point uses the same sealed-snapshot core. The tool
  validates the whole JSON cohort before hive parsing and compares every
  root/object/element value and store digest. This does not exclude an
  uncooperative same-UID writer that can race and restore source bytes, establish
  that Windows produced the inputs, or authorize hive/device writes. Source bytes
  and returned handle collections are
  bounded, but hivex still runs in-process without a wall-clock deadline,
  cancellation, or native-crash isolation; this developer evidence tool is not a
  privileged parsing boundary. A separate strict RAW schema deliberately carries
  no registry-tree interpretation. Its Linux importer pins an exact seven-file
  inventory through distinct read-only no-follow descriptors, derives the tree
  only through the sealed hivex reader, revalidates every byte, and publishes an
  eleven-file evidence directory through `renameat2(RENAME_NOREPLACE)`. The
  destination parent must be owned by the effective UID and exclude group/other
  writers; parent and temporary directory identities are rebound immediately
  around commit. Hostile same-EUID namespace manipulation remains out of scope,
  and any detected post-rename identity or durability uncertainty is reported as
  committed rather than success. The Windows collector accepts only ISO/index/new
  output parameters and operates on fixed VHD files beneath an Administrators/
  SYSTEM-only NTFS parent, but has only static and independent GPT/CRC tests on
  this Linux host. No PowerShell parser, embedded-C# compilation, Hyper-V run, or
  authentic cohort has been completed. Tests are otherwise synthetic and cannot
  remove native BCD authoring, QEMU/OVMF, or physical-media execution blockers.
  No application, helper, PolicyKit, or device-writing path imports these modules.
- The boot-artifact catalog contains the release-pinned UEFI:NTFS v2.8 image,
  dormant exact Syslinux `6.03-2014-10-06`/`6.04-pre1` payload sets, dormant
  GRUB 2.06/2.12 `core.img` entries, and the closed GRUB 2.14 rescue-media
  `boot.img`/`core.img` bundle, plus the exact upstream UEFI
  Shell 26H1 AA64, IA32, LoongArch64, RISC-V64, and X64 release set and the exact
  six-architecture `uefi-md5sum` v1.2 runtime-validation set. It records
  immutable upstream
  URLs, exact length, SHA-256, purpose-specific bundle membership, license, and
  provenance. Generic bundle preparation has cancellation, aggregate progress,
  a shared connection/download/cache-read/binding deadline, exact-version
  matching, and no partial return; every cache directory and object is opened
  no-follow, the parent pathname is revalidated against its bound descriptor,
  and every stable singly linked regular file is rehashed and frozen as immutable
  bytes. GRUB entries never satisfy a detected-image dependency. The exact 2.14
  rescue backend independently validates both payload hashes, the 432-byte
  bootstrap hash and fields, and the core diskboot blocklist. It accepts only a
  canonical empty anonymous MBR/FAT32 image, writes and read-back verifies the
  core first, proves the remainder of the embedding gap is zero, activates the
  MBR bootstrap last while preserving its metadata tail, and then revalidates
  the empty FAT tree and hashes the entire image. Cancellation requested during
  final attestation is honored before the image becomes streamable. Because the
  pinned core has no `normal.mod`, menu, or configuration, successful boot is
  intentionally limited to `grub rescue>`. The opt-in certificate passes only a
  sealed read-only descriptor to networkless snapshot QEMU inside fresh user
  and network namespaces. A separate environment-gated GUI/device caller now
  consumes only this exact rescue profile under the dedicated boundary described
  below; the certificate does not cover that transaction. A pure,
  non-destructive Syslinux consumer independently re-pins the two enabled
  payload pairs. A backend-only private-tree planner consumes caller-bound bytes
  as inert data, but no production BIOS executor or GUI path consumes them. The
  UEFI Shell backend independently
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
  **Download official image… → Download Linux ISO…**, a catalog entry, an
  exact destination filename, and final
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
- The FreeDOS downloader is network-inactive until the user chooses **Download
  official image… → Download FreeDOS USB image…**, one exact FreeDOS 1.4
  LiteUSB or FullUSB catalog entry, its exact
  destination filename, and final consent. ISOpropyl bundles catalog metadata,
  not FreeDOS media, and downloads the ZIP directly from the official
  `download.freedos.org` origin at runtime. Each catalog entry pins the exact
  archive filename, length, and SHA-256 recorded from FreeDOS's official
  `verify.txt`, plus the exact ordered three-member ZIP catalog and a separately
  reviewed SHA-256 for the inner disk image. Before archive transfer, the live
  bounded official verification page must contain exactly the cataloged SHA-256
  row. FreeDOS does not publish a detached signature for these archives: the
  project pin is the trust anchor, and the live HTTPS row is corroboration rather
  than cryptographic proof of publisher authorship.
- FreeDOS archive transfer uses a private, resumable exact-range download and a
  complete descriptor rehash. Extraction accepts only the cataloged ordinary,
  deflated image, VMDK descriptor, and readme entries with exact names, order,
  modes, sizes, compressed sizes, and CRCs; only the selected image is written
  to an exclusively created private file. Its reviewed inner SHA-256 is checked
  during extraction and again before no-overwrite publication, followed by
  exact MBR partition, FAT type, volume label, and 512-byte-sector checks. A
  descriptor-bound inspection must then identify the published result as the
  expected raw MBR, BIOS-only x86 FreeDOS image before the GUI loads it. Archive
  and image contents remain data and are never executed on Linux.
- The verified FreeDOS image is handed to ISOpropyl's ordinary authenticated
  DD/raw broker; the downloader does not introduce a separate BIOS writer. The
  official LiteUSB and FullUSB images are fixed at 32 MiB and 1 GiB respectively,
  so their partitions and filesystems are not expanded to fill a larger target.
  As with any shorter raw source, bytes between the image end and the physical
  target tail are not claimed to be erased. These releases target
  Intel-compatible x86 BIOS or UEFI Legacy/CSM only. They have no native UEFI,
  Secure Boot, ARM, or RISC-V path; Secure Boot must be disabled, and systems
  without CSM are unsupported.
- The source-checkout-only FreeDOS boot certificate is explicitly opt-in and
  refuses root or set-ID QEMU execution. It rechecks one exact catalog image,
  copies it into a sealed read-only memory file, hashes and executes QEMU through
  a bound descriptor, uses TCG, snapshot mode, no network or monitor, and QEMU's
  seccomp sandbox, and accepts only ordered markers rendered contiguously on a
  bounded 80x25 terminal model. It opens no host block device. This establishes
  narrow SeaBIOS emulator evidence only; it is not physical USB, firmware,
  Secure Boot, or hardware certification.
- The Windows downloader is likewise network-inactive until the user selects
  **Download official image… → Download Windows ISO…**, one immutable catalog
  object, an exact destination, a
  source method, and final consent. Its initial scope is the public Windows 11
  25H2 v2 consumer multi-edition ISO in English (United States) for x64 and
  ARM64. The closed, code-owned profile map binds each architecture to its exact
  Microsoft page and connector download type. The catalog separately pins each
  profile's exact Microsoft product/edition/SKU labels, official filename,
  length, and Microsoft-published SHA-256. Before a private partial is opened,
  ISOpropyl fetches that profile's bounded official page as data and requires
  its one English hash row to equal the bundled pin. This is an HTTPS-published
  hash, not a detached Microsoft signature; CDN ETags and API metadata are never
  accepted as an artifact digest.
- The recommended Windows path asks the user to generate a link in Microsoft's
  normal browser and paste it into a masked field. ISOpropyl accepts only the
  exact reviewed CDN origin and filename, canonical `t`/`P1`/`P2`/`P3`/`P4`
  query, and a bounded future expiry. The complete capability URL, cookies,
  session ID, and signature query are never logged, displayed after acceptance,
  stored in settings, or placed in resume state. They are transport state only;
  resume identity remains the exact filename, size, release ID, language,
  architecture, and SHA-256. Connector cookies and referers are not forwarded to
  the CDN, and redirects are disabled.
- The separately selected direct Windows resolver uses a fresh in-memory cookie
  jar and fixed exact Microsoft origins. It reads the bounded `mdt.js` response
  only as untrusted ASCII to extract two opaque challenge fields; no JavaScript,
  PowerShell, Fido, HTML, or ISO byte is evaluated or executed. Response schemas,
  list/string sizes, product labels, SKU, architecture, expiration, host, path,
  and query shape are strict. Microsoft can reject this privacy-minimal path, and
  ISOpropyl does not retry around regional, policy, entitlement, or anti-abuse
  decisions. The browser-assisted path remains available.
- Windows and Linux use the same authority-neutral private `0700` resume stage,
  singly linked `0600` partial, exact range/length/encoding rules, free-space
  reserve, complete partial rehash, immediate no-overwrite hardlink commit, and
  post-commit semantics. Each stage name is derived from the release ID,
  filename, exact size, and SHA-256, so a future same-filename catalog entry
  cannot consume another artifact's partial. A checksum mismatch removes only
  the known-bad bound partial. After Windows publication, a
  descriptor-identity-bound inspection must prove an ISO9660 Windows installer
  with exactly the catalog-selected x64 or ARM64 architecture before the GUI can
  load it; a wrong, mixed, or unknown architecture set is rejected. ISOpropyl
  never proxies or redistributes Microsoft media, automates account/subscription
  access, or claims that a download grants a Windows license; Microsoft terms
  apply and ISOpropyl is unaffiliated with Microsoft.
- Windows customization can be injected only through reviewed ISO staging
  paths; an existing answer file is never overwritten. Ordinary exposure uses
  UEFI ISO mode. The environment-gated x64 Windows BIOS+UEFI profile admits the
  same generator only when overlays, embedded images, BootEx, Syslinux,
  persistence, and the boot-time wrapper are absent. A selected WIM/ESD index is
  re-inspected through one inherited no-follow descriptor and bound to its exact
  source catalog path, size, architecture, edition set, ctime, and link count
  before `/IMAGE/INDEX` metadata is emitted. Nested or multi-source WIM answer
  files also receive an `InstallFrom/Path` value validated against that catalog;
  a forged path, alias, stale result, or ambiguous ESD selection fails closed.
  The staging plan retains the frozen typed customization and generator
  architecture, regenerates the complete answer file before extraction, and
  requires exact UTF-8 byte equality; structurally valid extra commands,
  comments, or whitespace changes are rejected. The dual-firmware path also
  binds the answer-file SHA-256, requires exactly lowercase root
  `autounattend.xml` with the planned size and digest in the final published-tree
  manifest, and freezes the typed options, optional WIM selection, and digest in
  the anonymous-image composite plan. Its final destructive confirmation names
  every selected effect and the digest. The opt-in certification harness accepts
  only one fixed generated profile and no arbitrary XML; that option proves
  composition plus initial Setup launch, not installation or execution of the
  later `specialize` effect. The retained VM observation remains uncustomized.
  Whenever hardware-bypass commands or image selection create a
  `Microsoft-Windows-Setup` windowsPE component, the generator also emits
  `AcceptEula=true` and an explicitly blank product key. The dual-mode final
  confirmation discloses both; ISOpropyl never invents or collects a key.
  The fixed `BypassNRO` command
  contains no user-derived text and is enabled only for an explicitly selected,
  recognized non-Home x64/ARM64 Windows 11 build in the 21H2–24H2 allowlist.
  Home, x86, newer, unknown, and obvious normalized English S-mode/cloud markers
  fail closed. WIM metadata cannot prove the absence of a localized or
  offline-serviced S-mode policy, so the GUI requires a separate explicit
  acknowledgment of that residual uncertainty before it can emit the command.
  The separate Fast Startup option emits only the fixed machine-level
  `HiberbootEnabled=0` registry command during `specialize`; it is default-off
  and discloses that full shutdowns may make startup slower.
  The separate Windows 11 quality-of-life bundle is also default-off. It
  requires an explicitly selected, validated x64/ARM64 Windows 11 WIM/ESD
  edition, rejects obvious normalized S-mode/cloud markers, and requires an
  acknowledgment that first-logon execution and Microsoft package/policy names
  can change. Its six `specialize` and seventeen first-logon commands are fixed
  project data: no username, path, downloaded text, or other user input enters
  them. They disable OneDrive synchronization, delete its setup binaries,
  remove provisioned/installed Outlook and Teams packages, and set the disclosed
  Windows policy/UI defaults. Selecting standalone Fast Startup as well cannot
  duplicate `HiberbootEnabled`. Tests assert one ordered component, one ordered
  first-logon sequence, exact regeneration from the frozen staging model, and
  the absence of `DiskConfiguration`, `InstallTo`, and `WillWipeDisk`.
  The installed-system Secure Boot revocation-policy option is separately
  default-off and requires an explicitly selected, validated x64/ARM64 Windows
  11 build 26200 or 28000. Unknown future builds and obvious S-mode/cloud
  editions fail closed. The
  generated first-logon command contains no user text, host path, downloaded
  payload, or network action: it creates a unique private mount directory,
  mounts the installed system's EFI System Partition, copies only that installed
  Windows image's own `System32\SecureBootUpdates\SkuSiPolicy.p7b`, and uses a
  `try/finally` cleanup to unmount the partition and remove the directory. The
  GUI requires confirmation that the image already contains the latest
  applicable updates and acknowledgment that older boot/recovery media may be
  blocked, current recovery media and any BitLocker recovery key should be
  available, and ISOpropyl cannot attest the image's servicing level or that the
  later first-logon step succeeds.
  This is an ISOpropyl construction invariant, not a claim that every unusual
  booted Windows Setup launch context has been physically certified. ISOpropyl
  never emits an automatic target-disk wipe instruction for Windows Setup.
- The Windows 2023-generation installer-boot transform is a separate,
  default-off direct-FAT32 option, not an answer-file setting. Planning hashes
  the complete ISO and requires one exact reviewed Microsoft-published Windows
  11 25H2 v2 English x64/ARM64 size and SHA-256 profile. Execution revalidates
  the source identity and complete hash, extracts only literal
  `Windows/Boot/EFI_EX` and `Windows/Boot/Fonts_EX` paths from
  `sources/boot.wim` index 2 through fixed `wimlib-imagex --no-globs`
  arguments, and accepts only a bounded, singly linked regular-file tree.
  Replacement executables must match the selected PE architecture and EFI
  subsystem and have a structurally present certificate table. Only the
  fallback loader, root `bootmgr.efi`, and direct boot fonts may be replaced;
  each destination is identity- and hash-bound, atomically replaced inside the
  unpublished private tree, reopened, hashed, and included in the final staging
  manifest and receipt. A failure discards that private staging workflow before
  device construction. The user separately acknowledges that 2011-only
  firmware may not boot the result. Whole-ISO provenance and a certificate-table
  presence do not establish the individual signer's chain, revocation status,
  signing time, Windows UEFI CA 2023 identity, or the target firmware's trust;
  in particular, ISOpropyl does not label the root `bootmgr_EX.efi` mapping as
  CA-2023-signed.
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
  unsigned-payload consent, or write authorization. A matching integrity result
  does not predict firmware acceptance.
- DBX advice is an independent, network-inactive comparison against the exact
  Microsoft `secureboot_objects` v1.6.5 source JSON at commit
  `798cdc513e0c192fe90e99637105748ed3bb4ca5`. ISOpropyl embeds only a strict
  digest-pinned projection of its 673 architecture-specific Authenticode
  SHA-256 image hashes, retaining Microsoft's unflagged/optional distinction;
  “unflagged” means only that Microsoft's source did not mark an entry optional.
  It measures unsigned payloads as well as signed ones and requires a bounded
  PE layout for which Microsoft's catalog implementation, the UEFI/TianoCore
  method, and Rufus's FileAlignment-rounded method produce the same digest.
  Unsupported, malformed,
  truncated, aliased, unreadable, timed-out, ambiguous, or catalog-invalid
  analysis is `unknown`. Cancellation propagates instead of becoming unknown.
- An unflagged or optional snapshot match opens a separate default-Cancel warning
  before either DD or ISO-mode preparation continues. “Not listed” applies only
  to the exact selected payload and pinned snapshot; it does not mean clean,
  safe, trusted, compatible, bootable, or accepted by the current machine.
  ISOpropyl does not read the machine's firmware DBX, authenticate live policy,
  or yet apply the snapshot's certificate/SVN entries or a current SBAT policy.
  ISO mode performs another bounded, descriptor-bound pass over every selected
  `.efi` file in the final constructed-media plan after overlays, persistence
  changes, and runtime-validation wrappers. A newly introduced exact match opens
  a second default-Cancel warning before any writer or formatter is invoked.
  Incomplete final coverage—whether from selection limits or unknown
  assessments—also requires a separate default-Cancel decision. The writer
  independently rejects subsequent staged-tree identity drift. For UEFI:NTFS,
  the exact whole-image hash is additionally bound to fixed, independently
  SHA-256-checked byte ranges for each selected architecture's bridge and NTFS
  driver; those actual PE bytes join the same final DBX decision. Nonselected
  architecture and exFAT payloads cannot complete the selected NTFS boot chain
  and are not assessed. RISC-V64 remains explicitly unknown because Microsoft's
  snapshot has no applicable architecture set. EFI executables reconstructed
  from a supported embedded El Torito FAT tree join both the source and final
  staged-tree passes; unsupported or ambiguous embedded layouts remain unknown.
- Automated device-facing tests use mocks and regular files. Hardware-backed
  write, boot, Secure Boot, cancellation, and failure-recovery testing is still
  required before the alpha label can be removed.
- Diagnostics omit drive identifiers, mount paths, ISO member lists, and logs by
  default. ISOpropyl contains no telemetry.

## Experimental Syslinux BIOS developer boundary

Ordinary GUI launches keep the BIOS path disabled. A per-process
`ISOPROPYL_EXPERIMENTAL_SYSLINUX=1` developer opt-in may expose only this narrow
profile; the variable grants no privilege and bypasses none of the receipts,
PolicyKit, target, or read-back checks below. The implemented boundary accepts
only exact Syslinux `6.03-2014-10-06` or `6.04-pre1` immutable bundles whose
family, purpose, license, provenance, artifact order, size, catalog digest, and
fresh SHA-256 all match a second consumer-local pin set. It reproduces upstream's
two-sector ADV, 64-KiB-aware extent encoding, patch-area checksum, first-sector
pointers, and FAT32 VBR merge. Bounds, overlap, integer-width, extent-capacity,
directory, and copied-code-region violations fail closed.

The companion mapper reads only an already-open regular-file descriptor. It
requires 512-byte mirrored FAT32 with matching primary/backup VBRs, valid FSInfo,
an exact `BPB_HiddSec`/volume-offset relationship, matching consulted entries
across both FAT copies, and one
unaliased root `LDLINUX.SYS`. It rejects loops, root/file cross-links, malformed
LFNs, duplicate sectors, source identity drift, and any byte or SHA-256 mismatch.
Sector numbers remain volume-relative. Synthetic fragmented images exercise a
complete patch/read-back loop; optional offline tests also compare both real
pinned payloads with frozen golden hashes from the upstream algorithm.

The same descriptor supplies the formatted MBR to a pure merge boundary. It
accepts only the exact hash-pinned 440-byte Syslinux 6.02 bootstrap used by the
pinned Rufus source, a conventional 2,048-sector start, and one active FAT32-LBA
partition whose size exactly matches the mapped volume. Additional partitions,
reserved-byte changes, malformed signatures, unaddressable geometry, and source
identity drift fail closed. Only bytes 0–439 are replaced; the disk signature,
reserved bytes, complete partition table, and MBR signature remain byte-for-byte
unchanged.

A separate pure staging policy accepts only complete, issue-free analysis for
the exact two supported Isolinux builds. It requires one or more nonempty
cataloged `isolinux.bin` payloads from one exact build, with either one
authoritative root `syslinux.cfg` and one payload or exactly one nonempty
sibling `isolinux.cfg`, `syslinux.cfg`, or `extlinux.conf` association. It never
uses shortest-path, tie-breaking, or distribution-name heuristics. Root
`ldlinux.sys`, ambiguous configs, links, special entries, case aliases, unsafe
paths, and every foreign or misplaced C32 module fail closed. The policy either
reuses byte-for-byte matching `ldlinux.c32` evidence or plans exclusive creation
from an independently size/hash/provenance-pinned bundle; it never overwrites a
source file. It separately binds the exact matched `ldlinux.bss`/`ldlinux.sys`
pair and always plans a new root `ldlinux.sys` consisting of the pinned raw file
plus the exact two-sector blank ADV. The complete root output has its own frozen
size/SHA-256 pin and can never be reused from source media. Generated files and
every input-derived field are digest-bound and rebuilt during plan validation.
The caller must supply immutable bytes for
every identity source and the selected config: each loader is size-bound and
re-identified, while the config is size/hash-bound, ASCII/control-checked, and
rejected if it can load direct or transitive modules through `UI`, `COM32`,
`CONFIG`, `INCLUDE`, `MENU INCLUDE`, or a `.c32` reference. Supporting those
directives later requires parsing and pinning their full dependency closure.
The policy itself still performs no filesystem mutation. An optional ISO
staging consumer accepts only an already prepared immutable C32 bundle together
with its same-version matched BIOS payload bundle, reopens the identity-bound
ISO, rebuilds the analysis and policy from exact member bytes, and repeats
validation against the extractor's actual files before any addition. It creates
only policy-authorized files through exclusive no-follow
descriptors in the unpublished private tree, fsyncs and reads them back, then
requires the Syslinux-adjusted planned namespace, sizes, digest, and free-space
accounting to match. A second exact-byte pass immediately precedes publication;
the existing final-tree scan separately covers later WIM and answer-file
transformations. The initial profile requires every Syslinux identity, config,
and reused C32 byte to originate in the base ISO; overlay/embedded-origin
evidence fails closed. The staging policy itself never downloads a bundle,
replaces media content, or authorizes a device write. The developer workflow
obtains both exact bundles only after explicit consent, retains their immutable
bytes through confirmation, and has no system-tool or prefix-match fallback.

The next boundary is now executable only on an already-open, owner-only `0600`
anonymous regular file with zero directory links, `O_RDWR` access, no `O_APPEND`,
and a nonblocking exclusive lock. It opens no path and rejects named files,
special files, multiply referenced paths, and block devices. Planning flushes
the fully built image, rebuilds the live FAT map and complete MBR/VBR/file patch
plan from the same descriptor, freezes exact preimage/postimage write records,
and streams the entire file once to bind both the source SHA-256 and the only
permitted final SHA-256. Validation repeats that work immediately before the
first mutation.

The transaction writes only file-length loader fragments, so final-sector and
remaining-cluster slack are not overwritten. It writes and fsyncs the loader
first, the backup VBR second, the primary VBR third, and the complete MBR sector
last as the activation gate. Each phase is read back exactly. Final validation
remaps the patched loader, requires the same cluster/sector chain, rereads every
postimage, preserves the MBR metadata tail, and hashes the entire image against
the witnessed expected result. Cancellation is accepted only before mutation;
after the first write the bounded verification completes without a cancellation
point. A write, sync, read-back, identity, map, or whole-image failure returns no
result and poisons the unpublished anonymous image, which must be closed and
discarded. The transaction deliberately attempts no unverifiable rollback.
If cancellation arrives after that internal transaction returns but while the
owner is independently reparsing or rehashing, the owner poisons and closes the
still-unpublished image instead of enabling streaming.

The transaction is now preceded by a production-owned, pathless image builder.
It accepts one canonical, descriptor-scanned staging tree whose directory and
single-link regular-file identities, timestamps, sizes, and SHA-256 digests are
frozen in a witnessed plan. The scratch workspace must be a stable user-owned
directory outside that tree. Construction requires Linux `O_TMPFILE | O_EXCL`,
mode `0600`, zero links, `O_RDWR`, a nonblocking exclusive lock, and successful
full-size preallocation. It writes a deterministic single-partition MBR/FAT32
image directly through bounded positional I/O. No formatter, mount, loop
association, pathname publication, or subprocess exists to outlive the build.
The MBR disk signature and FAT volume ID are separately domain-derived from the
canonical output-relevant plan, must be distinct and neither zero nor all ones,
and are independently read back. They are public 32-bit identifiers, not
secrets or global-uniqueness guarantees; byte-identical clones intentionally
share them.

Before returning, the builder rescans every source, exactly reads back its own
metadata, and invokes a separate read-only FAT parser. That parser requires the
canonical partition and FAT32 geometry, identical FAT copies and boot backups,
exact FSInfo allocation accounting, one matching root volume label, valid dot
entries, unique aliases and VFAT names, reachable non-cross-linked allocation,
and the expected hash of every file. The complete disk is then hashed between
stable identity snapshots. Only the opaque owner object retains the descriptor.
It exposes no fileno and cannot stream while unpatched.

After Syslinux mutation, the owner independently fsyncs, reparses, and hashes
the complete live disk again, binding the parser identity, transaction identity,
and expected whole-image digest. A synchronous mutation even in unused MBR gap
space therefore discards the image. Streaming becomes available only in the
patched-attested state and uses a close-on-exec duplicate acquired under a
lifecycle lock, so closing the owner cannot cause descriptor-number reuse to
splice another process file into an active stream. Patch, poison, and close are
serialized; failures never publish a scratch path or attempt rollback.

For the supported Syslinux staging profile, matching full-content manifests are
built immediately before and after atomic publication. A non-init receipt binds
the exact originally minted manifest, staging-plan identity, public result
fields, and final namespace; cloned/refreshed result dataclasses lose authority.
The developer-preview composite revalidates that live receipt without reopening
the ISO, binds both exact bundle roles, the selected root or nested config directory,
root loader, and private FAT32 plan, then performs builder → patch → final
attestation without exposing an unpatched owner. Its public entry point accepts
no injectable builder or transaction capable of retaining the anonymous
descriptor, and it returns only the patched-attested stream owner.

The target-authorization boundary joins that authentic composite to one exact
kernel-removable target. Its non-init receipt binds the exact composite and `Device`
objects, all public digests and media IDs, complete discovery fields, live block
major:minor, the kernel disk-generation sequence, equal image/target capacity,
fixed 512-byte logical sectors,
source/workspace non-residency, mandatory read-back, warnings, and a case-sensitive
typed phrase. Manual construction, `dataclasses.replace()`, refreshed equivalent
objects, and cross-plan confirmations lose authority. A bounded, trusted-path,
read-only `lsblk` probe must reproduce the complete discovery record and supplies
the descendant/stacked-device identities used for fail-closed source/workspace
residency checks at planning, validation, confirmation, and after unmounting.
The kernel disk generation is captured before typed confirmation and rechecked
before helper launch. These process-local
receipts prevent in-process substitution; they are not serialized privilege
credentials. Planning and confirmation do not prepare an image, unmount, or open
the target for I/O.

A separately installed root-owned executor implements that boundary. It is
reachable from the GUI only after the explicit developer opt-in. The unprivileged
one-shot coordinator verifies fixed root-owned
paths and one exact PolicyKit action, prepares and re-attests the anonymous image,
unmounts, mints a fresh target receipt, and transfers the source descriptor over
an authenticated `AF_UNIX/SOCK_SEQPACKET` channel. No target pathname crosses the
protocol; the helper derives it from the requested major:minor through sysfs. The
PolicyKit description and authentication message explicitly identify the media
bytes as caller-supplied; authentication does not imply content trust.

The helper accepts only 64-bit Linux, kernel-removable USB/MMC disks, 512-byte
logical sectors, and exact-capacity targets. It independently verifies initial
host namespaces, peer and message credentials, source ownership/mode/link count,
the canonical Syslinux MBR/FAT32 image, exact private-builder FAT geometry and
FSInfo mirrors, and the immutable code of the two pinned Syslinux VBR profiles.
It also verifies current mount and swap topology (including swapfiles), holders,
source residency, read-only state, and the sysfs disk generation. It opens the
block node once with `O_EXCL`, takes an advisory `flock`,
and checks `BLKGETSIZE64`, `BLKSSZGET`, `BLKROGET`, and `BLKGETDISKSEQ` on that
same descriptor. A bounded, authenticated PREPARED → COMMIT/CANCEL exchange is
the mutation boundary; GUI cancellation is in-band because an unprivileged parent
cannot reliably signal a root process after `pkexec` authorization.

After COMMIT, the helper repeats source, path, topology, and opened-descriptor
identity checks. It durably blanks only the legacy MBR/primary GPT header, then
durably blanks the standard backup GPT header at the final LBA; it does not wipe
a broad live-data tail. An interruption between those metadata steps occurs
before source streaming and can leave the old GPT recoverable from its backup.
It then writes all non-activation bytes, flushes and invalidates caches, verifies
them, rechecks the disk generation, and exact-reads sector zero to prove all 512
bytes are still inactive before writing the source MBR last. A failed inactive
proof takes the same durable emergency-deactivation path and never activates the
source MBR. A second flush/cache
invalidation and full SHA-256 read-back are mandatory. Post-activation failures
attempt same-descriptor MBR deactivation only after the disk generation and
geometry are re-established; cleanup is skipped and reported if media identity
changed. Cancellation after COMMIT is deferred through recovery and verification.

Linux block `O_EXCL` excludes competing exclusive holders, and `flock` coordinates
lock-aware peers; neither is absolute ownership against an uncooperative raw
`O_RDWR` writer. The Python helper is therefore provisional. A native hardened
implementation, installed pkexec/PolicyKit+SCM_RIGHTS testing in a root-owned VM,
OVMF retained-UEFI results, hot-swap/unplug races, and representative physical
media remain mandatory before normal GUI exposure. The device-free production
pipeline locally passed a sealed, networkless QEMU TCG/SeaBIOS
bootstrap/config-prompt certificate on 2026-08-28; the retained observation
records the exact QEMU version and SHA-256 and therefore depends on trust in that
emulator binary. This is not device-helper, UEFI, operating-system, or
physical-media certification. Until the remaining gates close,
hybrid media should use verified DD mode to preserve their existing layout.

## Experimental GRUB 2.14 rescue-device boundary

The blank GRUB rescue workflow is unreachable in an ordinary GUI launch and is
exposed only when the process starts with the exact
`ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE=1` environment opt-in. It accepts only a
writable, kernel-removable USB or MMC disk, exactly 512-byte logical sectors,
sector-aligned capacity, and no more than 128 GiB. Before acquiring payloads it
requires explicit consent and explains that the result contains no operating
system, installer, kernel, boot menu, `normal.mod`, or UEFI loader and will stop
at `grub rescue>`. Preparation uses owner-only staging and workspace directories,
requires free space for a fully allocated private image exactly equal to the
target plus a 64 MiB reserve, and rejects target-resident source or workspace
topology.

The device plan binds the authentic backend result, exact discovered `Device`
object, current major:minor and kernel disk-generation sequence, capacity,
512-byte geometry, complete image/MBR/FAT manifest hashes, mandatory
preactivation and final read-back, and the exact case-sensitive
`WRITE GRUB RESCUE /dev/… major:minor` phrase. Confirmation, unmounting, and
authorization revalidate those bindings. The prepared image has a fail-closed,
one-shot descriptor transfer and cannot be streamed again after a transfer
attempt.

This workflow uses the separate
`io.github.codebooker.isopropyl.write-grub-rescue-image` PolicyKit action,
`write-grub-2.14-rescue-image-v1` protocol operation, and
`io.github.codebooker.isopropyl/grub-2.14-rescue-device-helper/v1` helper
profile. The coordinator resolves that exact installed integration before any
download. It has no formatter, mount, Syslinux, Windows, or generic/raw writer
fallback. The authenticated PREPARED → COMMIT/CANCEL exchange passes the
already-open image descriptor while the privileged helper resolves the target
from major:minor and independently repeats namespace, credentials, source,
topology, removability, read-only, geometry, capacity, and disk-generation
checks.

The helper independently parses the exact target-sized blank MBR/FAT32 layout,
pinned 432-byte bootstrap, 42,742-byte core and diskboot blocklist, LBA-2048
active FAT32 partition, mirrored filesystem metadata, sole volume-label entry,
and zero empty remainder. During device mutation it first keeps sectors zero and
one inactive, writes and verifies bytes from offset 512 through the end (including
the embedded core), flushes and invalidates caches, and only then writes sector
zero. A second durability/cache barrier and complete physical-device SHA-256
read-back are mandatory. Post-activation failures attempt same-generation MBR
deactivation; cancellation after COMMIT is deferred through recovery and
verification. If progress or the authenticated result channel is lost after
COMMIT, the unprivileged runner keeps the UI and target quarantined until the
privileged helper process actually exits; it does not detach a background
reaper and announce completion. A missing verified result leaves the medium in
an explicitly unknown state and requires removal, reinsertion, inspection, and
a complete rewrite or restore before it can be trusted.

The retained QEMU TCG/SeaBIOS observation certifies only that the sealed exact
image reaches the intentional rescue prompt. It does not certify the PolicyKit
transaction, installed packaging, USB transport, physical BIOS firmware, or
physical media. The Python helper remains provisional: a native hardened helper,
installed-integration and hot-swap/unplug/failure tests, and representative
physical-media write and boot evidence remain mandatory before ordinary GUI
exposure.

## GUI and CLI raw/DD broker boundary

The generic raw profile is separate from the default-off Syslinux and GRUB
rescue developer profiles and is the GUI and CLI's sole DD/raw executor. It has
no legacy writer fallback. Every
plain, compressed, VTSI, virtual, or compressed-virtual input is bound through
one already-open outer-source descriptor and expanded into one stable private
`0700` snapshot workspace. Planning binds source device, inode, size, mtime,
ctime, materialization profile, format-specific target constraints, workspace
identity, and a fresh complete target-topology device-number set. Neither source,
temporary root, nor workspace may reside on the target. The builder requires
enough available space, creates an unlinked
`O_TMPFILE | O_EXCL` with mode `0600`, takes a nonblocking exclusive lock,
preallocates every byte, fsyncs, and independently reads and hashes the entire
expanded snapshot. Stream formats have exact-length decoding. Virtual formats
are freshly reinspected and converted directly into a borrowed anonymous
descriptor; backing files, encryption, corruption metadata, and QCOW2 external
data files are rejected. Compressed virtual decode staging is isolated from the
immutable snapshot directory. The opaque one-shot owner exposes no descriptor;
transfer duplicates, re-attests, and sends the source exactly once through
`SCM_RIGHTS`, then consumes the unprivileged owner.

Target authorization binds the authentic snapshot-plan digest, expanded size
and SHA-256, original source identity, workspace filesystem, complete `Device`
observation, target topology, major:minor, capacity, 512-byte logical sectors,
kernel disk generation, verification policy, warnings, and a case-sensitive
typed phrase. A fresh post-unmount receipt permits only the mounted-to-unmounted
transition on that same disk generation. The expanded source is capped at
64 TiB; the target is independently capped at 64 PiB and may be larger than the
source. Images smaller than 1024 bytes or not aligned to 512 bytes fail before
confirmation under this initial protocol.

The headless entry point adds no alternate authority. It accepts only one
canonical exact `/dev/...` path that uniquely matches the same protected device
inventory; indexes, globs, substrings, internal/root-backed disks, read-only
targets, and non-hot-pluggable fixed disks are rejected before a workflow is
created. Fixed hot-pluggable USB HDDs/SSDs require an explicit command-line flag
and an extra exact preparation phrase. Risky raw profiles and the explicit
full-final-verification opt-out require that same second interactive boundary.
The final phrase comes only from the authoritative target plan and is compared
before `confirm()` is invoked. Standard input must be a terminal, so pipes and
unattended jobs cannot approve erasure.

CLI inspection first freezes source device, inode, size, mtime, and ctime, passes
that identity into `inspect_image()`, and rechecks it after exact target
discovery. The CLI never imports Qt, invokes `dd`, constructs helper messages, or
calls the privileged protocol directly. Its `SIGINT`/`SIGTERM` handler only sets
a cooperative cancellation event; a pre-existing watcher thread calls the bound
workflow's lock-taking `cancel()` outside signal-handler context. The synchronous
caller then waits for that dispatch and the same pre-COMMIT cancellation,
authenticated cleanup, or post-COMMIT verified completion rules described below.
Terminal device listings omit serial/WWN values, while the privileged plan still
binds them internally.

The user-side coordinator verifies one separate exact PolicyKit action whose
prompt states that caller-supplied data will overwrite the selected target. It
has no `dd`, pathname, shell, or permissive-policy fallback. The fixed root
helper independently verifies peer credentials, the single anonymous source
descriptor, full source hash and stable status, target sysfs topology,
mounts/swapfiles, holders, USB or removable-MMC transport, source non-residency,
read-only state, capacity, sector size, and `BLKGETDISKSEQ`. It opens the target
once with block `O_EXCL`, takes a nonblocking `flock`, and retains that same
descriptor across mutation, durability, cache invalidation, and read-back. An
authenticated request-bound PREPARED → COMMIT/CANCEL exchange linearizes the
last cancellable point.

After COMMIT and another complete identity check, the helper durably zeros a
front activation guard of up to 1 MiB, the source's final sector, and the
physical target's final sector when distinct. It writes only the middle source
bytes, fsyncs and invalidates caches, reads back the inactive bulk, and confirms
that every activation region is physically zero. It then writes the source tail
followed by the front guard as the final activation step, flushes again, always
reads back the activation regions, and optionally hashes the complete final
source range. The physical final sector remains zero when a shorter source
could otherwise leave a stale backup GPT header. Every failure after the first
mutation re-establishes disk generation and geometry before attempting to zero
all activation regions, fsync, and invalidate caches; skipped or failed cleanup
is reported explicitly.

This ordering reduces the chance that a failed write appears as valid old or
new media; it is not power-loss atomicity and it does not erase unused bytes
between a shorter source and the physical target tail. `O_EXCL` and `flock` do
not stop a hostile or uncooperative nonexclusive block writer. Native-helper,
installed PolicyKit/SCM_RIGHTS VM, cache/power-loss, hot-unplug, replacement,
large-media, and physical boot tests remain mandatory for release confidence.
All GUI and CLI raw, compressed, virtual, and VTSI inputs now use this broker, and a
failed or unavailable broker transaction never falls back to the legacy DD path.

## Positional I/O retry boundary

ISOpropyl retries only fixed-offset `pread`/`pwrite` operations whose Linux
error contract proves that the failed syscall transferred no bytes. The policy
is active in the privileged Syslinux, Windows dual-firmware, authenticated
raw/DD, fast-zero, verified-restore, emergency-cleanup, and post-format receipt
paths, and in the anonymous raw-snapshot materializer. It never reopens a source
or target pathname. Every replay uses the same retained descriptor, the same
absolute offset, and only the exact untransferred suffix after a positive short
result.

`EINTR` is retried immediately without sleeping or consuming the transient-stall
budget. The reusable snapshot primitive and Syslinux-family helper permit at
most 1,024 positional syscall attempts per retry unit; the verified-restore
helper independently caps a consecutive `EINTR` run at 1,024 attempts.
`EAGAIN` and `EWOULDBLOCK` receive four total consecutive attempts with 0.1,
0.5, and 2.0 second backoffs, and those calls consume the total syscall cap where
one applies. Backoff sleeps are divided into at most 50 ms slices so the
operation can apply its boundary-specific cancellation policy. Positive I/O
progress resets the consecutive stall bounds. The reusable unprivileged
primitive also enforces a cooperative elapsed-time deadline and immutable
accounting; a blocking kernel syscall cannot be preempted by that deadline, and
a successful late return remains authoritative.

Immediately after an allowlisted failure and immediately before another syscall,
the caller-specific guard runs again. Anonymous sources must retain their bound
file identity. Anonymous snapshots must retain the same device/inode object,
owner-only mode, exact size, read/write non-append access, and full allocation.
Their modification/change timestamps and reported block count are deliberately
not compared with the pristine receipt because successful writes can alter
those fields; the allocation invariant is revalidated separately. A physical
target must retain its block `rdev`, capacity, logical-sector size, writable
state, kernel disk generation, topology, holders, and active-device evidence.
Verified filesystem receipt reads additionally require the exact retained child
descriptor, parent, partition number, start/count geometry, and fresh partition
discovery. A guard failure prevents the retry.

ISOpropyl does not retry `EIO`, `EREMOTEIO`, `ETIMEDOUT`, `ENODEV`, `ENXIO`,
`ESTALE`, `EBUSY`, space/quota/read-only errors, permission/policy errors,
unexpected EOF, zero/invalid progress, verification mismatch, or any other
ambiguous/permanent failure. It also never applies this policy to `open`,
`flock`, `fsync`, cache/partition ioctls, COMMIT/control messages, unmounting,
partitioning, formatting, publication, or high-level child commands. Those
operations execute once and enter their existing fail-closed cleanup path on
error. Syslinux/Windows/raw cancellation remains deferred after COMMIT; fast-zero
cancellation during a retry enters its authenticated boundary cleanup; verified
restore records post-COMMIT cancellation as deferred while the helper completes
durability and read-back.

This is narrower than Rufus's broad four-attempt write retry: ISOpropyl does not
replay whole short writes, retry arbitrary errors, repeat a formatter, weaken
exclusive access, or accept zero-byte writes. Installed-PolicyKit VM fault,
hot-unplug/replacement, and representative physical-device tests remain release
confidence gates. Mounted constructed-media and backup/optical paths remain
outside this policy until their exact positional and identity invariants are
proved separately.

## Fast-zero boundary

Fast zero is a separate target-only privileged protocol. It accepts no source
descriptor, pathname-selected payload, shell command, or legacy `dd` fallback.
Before showing the final typed confirmation, planning binds the exact removable
USB/MMC device, model, serial/WWN, major:minor, capacity, logical sector size,
complete related-device topology, kernel disk generation, fixed 32 MiB chunk
size, warnings, and executor profile. No unmount or target mutation occurs during
planning or while the confirmation dialog is open.

After confirmation, the coordinator revalidates and unmounts the same target.
The fixed root helper derives the device path from the authorized major:minor,
rejects mounted filesystems, swap, holders, read-only or non-removable targets,
opens it once with `O_RDWR | O_EXCL | O_NOFOLLOW`, takes a nonblocking exclusive
lock, and checks geometry, sysfs topology, and `BLKGETDISKSEQ` on that retained
descriptor. An authenticated PREPARED → COMMIT/CANCEL boundary is the final
pre-mutation decision.

After COMMIT, every logical byte is read in aligned 32 MiB chunks. A chunk is
skipped only when it is exactly all zero; every other chunk is overwritten with
zeroes. Success requires exact scan/write/skip accounting, `fsync`, device-cache
invalidation, a complete all-zero read-back, and a final identity/topology check.
Post-COMMIT cancellation is polled between chunks and travels over the same
authenticated channel. Before returning a partial cancellation or failure, the
helper re-establishes complete path, descriptor, disk-generation, mount/swap,
holder, geometry, and topology evidence, then durably zeroes and reads back the
first and last 16 MiB (counting overlap once). If that proof changes or cleanup
cannot be verified, no cleanup claim is made and the target state is reported
unknown.

Successful accounting is exact for every chunk. Partial-result counters cover
only fully completed chunks: if a kernel write accepts a prefix and a later
write to that same chunk fails, the uncompleted in-flight chunk may also have
changed. The GUI states that limitation instead of presenting the completed-
chunk counter as an exact physical-write total.

Fast zero is a logical host overwrite. It is not ATA Secure Erase, NVMe Sanitize,
cryptographic erasure, or proof that a flash controller erased remapped or spare
cells. `O_EXCL` and `flock` remain advisory against hostile or uncooperative
privileged writers. Installed-PolicyKit VM tests, hot-unplug/replacement tests,
cache/power-loss tests, large-media performance measurements, and representative
physical-device certification remain release gates.

## Verified restore boundary

Verified full overwrite + format is a distinct GUI and PolicyKit path, not a
sequence of the ordinary Quick formatter and erase runner. It is offered only
for an exact kernel-removable USB/MMC device with a stable serial or WWN, a known
512/1024/2048/4096-byte logical sector, and an existing validated FAT32 or NTFS
single-partition plan. Mounted volumes must first be unmounted. The unprivileged
workflow binds the selected `Device` object, complete format plan, topology,
major:minor, capacity, disk generation, random request identifier, partition
geometry, and a serial/WWN-derived target phrase into process-local plan and
confirmation receipts. It re-observes topology and disk generation during
prepare, exact phrase confirmation, and the runner's final COMMIT callback.
Cloned, mutated, stale, or cross-wired plans and confirmations are rejected.

The dedicated v2 root helper accepts no source payload and has no Quick-format,
shell, or `dd` fallback. Before PREPARED it resolves the authorized target by
major:minor, rejects unsafe topology, opens the whole device once with
`O_RDWR | O_EXCL | O_NOFOLLOW`, takes a nonblocking exclusive lock, and rechecks
the descriptor, size, logical sector, read-only state, removability, holders,
swap, mounts, and kernel disk generation. Only an authenticated COMMIT permits
mutation. The helper scans every logical byte, skips only chunks whose bytes are
all zero, overwrites every other chunk, flushes and invalidates caches, and then
requires a complete all-zero read-back before partitioning.

Partitioning uses one frozen MBR/GPT script and the retained whole-device
descriptor. The helper discovers exactly child partition 1 from sysfs, verifies
its parent, number, start, count, block identity, capacity, sector size, and
read/write state, and retains both parent and child descriptors. FAT32 `mkfs.fat`
and NTFS `mkntfs` receive explicit sector and hidden-partition-start arguments.
After formatting, every sampled metadata range must read identically through
the parent offset and child descriptor. FAT32 validation covers primary/backup
BPBs, hidden start/count, FAT and cluster geometry, both FSInfo copies, and the
root volume label. NTFS validation covers primary/backup BPBs, hidden
start/count, cluster/MFT geometry, update-sequence fixups for MFT record 3, and
the exact resident `$VOLUME_NAME`. The final receipt binds the request plan hash,
exact child major:minor, partition geometry, filesystem, sector/cluster geometry,
normalized label, and metadata SHA-256; the unprivileged runner and workflow
validate every field before reporting success.

Cancellation before COMMIT proves no target mutation. After COMMIT, cancellation
is deferred while durability and verification complete. A post-COMMIT failure
re-attests the retained target before durably zeroing and reading back its first
and last 16 MiB; if that cleanup cannot be proved, the GUI reports the target
state as unknown. This operation is logical overwrite plus ordinary filesystem
creation, not ATA Secure Erase, NVMe Sanitize, cryptographic erasure, flash-spare
erasure, bad-block testing, or Rufus/Windows slow filesystem checking. Installed
PolicyKit VM fault/hot-swap tests and representative physical-media certification
remain release-confidence gates.

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
