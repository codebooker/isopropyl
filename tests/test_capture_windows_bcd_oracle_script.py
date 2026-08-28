# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import binascii
import re
import struct
import unittest
import uuid
from pathlib import Path

from isopropyl.windows_bcd_capture import (
    RAW_BCD_CAPTURE_SCHEMA,
    RAW_BCD_CAPTURE_VARIANTS,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "capture_windows_bcd_oracle.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

SECTOR = 512
DISK_BYTES = 64 * 1024**3
TOTAL_LBAS = DISK_BYTES // SECTOR
LAST_LBA = TOTAL_LBAS - 1
ENTRY_COUNT = 128
ENTRY_BYTES = 128
ARRAY_BYTES = ENTRY_COUNT * ENTRY_BYTES
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
MSR_TYPE = uuid.UUID("e3c9e316-0b5c-4db8-817d-f92df00215ae")
WINDOWS_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
DISK_GUID = uuid.UUID("11111111-2222-4333-8444-555555555555")
ESP_GUID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
MSR_GUID = uuid.UUID("12345678-9abc-4def-8123-456789abcdef")
WINDOWS_GUID = uuid.UUID("fedcba98-7654-4321-8fed-cba987654321")


def guid_bytes(value: uuid.UUID) -> bytes:
    """Return the EFI/GPT mixed-endian wire form used by System.Guid."""

    return value.bytes_le


def crc32(payload: bytes | bytearray) -> int:
    return binascii.crc32(payload) & 0xFFFFFFFF


def make_entry(
    type_guid: uuid.UUID,
    unique_guid: uuid.UUID,
    first: int,
    last: int,
) -> bytes:
    result = bytearray(ENTRY_BYTES)
    result[0:16] = guid_bytes(type_guid)
    result[16:32] = guid_bytes(unique_guid)
    struct.pack_into("<QQQ", result, 32, first, last, 0)
    return bytes(result)


def make_header(
    *,
    current: int,
    backup: int,
    entries_lba: int,
    disk_guid: uuid.UUID,
    array_crc: int,
) -> bytearray:
    header = bytearray(SECTOR)
    header[0:8] = b"EFI PART"
    struct.pack_into("<II", header, 8, 0x00010000, 92)
    struct.pack_into("<QQQQ", header, 24, current, backup, 34, TOTAL_LBAS - 34)
    header[56:72] = guid_bytes(disk_guid)
    struct.pack_into("<QIII", header, 72, entries_lba, ENTRY_COUNT, ENTRY_BYTES, array_crc)
    refresh_header_crc(header)
    return header


def refresh_header_crc(header: bytearray) -> None:
    struct.pack_into("<I", header, 16, 0)
    struct.pack_into("<I", header, 16, crc32(header[:92]))


def golden_metadata() -> dict[str, bytearray]:
    entries = bytearray(ARRAY_BYTES)
    entries[0:ENTRY_BYTES] = make_entry(ESP_TYPE, ESP_GUID, 2048, 534527)
    entries[ENTRY_BYTES : 2 * ENTRY_BYTES] = make_entry(
        MSR_TYPE,
        MSR_GUID,
        534528,
        796671,
    )
    entries[2 * ENTRY_BYTES : 3 * ENTRY_BYTES] = make_entry(
        WINDOWS_TYPE,
        WINDOWS_GUID,
        796672,
        134215679,
    )
    array_crc = crc32(entries)
    return {
        "primary_header": make_header(
            current=1,
            backup=LAST_LBA,
            entries_lba=2,
            disk_guid=DISK_GUID,
            array_crc=array_crc,
        ),
        "backup_header": make_header(
            current=LAST_LBA,
            backup=1,
            entries_lba=LAST_LBA - 32,
            disk_guid=DISK_GUID,
            array_crc=array_crc,
        ),
        "primary_entries": bytearray(entries),
        "backup_entries": bytearray(entries),
    }


def mutate_golden(
    metadata: dict[str, bytearray],
    variant: str,
    replacement: uuid.UUID,
) -> None:
    if variant == "disk-guid":
        metadata["primary_header"][56:72] = guid_bytes(replacement)
        metadata["backup_header"][56:72] = guid_bytes(replacement)
    elif variant in {"esp-guid", "windows-guid"}:
        index = 0 if variant == "esp-guid" else 2
        offset = index * ENTRY_BYTES + 16
        metadata["primary_entries"][offset : offset + 16] = guid_bytes(replacement)
        metadata["backup_entries"][offset : offset + 16] = guid_bytes(replacement)
        array_crc = crc32(metadata["primary_entries"])
        struct.pack_into("<I", metadata["primary_header"], 88, array_crc)
        struct.pack_into("<I", metadata["backup_header"], 88, array_crc)
    else:
        raise ValueError(variant)
    refresh_header_crc(metadata["primary_header"])
    refresh_header_crc(metadata["backup_header"])


def changed_offsets(before: bytes | bytearray, after: bytes | bytearray) -> set[int]:
    return {index for index, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]}


class WindowsCollectorStaticTests(unittest.TestCase):
    def test_public_parameter_surface_is_exact_and_bounded(self) -> None:
        match = re.search(r"(?ms)^param\((.*?)^\)\n\nSet-StrictMode", TEXT)
        self.assertIsNotNone(match)
        block = match.group(1)
        names = re.findall(r"\$(IsoPath|ImageIndex|OutputDirectory)\b", block)
        self.assertEqual(names, ["IsoPath", "ImageIndex", "OutputDirectory"])
        self.assertEqual(
            set(re.findall(r"(?m)^\s*\[[a-zA-Z]+\]\s+\$(\w+),?\s*$", block)),
            {"IsoPath", "ImageIndex", "OutputDirectory"},
        )
        self.assertIn("[ValidateRange(1, 128)]", block)
        for unsafe in ("DiskNumber", "DevicePath", "VhdPath", "DriveLetter", "DiskSize"):
            self.assertNotRegex(block, rf"(?i)\${unsafe}\b")
        absolute_check = TEXT.index("[IO.Path]::IsPathFullyQualified($IsoPath)")
        iso_canonicalization = TEXT.index(
            "$IsoPath = Assert-NoReparsePath -LiteralPath $IsoPath",
        )
        output_canonicalization = TEXT.index(
            "$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)",
        )
        self.assertLess(absolute_check, iso_canonicalization)
        self.assertLess(absolute_check, output_canonicalization)

    def test_trusted_paths_modules_and_acl_are_fail_closed(self) -> None:
        folded = TEXT.casefold()
        self.assertNotIn("$env:systemroot", folded)
        self.assertNotIn("$env:programdata", folded)
        self.assertIn("[Environment]::SystemDirectory", TEXT)
        self.assertIn("'WindowsPowerShell', 'v1.0', 'Modules'", TEXT)
        self.assertIn("Import-Module -Name $manifest -Force -PassThru -SkipEditionCheck", TEXT)
        self.assertIn("-CommandType Cmdlet, Function", TEXT)
        self.assertIn("[System.Management.Automation.CommandTypes]::Function", TEXT)
        self.assertIn("An untrusted $moduleName module is already loaded", TEXT)
        self.assertIn("Get-AuthenticodeSignature -LiteralPath $full", TEXT)
        self.assertIn("O=Microsoft Corporation", TEXT)
        module_import = TEXT.index("Import-Module -Name $manifest")
        drive_preflight = TEXT.index("foreach ($letter in @('S', 'W'))", module_import)
        self.assertLess(module_import, drive_preflight)

        self.assertIn("$acl.SetAccessRuleProtection($true, $false)", TEXT)
        self.assertIn("$acl.SetOwner($administrators)", TEXT)
        self.assertIn("$rules.Count -ne 2", TEXT)
        self.assertNotIn("WindowsIdentity]::GetCurrent", TEXT)
        self.assertIn("Assert-PrivateDirectoryAcl -LiteralPath $outputParent", TEXT)

    def test_run_directories_and_final_tree_are_lifecycle_bound(self) -> None:
        try_block = TEXT.index("try {", TEXT.index("$captures ="))
        work_create = TEXT.index("New-PrivateDirectory -LiteralPath $work")
        stage_create = TEXT.index("New-PrivateDirectory -LiteralPath $stage")
        scratch_create = TEXT.index("New-PrivateDirectory -LiteralPath $scratch")
        self.assertLess(try_block, work_create)
        self.assertLess(try_block, stage_create)
        self.assertLess(try_block, scratch_create)
        move = TEXT.index("[IO.Directory]::Move($stage, $OutputDirectory)")
        precheck = TEXT.rindex("Assert-EvidenceTree -LiteralPath $stage", 0, move)
        postcheck = TEXT.index(
            "Assert-EvidenceTree -LiteralPath $OutputDirectory",
            move,
        )
        self.assertLess(precheck, move)
        self.assertLess(move, postcheck)
        publish_success = TEXT.index("$published = $true", postcheck)
        self.assertLess(postcheck, publish_success)
        move_owned = TEXT.index("$outputMoved = $true", move)
        self.assertLess(move, move_owned)
        self.assertLess(move_owned, postcheck)
        self.assertIn(
            "if ($outputMoved -and -not $published -and [IO.Directory]::Exists($OutputDirectory))",
            TEXT,
        )

    def test_forbidden_device_and_dispatch_vocabulary_is_absent(self) -> None:
        forbidden = (
            "physicaldrive",
            "diskpart",
            "clear-disk",
            "invoke-expression",
            "start-process",
            "cmd.exe",
            "powershell.exe",
            "regloadappkey",
            "root_description",
        )
        folded = TEXT.casefold()
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, folded)
        self.assertNotRegex(TEXT, r"(?i)Storage\\Get-Disk\s+-(?:Number|Path|UniqueId)\b")
        self.assertNotRegex(TEXT, r"(?i)Mount-VHD[^\n]*-(?:Disk|SourceDisk)\b")

    def test_generated_path_binding_and_offline_patch_order_are_explicit(self) -> None:
        self.assertIn("$vhd = Hyper-V\\Get-VHD -Path $GeneratedVhdPath", TEXT)
        self.assertIn("$disks = @($vhd | Storage\\Get-Disk)", TEXT)
        self.assertIn("if ($disks.Count -ne 1)", TEXT)
        self.assertIn("-not $vhd.Attached -or $vhd.Path -ne $GeneratedVhdPath", TEXT)
        self.assertIn("$disk.IsBoot -or $disk.IsSystem", TEXT)
        parent_detach = TEXT.index("Dismount-ExactVhd -GeneratedVhdPath $parentVhd")
        parent_raw = TEXT.index("ValidateAndPatch($parentVhd, 'baseline'", parent_detach)
        self.assertLess(parent_detach, parent_raw)
        clone_patch = TEXT.index("ValidateAndPatch($cloneVhd, $variant")
        clone_mount = TEXT.index("Hyper-V\\Mount-VHD -Path $cloneVhd", clone_patch)
        self.assertLess(clone_patch, clone_mount)
        self.assertIn("[IO.File]::Copy($parentVhd, $cloneVhd, $false)", TEXT)
        self.assertIn("[IO.File]::Delete($cloneVhd)", TEXT)

    def test_frozen_geometry_and_fixed_vhd_profile_are_literal(self) -> None:
        expected = {
            "$DiskSizeBytes = [UInt64]68719476736",
            "$SectorBytes = [UInt64]512",
            "$EspOffsetBytes = [UInt64]1048576",
            "$EspSizeBytes = [UInt64]272629760",
            "$MsrOffsetBytes = [UInt64]273678336",
            "$MsrSizeBytes = [UInt64]134217728",
            "$WindowsOffsetBytes = [UInt64]407896064",
            "$WindowsSizeBytes = [UInt64]68310532096",
            "-Fixed -SizeBytes $DiskSizeBytes -LogicalSectorSizeBytes 512",
        }
        for literal in expected:
            with self.subTest(literal=literal):
                self.assertIn(literal, TEXT)
        self.assertIn('Encoding.ASCII.GetBytes("conectix")', TEXT)
        self.assertIn('Encoding.ASCII.GetBytes("EFI PART")', TEXT)
        self.assertIn("const ulong LastUsable = 134217694;", TEXT)
        self.assertIn("const ulong WindowsLast = 134215679;", TEXT)

    def test_exact_command_argv_and_hard_bounds_are_frozen(self) -> None:
        compact = re.sub(r"\s+", " ", TEXT)
        self.assertIn(
            "'W:\\Windows', '/v', '/offline', '/f', 'UEFI', '/s', 'S:'",
            compact,
        )
        self.assertIn(
            "'/store', 'S:\\EFI\\Microsoft\\Boot\\BCD', '/set', "
            "'{default}', 'recoveryenabled', 'no'",
            compact,
        )
        self.assertIn(
            "'/store', 'S:\\EFI\\Microsoft\\Boot\\BCD', '/enum', 'all', '/v'",
            compact,
        )
        self.assertIn("$MaximumCommandBytes = 65536", TEXT)
        self.assertIn("-DeadlineSeconds 120", TEXT)
        self.assertEqual(TEXT.count("-DeadlineSeconds 30"), 2)
        self.assertIn("UseShellExecute = false", TEXT)
        self.assertIn("info.ArgumentList.Add(argument)", TEXT)
        self.assertIn("process.Kill(true)", TEXT)
        self.assertGreaterEqual(TEXT.count("Assert-VerifiedLetters -Disk $variantDisk"), 3)

    def test_raw_schema_and_artifact_names_match_linux_importer(self) -> None:
        self.assertIn(f"$Schema = '{RAW_BCD_CAPTURE_SCHEMA}'", TEXT)
        self.assertIn("$Variants = @('baseline', 'disk-guid', 'esp-guid', 'windows-guid')", TEXT)
        for key in (
            "host_windows_build",
            "source_windows_build",
            "source_iso_sha256",
            "source_wim_sha256",
            "source_wim_index",
            "source_edition",
            "disk_size_bytes",
            "msr_partition_guid",
            "bcdboot",
            "bcdedit",
            "template",
            "collector",
            "captures",
            "disk_guid",
            "esp_partition_guid",
            "windows_partition_guid",
            "store",
            "commands",
            "stdout_base64",
            "stderr_base64",
        ):
            with self.subTest(key=key):
                self.assertRegex(TEXT, rf"(?m)^\s*{re.escape(key)}\s*=")
        self.assertNotRegex(TEXT, r"(?m)^\s*objects\s*=")
        for name in ("capture.raw.json", "collector.ps1", "BCD-Template"):
            self.assertIn(f"'{name}'", TEXT)
        self.assertIn('"$variant.BCD"', TEXT)
        self.assertEqual(RAW_BCD_CAPTURE_VARIANTS, (
            "baseline",
            "disk-guid",
            "esp-guid",
            "windows-guid",
        ))

    def test_cleanup_precedes_atomic_publication(self) -> None:
        raw_write = TEXT.index("[IO.File]::WriteAllText($rawOutput")
        iso_detach = TEXT.index("Storage\\Dismount-DiskImage -ImagePath $isoCopy", raw_write)
        work_delete = TEXT.index("[IO.Directory]::Delete($work, $true)", iso_detach)
        publish = TEXT.index("[IO.Directory]::Move($stage, $OutputDirectory)", work_delete)
        self.assertLess(raw_write, iso_detach)
        self.assertLess(iso_detach, work_delete)
        self.assertLess(work_delete, publish)
        self.assertIn("if (-not $published", TEXT)
        self.assertIn("if ($null -ne $attachedVhd)", TEXT)
        self.assertIn("if ($isoMountAttempted", TEXT)
        self.assertIn("Copy-StableArtifact -Source $IsoPath -Destination $isoCopy", TEXT)
        self.assertIn("Storage\\Get-DiskImage -ImagePath $isoCopy", TEXT)


class IndependentGptGoldenTests(unittest.TestCase):
    def test_geometry_matches_oracle_alignment(self) -> None:
        aligned_end = ((TOTAL_LBAS - 33) // 2048) * 2048
        self.assertEqual(aligned_end, 134215680)
        self.assertEqual(796672 * SECTOR, 389 * 1024**2)
        self.assertEqual((aligned_end - 796672) * SECTOR, 68310532096)
        self.assertEqual(TOTAL_LBAS - 34, 134217694)

    def test_one_guid_mutations_have_exact_metadata_allowlists_and_valid_crcs(self) -> None:
        replacement = uuid.UUID("0f0e0d0c-0b0a-4908-8706-050403020100")
        for variant in RAW_BCD_CAPTURE_VARIANTS[1:]:
            with self.subTest(variant=variant):
                before = golden_metadata()
                after = {name: bytearray(value) for name, value in before.items()}
                mutate_golden(after, variant, replacement)

                header_allowed = set(range(16, 20))
                if variant == "disk-guid":
                    header_allowed |= set(range(56, 72))
                    entry_allowed: set[int] = set()
                else:
                    header_allowed |= set(range(88, 92))
                    entry_index = 0 if variant == "esp-guid" else 2
                    entry_allowed = set(
                        range(entry_index * ENTRY_BYTES + 16, entry_index * ENTRY_BYTES + 32),
                    )
                self.assertLessEqual(
                    changed_offsets(before["primary_header"], after["primary_header"]),
                    header_allowed,
                )
                self.assertLessEqual(
                    changed_offsets(before["backup_header"], after["backup_header"]),
                    header_allowed,
                )
                self.assertEqual(
                    changed_offsets(before["primary_entries"], after["primary_entries"]),
                    entry_allowed,
                )
                self.assertEqual(
                    changed_offsets(before["backup_entries"], after["backup_entries"]),
                    entry_allowed,
                )
                self.assertEqual(
                    struct.unpack_from("<I", after["primary_header"], 88)[0],
                    crc32(after["primary_entries"]),
                )
                self.assertEqual(
                    struct.unpack_from("<I", after["backup_header"], 88)[0],
                    crc32(after["backup_entries"]),
                )
                for header in (after["primary_header"], after["backup_header"]):
                    stored = struct.unpack_from("<I", header, 16)[0]
                    check = bytearray(header[:92])
                    struct.pack_into("<I", check, 16, 0)
                    self.assertEqual(stored, crc32(check))


if __name__ == "__main__":
    unittest.main()
