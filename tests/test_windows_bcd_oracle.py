# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
import unittest
import uuid
from dataclasses import replace

from isopropyl.windows_bcd import BcdError, encode_candidate_gpt_qualified_partition
from isopropyl.windows_bcd_oracle import (
    BCD_BOOT_MANAGER_ID,
    BCD_BOOT_MANAGER_OBJECT_TYPE,
    BCD_BOOTMGR_DEFAULT_ELEMENT,
    BCD_BOOTMGR_DEVICE_ELEMENT,
    BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT,
    BCD_LIBRARY_INHERIT_ELEMENT,
    BCD_LIBRARY_PATH_ELEMENT,
    BCD_OBJECT_TYPE_INHERITED,
    BCD_OSLOADER_DEVICE_ELEMENT,
    BCD_OSLOADER_OSDEVICE_ELEMENT,
    BCD_OSLOADER_SYSTEM_ROOT_ELEMENT,
    BCD_RECOVERY_ENABLED_ELEMENT,
    BCD_REG_BINARY,
    BCD_REG_DWORD,
    BCD_REG_MULTI_SZ,
    BCD_REG_SZ,
    BCD_ORACLE_ESP_SECTORS,
    BCD_ORACLE_ESP_START_LBA,
    BCD_ORACLE_ESP_TYPE_GUID,
    BCD_ORACLE_MAX_BYTES,
    BCD_ORACLE_MSR_SECTORS,
    BCD_ORACLE_MSR_TYPE_GUID,
    BCD_ORACLE_WINDOWS_TYPE_GUID,
    BCD_WINDOWS_OS_LOADER_OBJECT_TYPE,
    BcdOracleElement,
    BcdOracleFixture,
    BcdOracleLayout,
    BcdOracleObject,
    BcdOracleProvenance,
    canonical_bcd_oracle_bytes,
    parse_bcd_oracle_bytes,
    validate_bcd_oracle_differential_set,
    validate_bcd_oracle_fixture,
)


DISK_GUID = uuid.UUID("11111111-2222-4333-8444-555555555555")
ESP_GUID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
WINDOWS_GUID = uuid.UUID("12345678-9abc-4def-8123-456789abcdef")
MSR_GUID = uuid.UUID("77777777-8888-4999-aaaa-bbbbbbbbbbbb")
INHERITED_ID = uuid.UUID("6efb52bf-1766-41db-a6b3-0ee5eff72bd7")
GLOBAL_SETTINGS_ID = uuid.UUID("7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e")
MEMDIAG_ID = uuid.UUID("b2721d73-1db4-4c62-bf78-c548a880142d")
LOADER_ID = uuid.UUID("3d9d68d3-8b4d-4a78-8f42-2cd6d5f9628f")
DISK_GUID_2 = uuid.UUID("21111111-2222-4333-8444-555555555555")
ESP_GUID_2 = uuid.UUID("baaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
WINDOWS_GUID_2 = uuid.UUID("22345678-9abc-4def-8123-456789abcdef")
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
DISK_SIZE_BYTES = 64 * 1024 * 1024 * 1024


def element(
    element_type,
    *,
    binary_hex=None,
    string_value=None,
    multi_string_value=None,
    registry_type=None,
):
    element_format = (element_type >> 24) & 0xF
    if registry_type is None:
        if element_format in {1, 5, 6, 7}:
            registry_type = BCD_REG_BINARY
        elif element_format in {2, 3}:
            registry_type = BCD_REG_SZ
        else:
            registry_type = BCD_REG_MULTI_SZ
    return BcdOracleElement(
        element_type,
        registry_type,
        binary_hex,
        string_value,
        multi_string_value,
    )


def bcd_guid(value):
    return "{" + str(value) + "}"


def bcd_layout(disk_guid, esp_guid, windows_guid):
    msr_start = BCD_ORACLE_ESP_START_LBA + BCD_ORACLE_ESP_SECTORS
    windows_start = msr_start + BCD_ORACLE_MSR_SECTORS
    total_sectors = DISK_SIZE_BYTES // 512
    aligned_end = ((total_sectors - 33) // 2048) * 2048
    return BcdOracleLayout(
        disk_guid=disk_guid,
        esp_partition_guid=esp_guid,
        msr_partition_guid=MSR_GUID,
        windows_partition_guid=windows_guid,
        disk_size_bytes=DISK_SIZE_BYTES,
        esp_partition_number=1,
        esp_start_lba=BCD_ORACLE_ESP_START_LBA,
        esp_sector_count=BCD_ORACLE_ESP_SECTORS,
        esp_type_guid=BCD_ORACLE_ESP_TYPE_GUID,
        msr_partition_number=2,
        msr_start_lba=msr_start,
        msr_sector_count=BCD_ORACLE_MSR_SECTORS,
        msr_type_guid=BCD_ORACLE_MSR_TYPE_GUID,
        windows_partition_number=3,
        windows_start_lba=windows_start,
        windows_sector_count=aligned_end - windows_start,
        windows_type_guid=BCD_ORACLE_WINDOWS_TYPE_GUID,
        esp_drive="S:",
        windows_drive="W:",
        disposable_virtual_disk_claim=True,
        fresh_store_before_bcdboot=True,
        logical_sector_size=512,
        firmware="UEFI",
    )


def object_by_id(observed, object_id):
    return next(item for item in observed.objects if item.object_id == object_id)


def element_by_type(item, element_type):
    return next(value for value in item.elements if value.element_type == element_type)


def replace_object_element(observed, object_id, element_type, **changes):
    objects = list(observed.objects)
    object_index = next(
        index for index, item in enumerate(objects) if item.object_id == object_id
    )
    item = objects[object_index]
    elements = list(item.elements)
    element_index = next(
        index for index, value in enumerate(elements) if value.element_type == element_type
    )
    elements[element_index] = replace(elements[element_index], **changes)
    objects[object_index] = replace(item, elements=tuple(elements))
    return replace(observed, objects=tuple(objects))


def fixture_for_layout(variant, disk_guid, esp_guid, windows_guid, digest_digit):
    observed = fixture()
    observed = replace(
        observed,
        variant=variant,
        provenance=replace(observed.provenance, store_sha256=digest_digit * 64),
        layout=bcd_layout(disk_guid, esp_guid, windows_guid),
    )
    esp = encode_candidate_gpt_qualified_partition(disk_guid, esp_guid).hex()
    windows = encode_candidate_gpt_qualified_partition(disk_guid, windows_guid).hex()
    observed = replace_object_element(
        observed,
        BCD_BOOT_MANAGER_ID,
        BCD_BOOTMGR_DEVICE_ELEMENT,
        binary_hex=esp,
    )
    observed = replace_object_element(
        observed,
        LOADER_ID,
        BCD_OSLOADER_DEVICE_ELEMENT,
        binary_hex=windows,
    )
    return replace_object_element(
        observed,
        LOADER_ID,
        BCD_OSLOADER_OSDEVICE_ELEMENT,
        binary_hex=windows,
    )


def differential_fixtures():
    return (
        fixture_for_layout("baseline", DISK_GUID, ESP_GUID, WINDOWS_GUID, "2"),
        fixture_for_layout("disk-guid", DISK_GUID_2, ESP_GUID, WINDOWS_GUID, "4"),
        fixture_for_layout("esp-guid", DISK_GUID, ESP_GUID_2, WINDOWS_GUID, "5"),
        fixture_for_layout("windows-guid", DISK_GUID, ESP_GUID, WINDOWS_GUID_2, "6"),
    )


def rename_loader(observed, replacement_id):
    objects = []
    old_text = bcd_guid(LOADER_ID)
    new_text = bcd_guid(replacement_id)
    for item in observed.objects:
        elements = []
        for value in item.elements:
            string_value = value.string_value
            if string_value == old_text:
                string_value = new_text
            multi_string_value = value.multi_string_value
            if multi_string_value is not None:
                multi_string_value = tuple(
                    new_text if member == old_text else member
                    for member in multi_string_value
                )
            elements.append(
                replace(
                    value,
                    string_value=string_value,
                    multi_string_value=multi_string_value,
                )
            )
        objects.append(
            replace(
                item,
                object_id=replacement_id if item.object_id == LOADER_ID else item.object_id,
                elements=tuple(elements),
            )
        )
    return replace(
        observed,
        objects=tuple(sorted(objects, key=lambda item: item.object_id.hex)),
    )


def fixture() -> BcdOracleFixture:
    esp = encode_candidate_gpt_qualified_partition(DISK_GUID, ESP_GUID).hex()
    windows = encode_candidate_gpt_qualified_partition(DISK_GUID, WINDOWS_GUID).hex()
    inherited = BcdOracleObject(
        INHERITED_ID,
        BCD_OBJECT_TYPE_INHERITED | 0x00100000,
        BCD_REG_DWORD,
        (element(0x12000004, string_value="Windows Boot Loader Settings"),),
    )
    global_settings = BcdOracleObject(
        GLOBAL_SETTINGS_ID,
        BCD_OBJECT_TYPE_INHERITED | 0x00100000,
        BCD_REG_DWORD,
        (),
    )
    memdiag = BcdOracleObject(
        MEMDIAG_ID,
        0x10200005,
        BCD_REG_DWORD,
        (element(BCD_BOOTMGR_DEVICE_ELEMENT, binary_hex="0102"),),
    )
    loader = BcdOracleObject(
        LOADER_ID,
        BCD_WINDOWS_OS_LOADER_OBJECT_TYPE,
        BCD_REG_DWORD,
        (
            element(BCD_OSLOADER_DEVICE_ELEMENT, binary_hex=windows),
            element(BCD_LIBRARY_PATH_ELEMENT, string_value="\\Windows\\system32\\winload.efi"),
            element(BCD_LIBRARY_INHERIT_ELEMENT, multi_string_value=(bcd_guid(INHERITED_ID),)),
            element(BCD_RECOVERY_ENABLED_ELEMENT, binary_hex="00"),
            element(BCD_OSLOADER_OSDEVICE_ELEMENT, binary_hex=windows),
            element(BCD_OSLOADER_SYSTEM_ROOT_ELEMENT, string_value="\\Windows"),
        ),
    )
    manager = BcdOracleObject(
        BCD_BOOT_MANAGER_ID,
        BCD_BOOT_MANAGER_OBJECT_TYPE,
        BCD_REG_DWORD,
        (
            element(BCD_BOOTMGR_DEVICE_ELEMENT, binary_hex=esp),
            element(BCD_LIBRARY_PATH_ELEMENT, string_value="\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
            element(BCD_LIBRARY_INHERIT_ELEMENT, multi_string_value=(bcd_guid(GLOBAL_SETTINGS_ID),)),
            element(BCD_BOOTMGR_DEFAULT_ELEMENT, string_value=bcd_guid(LOADER_ID)),
            element(BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT, multi_string_value=(bcd_guid(LOADER_ID),)),
            element(0x24000010, multi_string_value=(bcd_guid(MEMDIAG_ID),)),
        ),
    )
    objects = tuple(
        sorted(
            (inherited, global_settings, memdiag, loader, manager),
            key=lambda item: item.object_id.hex,
        )
    )
    return BcdOracleFixture(
        variant="baseline",
        provenance=BcdOracleProvenance(
            profile="uefi-amd64-offline-no-bootex-v1",
            host_windows_build=26100,
            source_windows_build=26100,
            architecture="amd64",
            source_architecture="amd64",
            source_iso_sha256="6" * 64,
            source_wim_sha256="7" * 64,
            source_wim_index=1,
            source_edition="Windows 11 Enterprise",
            bootex_selected=False,
            efi_boot_directory_precreated=True,
            bcdboot_version="10.0.26100.8037",
            bcdedit_version="10.0.26100.8037",
            bcdboot_path="C:\\Windows\\System32\\bcdboot.exe",
            bcdedit_path="C:\\Windows\\System32\\bcdedit.exe",
            bcdboot_executable_sha256="4" * 64,
            bcdedit_executable_sha256="5" * 64,
            template_sha256="1" * 64,
            store_sha256="2" * 64,
            capture_tool_sha256="3" * 64,
            template_size=65536,
            store_size=65536,
            capture_tool_size=4096,
            bcdboot_argv=(
                "C:\\Windows\\System32\\bcdboot.exe", "W:\\Windows", "/v", "/offline",
                "/f", "UEFI", "/s", "S:",
            ),
            bcdboot_exit_code=0,
            bcdboot_stdout_sha256=EMPTY_SHA256,
            bcdboot_stderr_sha256=EMPTY_SHA256,
            bcdboot_stdout_hex="",
            bcdboot_stderr_hex="",
            bcdedit_set_recovery_argv=(
                "C:\\Windows\\System32\\bcdedit.exe", "/store", "S:\\EFI\\Microsoft\\Boot\\BCD",
                "/set", "{default}", "recoveryenabled", "no",
            ),
            bcdedit_set_recovery_exit_code=0,
            bcdedit_set_recovery_stdout_sha256=EMPTY_SHA256,
            bcdedit_set_recovery_stderr_sha256=EMPTY_SHA256,
            bcdedit_set_recovery_stdout_hex="",
            bcdedit_set_recovery_stderr_hex="",
            bcdedit_argv=(
                "C:\\Windows\\System32\\bcdedit.exe", "/store", "S:\\EFI\\Microsoft\\Boot\\BCD",
                "/enum", "all", "/v",
            ),
            bcdedit_exit_code=0,
            bcdedit_stdout_sha256=EMPTY_SHA256,
            bcdedit_stderr_sha256=EMPTY_SHA256,
            bcdedit_stdout_hex="",
            bcdedit_stderr_hex="",
        ),
        layout=bcd_layout(DISK_GUID, ESP_GUID, WINDOWS_GUID),
        objects=objects,
        root_key_name="BCD00000001",
        root_key_name_registry_type=BCD_REG_SZ,
        root_system=1,
        root_system_registry_type=BCD_REG_DWORD,
        root_treat_as_system=1,
        root_treat_as_system_registry_type=BCD_REG_DWORD,
        root_guid_cache_hex=None,
        root_guid_cache_registry_type=None,
    )


def mutate_payload(payload: bytes, callback) -> bytes:
    document = json.loads(payload)
    callback(document)
    return (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def mutate_document_element(document, object_id, element_type, changes):
    item = next(
        value
        for value in document["objects"]
        if value["object_id"] == bcd_guid(object_id)
    )
    value = next(
        element
        for element in item["elements"]
        if element["element_type"] == f"{element_type:08x}"
    )
    value.update(changes)


class WindowsBcdOracleTests(unittest.TestCase):
    def test_canonical_round_trip_preserves_exact_windows_evidence_claim(self):
        expected = fixture()
        payload = canonical_bcd_oracle_bytes(expected)
        self.assertEqual(parse_bcd_oracle_bytes(payload), expected)
        self.assertEqual(canonical_bcd_oracle_bytes(parse_bcd_oracle_bytes(payload)), payload)
        self.assertLess(len(payload), 16 * 1024)

    def test_required_device_records_bind_mixed_endian_disk_and_partition_guids(self):
        observed = fixture()
        validate_bcd_oracle_fixture(observed)
        manager = object_by_id(observed, BCD_BOOT_MANAGER_ID)
        loader = object_by_id(observed, LOADER_ID)
        esp = bytes.fromhex(
            element_by_type(manager, BCD_BOOTMGR_DEVICE_ELEMENT).binary_hex
        )
        windows = bytes.fromhex(
            element_by_type(loader, BCD_OSLOADER_DEVICE_ELEMENT).binary_hex
        )
        self.assertEqual(esp[0x20:0x30], ESP_GUID.bytes_le)
        self.assertEqual(esp[0x38:0x48], DISK_GUID.bytes_le)
        self.assertEqual(windows[0x20:0x30], WINDOWS_GUID.bytes_le)
        self.assertEqual(windows[0x38:0x48], DISK_GUID.bytes_le)

    def test_rejects_broadened_scope_wrong_paths_recovery_and_ambiguous_loader(self):
        valid = fixture()
        corruptions = (
            replace(valid, windows_generated_claim=False),
            replace(valid, hive_bytes_included=True),
            replace(valid, authorizes_linux_writes=True),
            replace_object_element(
                valid,
                BCD_BOOT_MANAGER_ID,
                BCD_LIBRARY_PATH_ELEMENT,
                string_value="\\EFI\\BOOT\\BOOTX64.EFI",
            ),
            replace_object_element(
                valid,
                LOADER_ID,
                BCD_LIBRARY_PATH_ELEMENT,
                string_value="\\Windows\\system32\\winload.exe",
            ),
            replace_object_element(
                valid,
                LOADER_ID,
                BCD_OSLOADER_SYSTEM_ROOT_ELEMENT,
                string_value="C:\\Windows",
            ),
            replace_object_element(
                valid,
                LOADER_ID,
                BCD_RECOVERY_ENABLED_ELEMENT,
                binary_hex="01",
            ),
        )
        for observed in corruptions:
            with self.subTest(observed=observed), self.assertRaises(BcdError):
                validate_bcd_oracle_fixture(observed)

    def test_rejects_device_identity_registry_type_and_graph_corruption(self):
        valid = fixture()
        objects = list(valid.objects)
        loader_index = next(
            index for index, item in enumerate(objects) if item.object_id == LOADER_ID
        )
        loader = objects[loader_index]
        bad_elements = list(loader.elements)
        bad_elements[0] = replace(bad_elements[0], registry_type=1)
        objects[loader_index] = replace(loader, elements=tuple(bad_elements))
        bad_registry = replace(valid, objects=tuple(objects))

        wrong_device = bytearray.fromhex(
            next(
                item for item in valid.objects if item.object_id == LOADER_ID
            ).elements[0].binary_hex
        )
        wrong_device[0x38] ^= 1
        objects = list(valid.objects)
        bad_device_elements = list(loader.elements)
        bad_device_elements[0] = replace(
            bad_device_elements[0],
            binary_hex=wrong_device.hex(),
        )
        objects[loader_index] = replace(loader, elements=tuple(bad_device_elements))
        bad_device = replace(valid, objects=tuple(objects))
        for observed in (bad_registry, bad_device):
            with self.subTest(observed=observed), self.assertRaises(BcdError):
                validate_bcd_oracle_fixture(observed)

    def test_json_parser_rejects_duplicates_noncanonical_bytes_and_unknown_fields(self):
        payload = canonical_bcd_oracle_bytes(fixture())
        duplicate = payload.replace(
            b'{"layout":',
            b'{"layout":{},"layout":',
            1,
        )
        unknown = mutate_payload(payload, lambda document: document.update({"extra": 1}))
        for candidate in (
            duplicate,
            unknown,
            b"\xef\xbb\xbf" + payload,
            payload.replace(b'"schema":', b' "schema":', 1),
            payload[:-1],
        ):
            with self.subTest(candidate=candidate[:80]), self.assertRaises(BcdError):
                parse_bcd_oracle_bytes(candidate)

    def test_json_parser_normalizes_integer_and_recursion_resource_failures(self):
        oversized_integer = b'{"x":' + b"1" * 5000 + b"}"
        deeply_nested = b"[" * 100_000 + b"0" + b"]" * 100_000
        for candidate in (oversized_integer, deeply_nested):
            with self.subTest(size=len(candidate)), self.assertRaises(BcdError):
                parse_bcd_oracle_bytes(candidate)

    def test_json_parser_rejects_semantic_mutations_even_when_canonical(self):
        payload = canonical_bcd_oracle_bytes(fixture())
        mutations = (
            lambda document: document["layout"].update({"logical_sector_size": 4096}),
            lambda document: document["provenance"].update({"architecture": "arm64"}),
            lambda document: document["provenance"].update({"template_sha256": "0" * 64}),
            lambda document: document["scope"].update({"authorizes_linux_writes": True}),
            lambda document: mutate_document_element(
                document,
                LOADER_ID,
                BCD_RECOVERY_ENABLED_ELEMENT,
                {"binary_hex": "01"},
            ),
            lambda document: mutate_document_element(
                document,
                BCD_BOOT_MANAGER_ID,
                BCD_BOOTMGR_DEFAULT_ELEMENT,
                {"string_value": "{ffffffff-ffff-4fff-8fff-ffffffffffff}"},
            ),
        )
        for mutation in mutations:
            candidate = mutate_payload(payload, mutation)
            with self.subTest(candidate=candidate[:120]), self.assertRaises(BcdError):
                parse_bcd_oracle_bytes(candidate)

    def test_typed_registry_values_match_bcd_format_nibbles_and_bind_semantics(self):
        observed = fixture()
        manager = object_by_id(observed, BCD_BOOT_MANAGER_ID)
        loader = object_by_id(observed, LOADER_ID)
        expected = {
            BCD_BOOTMGR_DEVICE_ELEMENT: BCD_REG_BINARY,
            BCD_LIBRARY_PATH_ELEMENT: BCD_REG_SZ,
            BCD_LIBRARY_INHERIT_ELEMENT: BCD_REG_MULTI_SZ,
            BCD_BOOTMGR_DEFAULT_ELEMENT: BCD_REG_SZ,
            BCD_BOOTMGR_DISPLAY_ORDER_ELEMENT: BCD_REG_MULTI_SZ,
            0x24000010: BCD_REG_MULTI_SZ,
        }
        for value in manager.elements:
            self.assertEqual(value.registry_type, expected[value.element_type])
        self.assertEqual(
            element_by_type(loader, BCD_LIBRARY_INHERIT_ELEMENT).registry_type,
            BCD_REG_MULTI_SZ,
        )
        self.assertEqual(
            element_by_type(loader, BCD_RECOVERY_ENABLED_ELEMENT).binary_hex,
            "00",
        )
        corruptions = (
            replace_object_element(
                observed,
                BCD_BOOT_MANAGER_ID,
                BCD_LIBRARY_PATH_ELEMENT,
                registry_type=BCD_REG_BINARY,
            ),
            replace_object_element(
                observed,
                BCD_BOOT_MANAGER_ID,
                BCD_LIBRARY_PATH_ELEMENT,
                registry_type=True,
            ),
            replace_object_element(
                observed,
                BCD_BOOT_MANAGER_ID,
                BCD_BOOTMGR_DEFAULT_ELEMENT,
                string_value=bcd_guid(INHERITED_ID),
            ),
            replace_object_element(
                observed,
                LOADER_ID,
                BCD_RECOVERY_ENABLED_ELEMENT,
                binary_hex="0000",
            ),
        )
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt), self.assertRaises(BcdError):
                validate_bcd_oracle_fixture(corrupt)

    def test_parser_and_validator_fail_closed_on_wrong_types_and_invalid_unicode(self):
        payload = canonical_bcd_oracle_bytes(fixture())
        wrong_type = mutate_payload(
            payload,
            lambda document: mutate_document_element(
                document,
                BCD_BOOT_MANAGER_ID,
                BCD_LIBRARY_PATH_ELEMENT,
                {"string_value": 7},
            ),
        )
        with self.assertRaises(BcdError):
            parse_bcd_oracle_bytes(wrong_type)
        invalid_unicode = replace_object_element(
            fixture(),
            BCD_BOOT_MANAGER_ID,
            BCD_LIBRARY_PATH_ELEMENT,
            string_value="\ud800",
        )
        with self.assertRaises(BcdError):
            validate_bcd_oracle_fixture(invalid_unicode)

    def test_canonical_serializer_and_parser_enforce_same_one_mibibyte_limit(self):
        observed = fixture()
        oversized_elements = tuple(
            element(0x11000100 + index, binary_hex="aa" * 4096)
            for index in range(128)
        )
        oversized_object = BcdOracleObject(
            uuid.UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
            BCD_OBJECT_TYPE_INHERITED | 0x00100000,
            BCD_REG_DWORD,
            oversized_elements,
        )
        oversized = replace(
            observed,
            objects=tuple(
                sorted(
                    (*observed.objects, oversized_object),
                    key=lambda item: item.object_id.hex,
                )
            ),
        )
        with self.assertRaises(BcdError):
            validate_bcd_oracle_fixture(oversized)
        with self.assertRaises(BcdError):
            canonical_bcd_oracle_bytes(oversized)
        with self.assertRaises(BcdError):
            parse_bcd_oracle_bytes(b" " * (BCD_ORACLE_MAX_BYTES + 1))

    def test_frozen_offline_profile_records_recovery_mutation_and_minimum_host(self):
        observed = fixture()
        corruptions = (
            replace(
                observed,
                provenance=replace(observed.provenance, host_windows_build=26000),
            ),
            replace(
                observed,
                provenance=replace(
                    observed.provenance,
                    bcdboot_version="10.0.26100.8036",
                ),
            ),
            replace(
                observed,
                provenance=replace(
                    observed.provenance,
                    bcdedit_set_recovery_argv=(
                        "bcdedit.exe",
                        "/store",
                        "S:\\EFI\\Microsoft\\Boot\\BCD",
                        "/enum",
                        "all",
                        "/v",
                    ),
                ),
            ),
        )
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt), self.assertRaises(BcdError):
                validate_bcd_oracle_fixture(corrupt)

    def test_provenance_root_and_gpt_geometry_are_independently_bound(self):
        observed = fixture()
        corruptions = (
            replace(
                observed,
                provenance=replace(
                    observed.provenance,
                    bcdboot_stdout_hex="00",
                ),
            ),
            replace(
                observed,
                provenance=replace(
                    observed.provenance,
                    bcdboot_exit_code=1,
                ),
            ),
            replace(
                observed,
                provenance=replace(
                    observed.provenance,
                    bootex_selected=True,
                ),
            ),
            replace(
                observed,
                layout=replace(
                    observed.layout,
                    esp_partition_number=True,
                ),
            ),
            replace(
                observed,
                layout=replace(
                    observed.layout,
                    windows_sector_count=observed.layout.windows_sector_count - 1,
                ),
            ),
            replace(
                observed,
                layout=replace(
                    observed.layout,
                    fresh_store_before_bcdboot=False,
                ),
            ),
            replace(observed, root_key_name_registry_type=BCD_REG_BINARY),
            replace(observed, root_key_name_registry_type=True),
            replace(observed, root_system=None, root_system_registry_type=BCD_REG_DWORD),
            replace(observed, root_system=True),
        )
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt), self.assertRaises(BcdError):
                validate_bcd_oracle_fixture(corrupt)

    def test_differential_set_proves_one_guid_mutation_and_exact_device_dependencies(self):
        fixtures = differential_fixtures()
        validate_bcd_oracle_differential_set(fixtures)
        baseline, disk_variant, esp_variant, windows_variant = fixtures

        def device_bytes(observed, object_id, element_type):
            return bytes.fromhex(
                element_by_type(
                    object_by_id(observed, object_id),
                    element_type,
                ).binary_hex
            )

        baseline_manager = device_bytes(
            baseline,
            BCD_BOOT_MANAGER_ID,
            BCD_BOOTMGR_DEVICE_ELEMENT,
        )
        disk_manager = device_bytes(
            disk_variant,
            BCD_BOOT_MANAGER_ID,
            BCD_BOOTMGR_DEVICE_ELEMENT,
        )
        esp_manager = device_bytes(
            esp_variant,
            BCD_BOOT_MANAGER_ID,
            BCD_BOOTMGR_DEVICE_ELEMENT,
        )
        windows_manager = device_bytes(
            windows_variant,
            BCD_BOOT_MANAGER_ID,
            BCD_BOOTMGR_DEVICE_ELEMENT,
        )
        self.assertEqual(baseline_manager[:0x38], disk_manager[:0x38])
        self.assertEqual(baseline_manager[0x48:], disk_manager[0x48:])
        self.assertNotEqual(baseline_manager[0x38:0x48], disk_manager[0x38:0x48])
        self.assertEqual(baseline_manager[:0x20], esp_manager[:0x20])
        self.assertEqual(baseline_manager[0x30:], esp_manager[0x30:])
        self.assertNotEqual(baseline_manager[0x20:0x30], esp_manager[0x20:0x30])
        self.assertEqual(baseline_manager, windows_manager)

    def test_differential_set_alpha_normalizes_only_the_selected_loader(self):
        replacements = (
            LOADER_ID,
            uuid.UUID("4d9d68d3-8b4d-4a78-8f42-2cd6d5f9628f"),
            uuid.UUID("5d9d68d3-8b4d-4a78-8f42-2cd6d5f9628f"),
            uuid.UUID("6d9d68d3-8b4d-4a78-8f42-2cd6d5f9628f"),
        )
        fixtures = tuple(
            rename_loader(observed, replacement_id)
            for observed, replacement_id in zip(
                differential_fixtures(),
                replacements,
                strict=True,
            )
        )
        validate_bcd_oracle_differential_set(fixtures)

    def test_differential_set_rejects_missing_noop_stale_and_semantic_drift(self):
        fixtures = differential_fixtures()
        with self.assertRaises(BcdError):
            validate_bcd_oracle_differential_set(fixtures[:-1])
        duplicate_digest = list(fixtures)
        duplicate_digest[1] = replace(
            duplicate_digest[1],
            provenance=replace(
                duplicate_digest[1].provenance,
                store_sha256=fixtures[0].provenance.store_sha256,
            ),
        )
        stale_device = list(fixtures)
        baseline_loader_device = element_by_type(
            object_by_id(fixtures[0], LOADER_ID),
            BCD_OSLOADER_DEVICE_ELEMENT,
        ).binary_hex
        stale_device[1] = replace_object_element(
            stale_device[1],
            LOADER_ID,
            BCD_OSLOADER_DEVICE_ELEMENT,
            binary_hex=baseline_loader_device,
        )
        semantic_drift = list(fixtures)
        semantic_drift[2] = replace_object_element(
            semantic_drift[2],
            LOADER_ID,
            BCD_OSLOADER_SYSTEM_ROOT_ELEMENT,
            string_value="\\WINDOWS2",
        )
        for corrupt in (tuple(duplicate_digest), tuple(stale_device), tuple(semantic_drift)):
            with self.subTest(corrupt=corrupt), self.assertRaises(BcdError):
                validate_bcd_oracle_differential_set(corrupt)


if __name__ == "__main__":
    unittest.main()
