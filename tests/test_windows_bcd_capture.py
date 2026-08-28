# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace

from isopropyl.windows_bcd import BcdError
from isopropyl.windows_bcd_capture import (
    RAW_BCD_CAPTURE_MAX_BYTES,
    RAW_BCD_CAPTURE_SCHEMA,
    VerifiedArtifactReceipt,
    derive_bcd_oracle_fixtures,
    parse_raw_bcd_capture_bytes,
)
from isopropyl.windows_bcd_hivex import BcdHiveObservation
from isopropyl.windows_bcd_oracle import (
    BCD_ORACLE_ESP_SECTORS,
    BCD_ORACLE_ESP_START_LBA,
    BCD_ORACLE_LOGICAL_SECTOR_SIZE,
    BCD_ORACLE_MSR_SECTORS,
)
from tests.test_windows_bcd_oracle import differential_fixtures


def observation(fixture) -> BcdHiveObservation:
    return BcdHiveObservation(
        store_sha256=fixture.provenance.store_sha256,
        store_size=fixture.provenance.store_size,
        objects=fixture.objects,
        root_key_name=fixture.root_key_name,
        root_key_name_registry_type=fixture.root_key_name_registry_type,
        root_system=fixture.root_system,
        root_system_registry_type=fixture.root_system_registry_type,
        root_treat_as_system=fixture.root_treat_as_system,
        root_treat_as_system_registry_type=fixture.root_treat_as_system_registry_type,
        root_guid_cache_hex=fixture.root_guid_cache_hex,
        root_guid_cache_registry_type=fixture.root_guid_cache_registry_type,
    )


def command(argv, exit_code, stdout_hex, stderr_hex):
    return {
        "stderr_base64": base64.b64encode(bytes.fromhex(stderr_hex)).decode("ascii"),
        "argv": list(argv),
        "stdout_base64": base64.b64encode(bytes.fromhex(stdout_hex)).decode("ascii"),
        "exit_code": exit_code,
    }


def capture_fixtures():
    fixtures = []
    for fixture in differential_fixtures():
        enumeration = f"Windows BCD enumeration: {fixture.variant}\r\n".encode("utf-8")
        fixtures.append(
            replace(
                fixture,
                provenance=replace(
                    fixture.provenance,
                    bcdedit_stdout_hex=enumeration.hex(),
                    bcdedit_stdout_sha256=hashlib.sha256(enumeration).hexdigest(),
                ),
            ),
        )
    return tuple(fixtures)


def raw_document():
    fixtures = capture_fixtures()
    provenance = fixtures[0].provenance
    layout = fixtures[0].layout
    captures = []
    for fixture in reversed(fixtures):
        item = fixture.provenance
        captures.append(
            {
                "windows_partition_guid": str(fixture.layout.windows_partition_guid),
                "variant": fixture.variant,
                "store": {"sha256": item.store_sha256, "size": item.store_size},
                "esp_partition_guid": str(fixture.layout.esp_partition_guid),
                "disk_guid": str(fixture.layout.disk_guid),
                "commands": {
                    "bcdedit_enum": command(
                        item.bcdedit_argv,
                        item.bcdedit_exit_code,
                        item.bcdedit_stdout_hex,
                        item.bcdedit_stderr_hex,
                    ),
                    "bcdboot": command(
                        item.bcdboot_argv,
                        item.bcdboot_exit_code,
                        item.bcdboot_stdout_hex,
                        item.bcdboot_stderr_hex,
                    ),
                    "bcdedit_set_recovery": command(
                        item.bcdedit_set_recovery_argv,
                        item.bcdedit_set_recovery_exit_code,
                        item.bcdedit_set_recovery_stdout_hex,
                        item.bcdedit_set_recovery_stderr_hex,
                    ),
                },
            },
        )
    return {
        "captures": captures,
        "schema": RAW_BCD_CAPTURE_SCHEMA,
        "profile": {
            "template": {
                "sha256": provenance.template_sha256,
                "size": provenance.template_size,
            },
            "source_windows_build": provenance.source_windows_build,
            "source_wim_sha256": provenance.source_wim_sha256,
            "source_wim_index": provenance.source_wim_index,
            "source_iso_sha256": provenance.source_iso_sha256,
            "source_edition": provenance.source_edition,
            "msr_partition_guid": str(layout.msr_partition_guid),
            "host_windows_build": provenance.host_windows_build,
            "disk_size_bytes": layout.disk_size_bytes,
            "collector": {
                "sha256": provenance.capture_tool_sha256,
                "size": provenance.capture_tool_size,
            },
            "bcdedit": {
                "version": provenance.bcdedit_version,
                "path": provenance.bcdedit_path,
                "executable_sha256": provenance.bcdedit_executable_sha256,
            },
            "bcdboot": {
                "version": provenance.bcdboot_version,
                "path": provenance.bcdboot_path,
                "executable_sha256": provenance.bcdboot_executable_sha256,
            },
        },
    }


def payload(document=None) -> bytes:
    return json.dumps(
        raw_document() if document is None else document,
        indent=2,
        ensure_ascii=True,
    ).encode("ascii")


class WindowsBcdCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = capture_fixtures()
        self.observations = {
            fixture.variant: observation(fixture) for fixture in self.expected
        }
        provenance = self.expected[0].provenance
        self.collector = VerifiedArtifactReceipt(
            provenance.capture_tool_size,
            provenance.capture_tool_sha256,
        )
        self.template = VerifiedArtifactReceipt(
            provenance.template_size,
            provenance.template_sha256,
        )

    def derive(self, document=None):
        bundle = parse_raw_bcd_capture_bytes(payload(document))
        return derive_bcd_oracle_fixtures(
            bundle,
            self.observations,
            collector_receipt=self.collector,
            template_receipt=self.template,
        )

    def test_noncanonical_raw_document_derives_exact_canonical_cohort(self) -> None:
        result = self.derive()
        self.assertEqual(result, self.expected)
        self.assertEqual(tuple(item.variant for item in result), (
            "baseline",
            "disk-guid",
            "esp-guid",
            "windows-guid",
        ))
        self.assertEqual(
            result[0].provenance.bcdboot_stdout_sha256,
            hashlib.sha256(bytes.fromhex(result[0].provenance.bcdboot_stdout_hex)).hexdigest(),
        )

    def test_registry_tree_and_unknown_fields_are_rejected(self) -> None:
        for field in ("objects", "root_description", "scope", "authorizes_linux_writes"):
            document = raw_document()
            document[field] = []
            with self.subTest(field=field), self.assertRaises(BcdError):
                parse_raw_bcd_capture_bytes(payload(document))
        document = raw_document()
        document["captures"][0]["objects"] = []
        with self.assertRaises(BcdError):
            parse_raw_bcd_capture_bytes(payload(document))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        encoded = payload()
        duplicate = encoded.replace(
            b'{\n  "captures"',
            b'{\n  "schema": "' + RAW_BCD_CAPTURE_SCHEMA.encode("ascii") + b'",\n  "captures"',
            1,
        )
        with self.assertRaisesRegex(BcdError, "repeats key"):
            parse_raw_bcd_capture_bytes(duplicate)

    def test_json_encoding_size_depth_and_number_forms_are_strict(self) -> None:
        invalid = (
            b"\xef\xbb\xbf" + payload(),
            "{}".encode("utf-16-le"),
            b"[" * 17 + b"0" + b"]" * 17,
            b"x" * (RAW_BCD_CAPTURE_MAX_BYTES + 1),
            payload().replace(b'"host_windows_build": 26100', b'"host_windows_build": 26100.0'),
            payload().replace(b'"host_windows_build": 26100', b'"host_windows_build": true'),
        )
        for value in invalid:
            with self.subTest(prefix=value[:20]), self.assertRaises(BcdError):
                parse_raw_bcd_capture_bytes(value)

    def test_hash_guid_and_version_forms_are_canonical(self) -> None:
        mutations = []
        document = raw_document()
        document["profile"]["source_iso_sha256"] = "A" * 64
        mutations.append(document)
        document = raw_document()
        document["profile"]["msr_partition_guid"] = document["profile"][
            "msr_partition_guid"
        ].upper()
        mutations.append(document)
        document = raw_document()
        document["profile"]["bcdboot"]["version"] = "10.0.026100.8037"
        mutations.append(document)
        for document in mutations:
            with self.subTest(document=document), self.assertRaises(BcdError):
                parse_raw_bcd_capture_bytes(payload(document))

    def test_base64_is_canonical_bounded_and_binary_safe(self) -> None:
        document = raw_document()
        document["captures"][0]["commands"]["bcdboot"]["stdout_base64"] = "YQ"
        with self.assertRaises(BcdError):
            parse_raw_bcd_capture_bytes(payload(document))

        document = raw_document()
        document["captures"][0]["commands"]["bcdedit_enum"]["stdout_base64"] = ""
        with self.assertRaisesRegex(BcdError, "enum stdout is empty"):
            parse_raw_bcd_capture_bytes(payload(document))

        document = raw_document()
        binary_output = b"\0\xff\r\n"
        baseline = next(
            item for item in document["captures"] if item["variant"] == "baseline"
        )
        baseline["commands"]["bcdboot"]["stdout_base64"] = base64.b64encode(
            binary_output,
        ).decode("ascii")
        derived = self.derive(document)[0]
        self.assertEqual(derived.provenance.bcdboot_stdout_hex, binary_output.hex())
        self.assertEqual(
            derived.provenance.bcdboot_stdout_sha256,
            hashlib.sha256(binary_output).hexdigest(),
        )
        document = raw_document()
        document["captures"][0]["commands"]["bcdboot"]["stdout_base64"] = base64.b64encode(
            b"x" * (64 * 1024 + 1),
        ).decode("ascii")
        with self.assertRaises(BcdError):
            parse_raw_bcd_capture_bytes(payload(document))

    def test_variant_set_is_exact_but_input_order_is_not_canonical(self) -> None:
        document = raw_document()
        document["captures"][0]["variant"] = document["captures"][1]["variant"]
        with self.assertRaises(BcdError):
            parse_raw_bcd_capture_bytes(payload(document))
        document = raw_document()
        document["captures"] = document["captures"][:-1]
        with self.assertRaises(BcdError):
            parse_raw_bcd_capture_bytes(payload(document))

    def test_verified_artifact_and_store_receipts_must_match(self) -> None:
        bundle = parse_raw_bcd_capture_bytes(payload())
        with self.assertRaisesRegex(BcdError, "collector receipt"):
            derive_bcd_oracle_fixtures(
                bundle,
                self.observations,
                collector_receipt=replace(self.collector, size=self.collector.size + 1),
                template_receipt=self.template,
            )
        with self.assertRaisesRegex(BcdError, "template receipt"):
            derive_bcd_oracle_fixtures(
                bundle,
                self.observations,
                collector_receipt=self.collector,
                template_receipt=replace(self.template, sha256="a" * 64),
            )
        changed = dict(self.observations)
        changed["baseline"] = replace(changed["baseline"], store_sha256="a" * 64)
        with self.assertRaisesRegex(BcdError, "store claim"):
            derive_bcd_oracle_fixtures(
                bundle,
                changed,
                collector_receipt=self.collector,
                template_receipt=self.template,
            )
        changed = dict(self.observations)
        changed["baseline"] = replace(changed["baseline"], store_size=1)
        with self.assertRaisesRegex(BcdError, "store claim"):
            derive_bcd_oracle_fixtures(
                bundle,
                changed,
                collector_receipt=self.collector,
                template_receipt=self.template,
            )

    def test_observation_mapping_is_exact_and_typed(self) -> None:
        bundle = parse_raw_bcd_capture_bytes(payload())
        for observations in (
            {key: value for key, value in self.observations.items() if key != "baseline"},
            {**self.observations, "extra": self.observations["baseline"]},
            {**self.observations, "baseline": object()},
        ):
            with self.subTest(keys=observations.keys()), self.assertRaises(BcdError):
                derive_bcd_oracle_fixtures(
                    bundle,
                    observations,
                    collector_receipt=self.collector,
                    template_receipt=self.template,
                )
        with self.assertRaisesRegex(BcdError, "parsed RAW"):
            derive_bcd_oracle_fixtures(
                replace(bundle, schema="unsupported"),
                self.observations,
                collector_receipt=self.collector,
                template_receipt=self.template,
            )
        for forged in (
            replace(bundle, disk_size_bytes="not-an-integer"),
            replace(bundle, bcdboot=object()),
            replace(bundle, captures=(replace(bundle.captures[0], bcdboot=object()),) + bundle.captures[1:]),
        ):
            with self.subTest(forged=forged), self.assertRaises(BcdError):
                derive_bcd_oracle_fixtures(
                    forged,
                    self.observations,
                    collector_receipt=self.collector,
                    template_receipt=self.template,
                )

    def test_disk_geometry_boundaries_are_explicitly_validated(self) -> None:
        windows_start = (
            BCD_ORACLE_ESP_START_LBA
            + BCD_ORACLE_ESP_SECTORS
            + BCD_ORACLE_MSR_SECTORS
        )
        first_aligned_end = ((windows_start // 2048) + 1) * 2048
        first_valid_size = (
            first_aligned_end + 33
        ) * BCD_ORACLE_LOGICAL_SECTOR_SIZE
        for disk_size in (1, first_valid_size - BCD_ORACLE_LOGICAL_SECTOR_SIZE, first_valid_size + 1):
            document = raw_document()
            document["profile"]["disk_size_bytes"] = disk_size
            with self.subTest(disk_size=disk_size), self.assertRaises(BcdError):
                self.derive(document)

        document = raw_document()
        document["profile"]["disk_size_bytes"] = first_valid_size
        self.assertEqual(
            self.derive(document)[0].layout.windows_sector_count,
            first_aligned_end - windows_start,
        )

        largest_aligned_uint64 = ((1 << 64) - 1) // 512 * 512
        document = raw_document()
        document["profile"]["disk_size_bytes"] = largest_aligned_uint64
        self.assertEqual(
            self.derive(document)[0].layout.disk_size_bytes,
            largest_aligned_uint64,
        )

    def test_existing_oracle_validation_rejects_raw_semantic_drift(self) -> None:
        document = raw_document()
        # The disk-guid variant must change only its disk GUID.
        disk_variant = next(
            item for item in document["captures"] if item["variant"] == "disk-guid"
        )
        esp_variant = next(
            item for item in document["captures"] if item["variant"] == "esp-guid"
        )
        disk_variant["esp_partition_guid"] = esp_variant["esp_partition_guid"]
        with self.assertRaises(BcdError):
            self.derive(document)

        document = raw_document()
        document["captures"][0]["commands"]["bcdboot"]["argv"][-1] = "T:"
        with self.assertRaises(BcdError):
            self.derive(document)


if __name__ == "__main__":
    unittest.main()
