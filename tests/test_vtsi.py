from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.vtsi import (
    VTSI_MAX_DISK_BYTES,
    VTSI_MAX_READ_BYTES,
    VTSI_MAX_SEGMENTS,
    VTSI_SECTOR_BYTES,
    VtsiChanged,
    VtsiPlan,
    VtsiSafetyError,
    inspect_vtsi,
    inspect_vtsi_descriptor,
    iter_vtsi_chunks,
    read_vtsi_at,
    validate_vtsi_plan,
)


FOOTER = struct.Struct("<8sHHQIIIIQ")
SEGMENT = struct.Struct("<QQQ")
FOOTER_BYTES = 512
FOOTER_CHECKSUM_OFFSET = 24
SEGMENT_COUNT_OFFSET = 28
SEGMENT_CHECKSUM_OFFSET = 32
SEGMENT_OFFSET_OFFSET = 36
DISK_SIZE_OFFSET = 12
DISK_SIGNATURE_OFFSET = 20
VERSION_MAJOR_OFFSET = 8
VERSION_MINOR_OFFSET = 10
RESERVED_OFFSET = FOOTER.size
SIGNATURE = 0x78563412


def checksum(payload: bytes) -> int:
    return (~sum(payload)) & 0xFFFFFFFF


def build_vtsi(
    path: Path,
    *,
    disk_sectors: int = 12,
    segments: tuple[tuple[int, bytes], ...] | None = None,
) -> tuple[bytes, tuple[tuple[int, bytes], ...]]:
    if segments is None:
        sector_zero = bytearray(b"A" * VTSI_SECTOR_BYTES)
        sector_zero[440:444] = SIGNATURE.to_bytes(4, "little")
        segments = (
            (0, bytes(sector_zero)),
            (3, b"B" * (2 * VTSI_SECTOR_BYTES)),
            (disk_sectors - 1, b"Z" * VTSI_SECTOR_BYTES),
        )
    data = bytearray()
    records = bytearray()
    for disk_start, payload in segments:
        if len(payload) % VTSI_SECTOR_BYTES:
            raise ValueError("test segment payloads must be sector aligned")
        records.extend(SEGMENT.pack(
            disk_start,
            len(payload) // VTSI_SECTOR_BYTES,
            len(data),
        ))
        data.extend(payload)
    segment_offset = len(data)
    padding = b"\x00" * (-len(records) % VTSI_SECTOR_BYTES)
    footer = bytearray(FOOTER_BYTES)
    FOOTER.pack_into(
        footer,
        0,
        b"VENTOY\x00\x00",
        1,
        0,
        disk_sectors * VTSI_SECTOR_BYTES,
        SIGNATURE,
        0,
        len(segments),
        checksum(bytes(records)),
        segment_offset,
    )
    footer[FOOTER_CHECKSUM_OFFSET:FOOTER_CHECKSUM_OFFSET + 4] = checksum(
        bytes(footer)
    ).to_bytes(4, "little")
    path.write_bytes(bytes(data) + bytes(records) + padding + bytes(footer))
    expanded = bytearray(disk_sectors * VTSI_SECTOR_BYTES)
    for disk_start, payload in segments:
        offset = disk_start * VTSI_SECTOR_BYTES
        expanded[offset:offset + len(payload)] = payload
    return bytes(expanded), segments


def footer_offset(payload: bytearray) -> int:
    return len(payload) - FOOTER_BYTES


def repair_footer_checksum(payload: bytearray) -> None:
    start = footer_offset(payload)
    footer = bytearray(payload[start:])
    footer[FOOTER_CHECKSUM_OFFSET:FOOTER_CHECKSUM_OFFSET + 4] = b"\x00" * 4
    payload[
        start + FOOTER_CHECKSUM_OFFSET:start + FOOTER_CHECKSUM_OFFSET + 4
    ] = checksum(bytes(footer)).to_bytes(4, "little")


def mutate_footer_u16(payload: bytearray, offset: int, value: int) -> None:
    start = footer_offset(payload)
    struct.pack_into("<H", payload, start + offset, value)
    repair_footer_checksum(payload)


def mutate_footer_u32(payload: bytearray, offset: int, value: int) -> None:
    start = footer_offset(payload)
    struct.pack_into("<I", payload, start + offset, value)
    repair_footer_checksum(payload)


def mutate_footer_u64(payload: bytearray, offset: int, value: int) -> None:
    start = footer_offset(payload)
    struct.pack_into("<Q", payload, start + offset, value)
    repair_footer_checksum(payload)


def mutate_segment(
    payload: bytearray,
    index: int,
    field: int,
    value: int,
) -> None:
    start = footer_offset(payload)
    segment_count = struct.unpack_from("<I", payload, start + SEGMENT_COUNT_OFFSET)[0]
    table_offset = struct.unpack_from("<Q", payload, start + SEGMENT_OFFSET_OFFSET)[0]
    struct.pack_into("<Q", payload, table_offset + index * SEGMENT.size + field * 8, value)
    table = bytes(payload[table_offset:table_offset + segment_count * SEGMENT.size])
    struct.pack_into(
        "<I",
        payload,
        start + SEGMENT_CHECKSUM_OFFSET,
        checksum(table),
    )
    repair_footer_checksum(payload)


class CancellationSignal(OSError):
    pass


class VtsiTests(unittest.TestCase):
    def open_bound(self, path: Path) -> tuple[int, VtsiPlan]:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            plan = inspect_vtsi_descriptor(descriptor, path.absolute())
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, plan

    def assert_rejected(self, path: Path, payload: bytes, pattern: str) -> None:
        path.write_bytes(payload)
        with self.assertRaisesRegex(VtsiSafetyError, pattern):
            inspect_vtsi(path)

    def test_inspects_valid_v1_and_exposes_exact_expanded_view(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VentoySparseImg.vtsi"
            expanded, source_segments = build_vtsi(path)
            descriptor, plan = self.open_bound(path)
            try:
                self.assertEqual(plan.path, path.absolute())
                self.assertEqual((plan.version_major, plan.version_minor), (1, 0))
                self.assertEqual(plan.disk_size, len(expanded))
                self.assertEqual(plan.disk_signature, SIGNATURE)
                self.assertEqual(len(plan.segments), len(source_segments))
                self.assertEqual(
                    [segment.data_offset for segment in plan.segments],
                    [0, VTSI_SECTOR_BYTES, 3 * VTSI_SECTOR_BYTES],
                )
                self.assertEqual(
                    read_vtsi_at(descriptor, plan, 0, len(expanded)),
                    expanded,
                )
                self.assertEqual(
                    b"".join(iter_vtsi_chunks(descriptor, plan, chunk_size=777)),
                    expanded,
                )
                validate_vtsi_plan(descriptor, plan)
            finally:
                os.close(descriptor)

    def test_random_reads_map_data_and_zero_gaps_without_disk_sized_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.vtsi"
            expanded, _ = build_vtsi(path, disk_sectors=64)
            descriptor, plan = self.open_bound(path)
            try:
                for offset, length in (
                    (0, 0),
                    (plan.disk_size, 0),
                    (17, 101),
                    (500, 40),
                    (VTSI_SECTOR_BYTES, 2 * VTSI_SECTOR_BYTES),
                    (3 * VTSI_SECTOR_BYTES - 9, 2 * VTSI_SECTOR_BYTES + 23),
                    (plan.disk_size - 600, 600),
                ):
                    with self.subTest(offset=offset, length=length):
                        self.assertEqual(
                            read_vtsi_at(descriptor, plan, offset, length),
                            expanded[offset:offset + length],
                        )
            finally:
                os.close(descriptor)

    def test_out_of_disk_order_segments_preserve_catalog_data_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "official-write-order.vtsi"
            sector_zero = bytearray(b"A" * VTSI_SECTOR_BYTES)
            sector_zero[440:444] = SIGNATURE.to_bytes(4, "little")
            expanded, stored = build_vtsi(
                path,
                disk_sectors=16,
                segments=(
                    (14, b"Z" * VTSI_SECTOR_BYTES),
                    (3, b"C" * (2 * VTSI_SECTOR_BYTES)),
                    (0, bytes(sector_zero)),
                    (9, b"N" * VTSI_SECTOR_BYTES),
                ),
            )
            descriptor, plan = self.open_bound(path)
            try:
                self.assertEqual(
                    tuple(segment.disk_start_sector for segment in plan.segments),
                    tuple(start for start, _payload in stored),
                )
                self.assertEqual(
                    read_vtsi_at(
                        descriptor,
                        plan,
                        2 * VTSI_SECTOR_BYTES,
                        13 * VTSI_SECTOR_BYTES,
                    ),
                    expanded[2 * VTSI_SECTOR_BYTES:15 * VTSI_SECTOR_BYTES],
                )
                self.assertEqual(
                    b"".join(iter_vtsi_chunks(
                        descriptor, plan, chunk_size=613,
                    )),
                    expanded,
                )
            finally:
                os.close(descriptor)

    def test_footer_magic_version_checksum_and_reserved_bytes_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.vtsi"
            build_vtsi(original_path)
            original = bytearray(original_path.read_bytes())
            cases: list[tuple[str, bytearray, str]] = []

            broken = bytearray(original)
            broken[footer_offset(broken)] ^= 1
            cases.append(("magic", broken, "magic"))
            broken = bytearray(original)
            mutate_footer_u16(broken, VERSION_MAJOR_OFFSET, 2)
            cases.append(("major", broken, "version"))
            broken = bytearray(original)
            mutate_footer_u16(broken, VERSION_MINOR_OFFSET, 1)
            cases.append(("minor", broken, "version"))
            broken = bytearray(original)
            broken[footer_offset(broken) + FOOTER_CHECKSUM_OFFSET] ^= 1
            cases.append(("checksum", broken, "footer checksum"))
            broken = bytearray(original)
            broken[footer_offset(broken) + RESERVED_OFFSET] = 1
            repair_footer_checksum(broken)
            cases.append(("reserved", broken, "reserved"))

            for name, payload, pattern in cases:
                with self.subTest(name=name):
                    self.assert_rejected(root / f"{name}.vtsi", payload, pattern)

    def test_disk_size_and_segment_count_bounds_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.vtsi"
            build_vtsi(original_path)
            original = bytearray(original_path.read_bytes())
            cases = []
            for name, size in (
                ("zero-size", 0),
                ("misaligned-size", 513),
                ("oversized", VTSI_MAX_DISK_BYTES + VTSI_SECTOR_BYTES),
            ):
                broken = bytearray(original)
                mutate_footer_u64(broken, DISK_SIZE_OFFSET, size)
                cases.append((name, broken, "disk size"))
            for name, count in (
                ("zero-segments", 0),
                ("too-many-segments", VTSI_MAX_SEGMENTS + 1),
            ):
                broken = bytearray(original)
                mutate_footer_u32(broken, SEGMENT_COUNT_OFFSET, count)
                cases.append((name, broken, "segment count"))

            for name, payload, pattern in cases:
                with self.subTest(name=name):
                    self.assert_rejected(root / f"{name}.vtsi", payload, pattern)

            with self.assertRaisesRegex(VtsiSafetyError, "disk size"):
                inspect_vtsi(original_path, maximum_disk_size=4096)
            for maximum in (True, 0, 511, VTSI_MAX_DISK_BYTES + 512):
                with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                    inspect_vtsi(original_path, maximum_disk_size=maximum)

    def test_exact_metadata_layout_padding_and_checksums_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.vtsi"
            build_vtsi(original_path)
            original = bytearray(original_path.read_bytes())
            start = footer_offset(original)
            table_offset = struct.unpack_from(
                "<Q", original, start + SEGMENT_OFFSET_OFFSET,
            )[0]
            table_size = 3 * SEGMENT.size

            cases: list[tuple[str, bytearray, str]] = []
            broken = bytearray(original)
            mutate_footer_u64(broken, SEGMENT_OFFSET_OFFSET, table_offset + 1)
            cases.append(("unaligned-offset", broken, "offset"))
            broken = bytearray(original)
            mutate_footer_u64(broken, SEGMENT_OFFSET_OFFSET, table_offset + 512)
            cases.append(("layout-gap", broken, "layout"))
            broken = bytearray(original)
            broken[table_offset] ^= 1
            cases.append(("table-checksum", broken, "table checksum"))
            broken = bytearray(original)
            broken[table_offset + table_size] = 1
            cases.append(("padding", broken, "padding"))
            broken = bytearray(original)
            broken.insert(start, 0)
            cases.append(("trailing-metadata", broken, "magic|layout"))
            broken = bytearray(original[:-1])
            cases.append(("truncated", broken, "magic|layout|checksum"))

            for name, payload, pattern in cases:
                with self.subTest(name=name):
                    self.assert_rejected(root / f"{name}.vtsi", payload, pattern)

    def test_segment_offsets_order_and_ranges_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.vtsi"
            build_vtsi(original_path)
            original = bytearray(original_path.read_bytes())
            cases: list[tuple[str, bytearray, str]] = []

            broken = bytearray(original)
            mutate_segment(broken, 0, 1, 0)
            cases.append(("zero-count", broken, "segment 0"))
            broken = bytearray(original)
            mutate_segment(broken, 1, 2, VTSI_SECTOR_BYTES + 1)
            cases.append(("data-gap", broken, "data offset"))
            broken = bytearray(original)
            mutate_segment(broken, 1, 0, 0)
            cases.append(("overlap", broken, "overlap"))
            broken = bytearray(original)
            mutate_segment(broken, 2, 0, 12)
            cases.append(("past-disk", broken, "exceeds"))
            broken = bytearray(original)
            mutate_segment(broken, 1, 1, 1)
            cases.append(("data-area-mismatch", broken, "data area|data offset"))
            for name, payload, pattern in cases:
                with self.subTest(name=name):
                    self.assert_rejected(root / f"{name}.vtsi", payload, pattern)

    def test_disk_signature_is_opaque_and_sector_zero_need_not_be_stored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "no-sector-zero.vtsi"
            expanded, _ = build_vtsi(
                path,
                disk_sectors=8,
                segments=((3, b"C" * VTSI_SECTOR_BYTES),),
            )
            payload = bytearray(path.read_bytes())
            mutate_footer_u32(payload, DISK_SIGNATURE_OFFSET, 0xDEADBEEF)
            path.write_bytes(payload)
            descriptor, plan = self.open_bound(path)
            try:
                self.assertEqual(plan.disk_signature, 0xDEADBEEF)
                self.assertEqual(
                    read_vtsi_at(descriptor, plan, 0, len(expanded)),
                    expanded,
                )
            finally:
                os.close(descriptor)

    def test_descriptor_identity_is_authoritative_and_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source.vtsi"
            expanded, _ = build_vtsi(path)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                # The pathname is display metadata only. The already-open
                # descriptor remains the authoritative source.
                plan = inspect_vtsi_descriptor(
                    descriptor, root / "not-the-open-source.vtsi",
                )
                self.assertEqual(
                    read_vtsi_at(descriptor, plan, 0, VTSI_SECTOR_BYTES),
                    expanded[:VTSI_SECTOR_BYTES],
                )
                writable = os.open(path, os.O_WRONLY)
                try:
                    os.pwrite(writable, b"X", 0)
                    os.fsync(writable)
                finally:
                    os.close(writable)
                with self.assertRaises(VtsiChanged):
                    read_vtsi_at(descriptor, plan, 0, 1)
            finally:
                os.close(descriptor)

    def test_mutation_during_pread_suppresses_newly_read_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.vtsi"
            build_vtsi(path)
            descriptor, plan = self.open_bound(path)
            real_pread = os.pread
            changed = False

            def mutate_after_read(fd: int, length: int, offset: int) -> bytes:
                nonlocal changed
                payload = real_pread(fd, length, offset)
                if not changed:
                    changed = True
                    writable = os.open(path, os.O_WRONLY)
                    try:
                        os.pwrite(writable, b"X", 100)
                        os.fsync(writable)
                    finally:
                        os.close(writable)
                return payload

            try:
                with (
                    patch("isopropyl.vtsi.os.pread", side_effect=mutate_after_read),
                    self.assertRaises(VtsiChanged),
                ):
                    read_vtsi_at(descriptor, plan, 0, VTSI_SECTOR_BYTES)
                self.assertTrue(changed)
            finally:
                os.close(descriptor)

    def test_link_count_change_and_forged_frozen_model_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source.vtsi"
            build_vtsi(path)
            descriptor, plan = self.open_bound(path)
            try:
                alias = root / "alias.vtsi"
                os.link(path, alias)
                with self.assertRaises(VtsiChanged):
                    validate_vtsi_plan(descriptor, plan)
            finally:
                os.close(descriptor)

            descriptor, plan = self.open_bound(path)
            try:
                object.__setattr__(plan.segments[0], "sector_count", 1.0)
                with self.assertRaisesRegex(VtsiSafetyError, "model"):
                    read_vtsi_at(descriptor, plan, 0, 1)
            finally:
                os.close(descriptor)

    def test_forged_plan_cross_field_invariants_fail_before_payload_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.vtsi"
            build_vtsi(path)

            def forge_bounds(plan: VtsiPlan) -> None:
                object.__setattr__(
                    plan.segments[0],
                    "disk_start_sector",
                    plan.disk_size // VTSI_SECTOR_BYTES,
                )

            def forge_data_offset(plan: VtsiPlan) -> None:
                object.__setattr__(
                    plan.segments[1],
                    "data_offset",
                    plan.segments[1].data_offset + VTSI_SECTOR_BYTES,
                )

            def forge_overlap(plan: VtsiPlan) -> None:
                object.__setattr__(plan.segments[1], "disk_start_sector", 0)

            def forge_layout(plan: VtsiPlan) -> None:
                object.__setattr__(
                    plan.identity,
                    "size",
                    plan.identity.size + VTSI_SECTOR_BYTES,
                )

            cases = (
                ("bounds", forge_bounds, "expanded disk"),
                ("data-offset", forge_data_offset, "data offset"),
                ("overlap", forge_overlap, "overlap"),
                ("layout", forge_layout, "file layout"),
            )
            for name, forge, pattern in cases:
                with self.subTest(name=name):
                    descriptor, plan = self.open_bound(path)
                    try:
                        forge(plan)
                        with (
                            patch("isopropyl.vtsi.os.pread") as pread,
                            self.assertRaisesRegex(VtsiSafetyError, pattern),
                        ):
                            read_vtsi_at(descriptor, plan, 0, 1)
                        pread.assert_not_called()
                    finally:
                        os.close(descriptor)

    def test_symlink_fifo_and_invalid_descriptors_fail_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.vtsi"
            build_vtsi(target)
            symlink = root / "link.vtsi"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(VtsiSafetyError, "opened safely"):
                inspect_vtsi(symlink)

            fifo = root / "source.vtsi"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(VtsiSafetyError, "regular file|too small"):
                inspect_vtsi(fifo)

            for descriptor in (-1, True, 10**9):
                with self.subTest(descriptor=descriptor), self.assertRaises(VtsiSafetyError):
                    inspect_vtsi_descriptor(descriptor, target.absolute())

    def test_cancellation_exception_is_preserved_before_and_after_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.vtsi"
            build_vtsi(path)

            signal = CancellationSignal("cancel now")
            with (
                patch("isopropyl.vtsi.os.pread") as pread,
                self.assertRaises(CancellationSignal) as caught,
            ):
                inspect_vtsi(path, cancel_check=lambda: (_ for _ in ()).throw(signal))
            self.assertIs(caught.exception, signal)
            pread.assert_not_called()

            descriptor, plan = self.open_bound(path)
            calls = 0

            def cancel_after_read() -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise signal

            try:
                with self.assertRaises(CancellationSignal) as caught:
                    read_vtsi_at(
                        descriptor,
                        plan,
                        0,
                        VTSI_SECTOR_BYTES,
                        cancel_check=cancel_after_read,
                    )
                self.assertIs(caught.exception, signal)
            finally:
                os.close(descriptor)

    def test_read_and_chunk_arguments_are_exact_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.vtsi"
            build_vtsi(path)
            descriptor, plan = self.open_bound(path)
            try:
                for offset, length in (
                    (-1, 0),
                    (0, -1),
                    (plan.disk_size + 1, 0),
                    (plan.disk_size, 1),
                    (0, VTSI_MAX_READ_BYTES + 1),
                    (True, 0),
                    (0, False),
                ):
                    with self.subTest(offset=offset, length=length), self.assertRaises(
                        VtsiSafetyError
                    ):
                        read_vtsi_at(descriptor, plan, offset, length)
                for chunk_size in (0, -1, True, VTSI_MAX_READ_BYTES + 1, 1.0):
                    with self.subTest(chunk_size=chunk_size), self.assertRaises(ValueError):
                        tuple(iter_vtsi_chunks(
                            descriptor, plan, chunk_size=chunk_size,
                        ))
            finally:
                os.close(descriptor)

    def test_plan_constructor_and_validation_reject_wrong_exact_types(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.vtsi"
            build_vtsi(path)
            descriptor, plan = self.open_bound(path)
            try:
                with self.assertRaises(ValueError):
                    replace(plan, disk_size=float(plan.disk_size))
                with self.assertRaises(ValueError):
                    replace(plan, segments=list(plan.segments))
                with self.assertRaisesRegex(VtsiSafetyError, "invalid type"):
                    validate_vtsi_plan(descriptor, object())  # type: ignore[arg-type]
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
