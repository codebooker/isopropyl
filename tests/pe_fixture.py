# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portable PE byte fixtures without host or filesystem test dependencies."""
import struct


def make_pe(
    *, machine: int = 0x8664, pe32: bool = False, subsystem: int = 10,
    sbat: bytes | None = None, certificate: bytes | None = None,
    security_override: tuple[int, int] | None = None,
    duplicate_sbat: bool = False,
) -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0 if pe32 else 0xF0
    sections = []
    if sbat is not None:
        sections.append((b".sbat", sbat))
        if duplicate_sbat:
            sections.append((b".sbat", sbat))
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, len(sections))
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    directory_count_offset = 92 if pe32 else 108
    directories_offset = 96 if pe32 else 112
    struct.pack_into("<I", data, optional + directory_count_offset, 16)

    section_table = optional + optional_size
    raw_cursor = 0x400
    required_header = section_table + len(sections) * 40
    if len(data) < required_header:
        data.extend(b"\0" * (required_header - len(data)))
    for index, (name, payload) in enumerate(sections):
        header = section_table + index * 40
        data[header:header + 8] = name.ljust(8, b"\0")
        struct.pack_into("<II", data, header + 16, len(payload), raw_cursor)
        if len(data) < raw_cursor + len(payload):
            data.extend(b"\0" * (raw_cursor + len(payload) - len(data)))
        data[raw_cursor:raw_cursor + len(payload)] = payload
        raw_cursor = (raw_cursor + len(payload) + 0x1FF) & ~0x1FF

    security_offset = 0
    security_size = 0
    if certificate is not None:
        security_offset = max((len(data) + 7) & ~7, raw_cursor)
        if len(data) < security_offset:
            data.extend(b"\0" * (security_offset - len(data)))
        data.extend(certificate)
        security_size = len(certificate)
    if security_override is not None:
        security_offset, security_size = security_override
    security_directory = optional + directories_offset + 4 * 8
    struct.pack_into("<II", data, security_directory, security_offset, security_size)
    return bytes(data)

