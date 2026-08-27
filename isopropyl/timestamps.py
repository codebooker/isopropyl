from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared policy for portable ISO/UDF modification times."""

import os


NANOSECONDS_PER_SECOND = 1_000_000_000

# FAT's on-disk calendar spans 1980 through 2107 in local time.  ISOpropyl
# catalogs in UTC, so leave a conservative full-day margin at both ends.  This
# remains representable even at the practical UTC-12 and UTC+14 extremes.
MIN_PORTABLE_ARCHIVE_MTIME_NS = 315_619_200 * NANOSECONDS_PER_SECOND
MAX_PORTABLE_ARCHIVE_MTIME_NS = (
    4_354_732_798 * NANOSECONDS_PER_SECOND + 999_999_999
)

# FAT modification times have two-second granularity.  A user-selected staging
# filesystem may be equally coarse, so retain the observed normalized value as
# long as it remains within this explicit bound.
FAT_MTIME_TOLERANCE_NS = 2 * NANOSECONDS_PER_SECOND
STAGING_MTIME_TOLERANCE_NS = FAT_MTIME_TOLERANCE_NS
NTFS_MTIME_TOLERANCE_NS = 100


class TimestampPreservationError(RuntimeError):
    pass


def mtime_matches(expected_ns: int, observed_ns: int, tolerance_ns: int) -> bool:
    # A difference of one complete filesystem tick is a distinct timestamp,
    # not rounding of the requested value.
    return abs(expected_ns - observed_ns) < tolerance_ns


def apply_descriptor_mtime(
    descriptor: int,
    modified_ns: int,
    *,
    tolerance_ns: int,
) -> int:
    """Set an mtime through an already-bound descriptor and return normalization."""

    try:
        before = os.fstat(descriptor)
        os.utime(descriptor, ns=(before.st_atime_ns, modified_ns))
        os.fsync(descriptor)
        observed_ns = os.fstat(descriptor).st_mtime_ns
    except OSError as error:
        raise TimestampPreservationError(str(error)) from error
    if not mtime_matches(modified_ns, observed_ns, tolerance_ns):
        raise TimestampPreservationError(
            "the filesystem normalized the modification time beyond the supported "
            f"{tolerance_ns}-nanosecond bound"
        )
    return observed_ns
