"""VHD (Virtual Hard Disk, "VHD Image Format Specification") reader.

Every VHD -- fixed, dynamic, or differencing -- ends with a 512-byte
footer (dynamic disks also keep a copy at the very start of the file,
before the dynamic header + block allocation table):

    0    8   cookie "conectix"
    8    4   features
    12   4   file format version (0x00010000)
    16   8   data offset (0xFFFFFFFFFFFFFFFF for fixed disks; otherwise
             the absolute offset of the dynamic disk header)
    24   4   timestamp (seconds since 2000-01-01T00:00:00Z)
    28   4   creator application
    32   4   creator version
    36   4   creator host OS
    40   8   original size (bytes)
    48   8   current size (bytes)
    56   4   disk geometry (cylinders:2, heads:1, sectors_per_track:1)
    60   4   disk type (2=fixed, 3=dynamic, 4=differencing)
    64   4   checksum (one's complement of the sum of all other footer bytes)
    68   16  unique id (GUID)
    84   1   saved state
    85   427 reserved

VHDX (the newer, more complex successor format) is a different,
substantially larger binary structure and is not covered here.
"""
from __future__ import annotations

import struct
import uuid as uuid_module
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FOOTER_SIZE = 512
COOKIE = b"conectix"
VHD_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)

DISK_TYPES = {0: "none", 2: "fixed", 3: "dynamic", 4: "differencing"}


class VhdError(Exception):
    pass


@dataclass
class VhdFooter:
    disk_type: str
    original_size_bytes: int
    current_size_bytes: int
    cylinders: int
    heads: int
    sectors_per_track: int
    timestamp: str | None
    creator_application: str
    unique_id: str
    checksum_valid: bool
    is_dynamic: bool
    dynamic_header_offset: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _compute_checksum(footer_bytes: bytearray) -> int:
    """VHD footer checksum: one's complement of the sum of all footer
    bytes with the checksum field itself treated as zero."""
    total = 0
    for i, b in enumerate(footer_bytes):
        if 64 <= i < 68:  # checksum field itself is excluded (treated as 0)
            continue
        total += b
    return (~total) & 0xFFFFFFFF


def parse_footer(data: bytes) -> VhdFooter:
    if len(data) < FOOTER_SIZE:
        raise VhdError("Buffer too short to contain a VHD footer")
    footer = bytearray(data[-FOOTER_SIZE:])
    if footer[:8] != COOKIE:
        # Dynamic disks also carry an identical copy at the very start of the file.
        if data[:8] == COOKIE:
            footer = bytearray(data[:FOOTER_SIZE])
        else:
            raise VhdError("Not a VHD file (missing 'conectix' cookie)")

    data_offset = struct.unpack_from(">Q", footer, 16)[0]
    timestamp_raw = struct.unpack_from(">I", footer, 24)[0]
    creator_app = footer[28:32].decode("ascii", errors="ignore")
    original_size = struct.unpack_from(">Q", footer, 40)[0]
    current_size = struct.unpack_from(">Q", footer, 48)[0]
    cylinders = struct.unpack_from(">H", footer, 56)[0]
    heads = footer[58]
    sectors_per_track = footer[59]
    disk_type_raw = struct.unpack_from(">I", footer, 60)[0]
    stored_checksum = struct.unpack_from(">I", footer, 64)[0]
    unique_id = uuid_module.UUID(bytes=bytes(footer[68:84]))

    computed_checksum = _compute_checksum(footer)
    is_dynamic = disk_type_raw in (3, 4)

    timestamp_iso = None
    if timestamp_raw:
        timestamp_iso = (VHD_EPOCH + timedelta(seconds=timestamp_raw)).isoformat()

    return VhdFooter(
        disk_type=DISK_TYPES.get(disk_type_raw, f"unknown ({disk_type_raw})"),
        original_size_bytes=original_size, current_size_bytes=current_size,
        cylinders=cylinders, heads=heads, sectors_per_track=sectors_per_track,
        timestamp=timestamp_iso, creator_application=creator_app, unique_id=str(unique_id),
        checksum_valid=(stored_checksum == computed_checksum),
        is_dynamic=is_dynamic,
        dynamic_header_offset=(data_offset if is_dynamic and data_offset != 0xFFFFFFFFFFFFFFFF else None),
    )


def read_footer(path: str | Path) -> VhdFooter:
    data = Path(path).read_bytes()
    return parse_footer(data)
