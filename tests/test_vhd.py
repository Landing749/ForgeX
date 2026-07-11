import struct
import uuid
from datetime import datetime, timezone

import pytest

from modules.disk.vhd import VHD_EPOCH, VhdError, parse_footer


def _build_vhd_footer(disk_type: int = 2, current_size: int = 1024 * 1024 * 100,
                       data_offset: int = 0xFFFFFFFFFFFFFFFF) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 0)  # features
    struct.pack_into(">I", footer, 12, 0x00010000)  # file format version
    struct.pack_into(">Q", footer, 16, data_offset)
    ts = int((datetime(2026, 1, 1, tzinfo=timezone.utc) - VHD_EPOCH).total_seconds())
    struct.pack_into(">I", footer, 24, ts)
    footer[28:32] = b"wa\x00\x00"  # creator app "wa" (mock)
    struct.pack_into(">I", footer, 32, 0x00010000)  # creator version
    footer[36:40] = b"Wi2k"
    struct.pack_into(">Q", footer, 40, current_size)  # original size
    struct.pack_into(">Q", footer, 48, current_size)  # current size
    struct.pack_into(">H", footer, 56, 1024)  # cylinders
    footer[58] = 16  # heads
    footer[59] = 63  # sectors per track
    struct.pack_into(">I", footer, 60, disk_type)
    footer[68:84] = uuid.uuid4().bytes

    checksum = (~sum(b for i, b in enumerate(footer) if not (64 <= i < 68))) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


def test_parse_fixed_disk_footer():
    data = _build_vhd_footer(disk_type=2)
    footer = parse_footer(data)
    assert footer.disk_type == "fixed"
    assert footer.checksum_valid is True
    assert footer.is_dynamic is False
    assert footer.dynamic_header_offset is None
    assert footer.cylinders == 1024
    assert footer.heads == 16
    assert footer.sectors_per_track == 63


def test_parse_dynamic_disk_footer():
    data = _build_vhd_footer(disk_type=3, data_offset=512)
    footer = parse_footer(data)
    assert footer.disk_type == "dynamic"
    assert footer.is_dynamic is True
    assert footer.dynamic_header_offset == 512


def test_footer_at_end_of_larger_file():
    footer_bytes = _build_vhd_footer(disk_type=2)
    fake_disk_data = b"\x00" * 4096
    full_file = fake_disk_data + footer_bytes
    footer = parse_footer(full_file)
    assert footer.checksum_valid is True


def test_rejects_non_vhd_file():
    with pytest.raises(VhdError):
        parse_footer(b"not a vhd file" * 50)


def test_checksum_detects_corruption():
    data = bytearray(_build_vhd_footer(disk_type=2))
    data[40] ^= 0xFF  # corrupt the original_size field without fixing checksum
    footer = parse_footer(bytes(data))
    assert footer.checksum_valid is False
