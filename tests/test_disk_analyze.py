import struct
import zlib
from pathlib import Path

from modules.disk import analyze
from modules.disk.ewf import EWF1_SIGNATURE


def _build_mbr_sector(bootable_type=0x07, start_lba=2048, sector_count=204800) -> bytes:
    sector = bytearray(512)
    sector[446] = 0x80
    sector[446 + 4] = bootable_type
    struct.pack_into("<II", sector, 446 + 8, start_lba, sector_count)
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _build_fixed_vhd(raw_disk: bytes) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 12, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", footer, 40, len(raw_disk))
    struct.pack_into(">Q", footer, 48, len(raw_disk))
    struct.pack_into(">I", footer, 60, 2)  # fixed
    checksum = (~sum(b for i, b in enumerate(footer) if not (64 <= i < 68))) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return raw_disk + bytes(footer)


def test_dd_raw_image_partitions(tmp_path: Path):
    raw_disk = _build_mbr_sector() + b"\x00" * (8192 - 512)
    path = tmp_path / "evidence.dd"
    path.write_bytes(raw_disk)

    info = analyze.identify_image(path)
    assert info.format == "DD (raw)"
    assert info.supports_native_parsing is True

    parts = analyze.partitions(path)
    assert len(parts) == 1
    assert parts[0]["type_name"] == "NTFS/exFAT"


def test_fixed_vhd_partitions(tmp_path: Path):
    raw_disk = _build_mbr_sector(start_lba=4096) + b"\x00" * (8192 - 512)
    vhd_bytes = _build_fixed_vhd(raw_disk)
    path = tmp_path / "evidence.vhd"
    path.write_bytes(vhd_bytes)

    info = analyze.identify_image(path)
    assert info.format == "VHD (fixed)"
    assert info.supports_native_parsing is True

    parts = analyze.partitions(path)
    assert len(parts) == 1
    assert parts[0]["start_lba"] == 4096

    # get_raw_bytes should exclude the trailing 512-byte footer
    raw = analyze.get_raw_bytes(path)
    assert len(raw) == len(raw_disk)
    assert raw[:512] == raw_disk[:512]


def _build_synthetic_e01(chunk0: bytes, chunk1: bytes) -> bytes:
    header = EWF1_SIGNATURE + bytes([0x01]) + struct.pack("<H", 1) + b"\x00\x00"
    compressed_chunk0 = zlib.compress(chunk0)
    raw_chunk1 = b"\xffRAWDATA_NOT_ZLIB_COMPRESSED_1234567890" + chunk1
    sectors_body = compressed_chunk0 + raw_chunk1
    sectors_offset = len(header)

    table_header = struct.pack("<I", 2) + b"\x00" * 4 + struct.pack("<Q", sectors_offset) + b"\x00" * 8
    table_entries = struct.pack("<II", 0, len(compressed_chunk0))
    table_body = table_header + table_entries

    sectors_section_size = 76 + len(sectors_body)
    table_section_size = 76 + len(table_body)
    table_offset = sectors_offset + sectors_section_size
    done_offset = table_offset + table_section_size

    def build_section(type_str: str, body: bytes, next_offset: int) -> bytes:
        descriptor = bytearray(76)
        descriptor[0:len(type_str)] = type_str.encode("ascii")
        struct.pack_into("<QQ", descriptor, 16, next_offset, 76 + len(body))
        return bytes(descriptor) + body

    sectors_section = build_section("sectors", sectors_body, next_offset=table_offset)
    table_section = build_section("table", table_body, next_offset=done_offset)
    done_section = build_section("done", b"", next_offset=0)
    return header + sectors_section + table_section + done_section


def test_e01_partitions_via_reconstruction(tmp_path: Path):
    raw_disk = _build_mbr_sector() + b"\x00" * 200  # small, but enough for the table
    data = _build_synthetic_e01(raw_disk, b"trailing")
    path = tmp_path / "evidence.E01"
    path.write_bytes(data)

    info = analyze.identify_image(path)
    assert info.format == "E01 (EnCase Evidence File)"
    assert info.supports_native_parsing is True

    parts = analyze.partitions(path)
    assert len(parts) == 1
    assert parts[0]["type_name"] == "NTFS/exFAT"


def test_analyze_full_pipeline(tmp_path: Path):
    raw_disk = _build_mbr_sector() + b"\x00" * (8192 - 512)
    path = tmp_path / "evidence.dd"
    path.write_bytes(raw_disk)

    result = analyze.analyze(path)
    assert "warning" not in result or result["warning"] is None
    assert len(result["partitions"]) == 1


def test_unrecognized_format_is_honest_extension_point(tmp_path: Path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"not a disk image")
    info = analyze.identify_image(path)
    assert info.format == "unknown"
    assert info.supports_native_parsing is False
