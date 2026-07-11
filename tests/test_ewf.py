import struct
import zlib
from pathlib import Path

import pytest

from modules.disk.ewf import (
    EWF1_SIGNATURE,
    EwfError,
    get_case_info,
    iter_sections,
    reconstruct_raw_image,
    summarize,
)


def _build_section(type_str: str, body: bytes, next_offset: int) -> bytes:
    descriptor = bytearray(76)
    type_bytes = type_str.encode("ascii")
    descriptor[0:len(type_bytes)] = type_bytes
    total_size = 76 + len(body)
    struct.pack_into("<QQ", descriptor, 16, next_offset, total_size)
    # bytes 32-71 padding (already zero), checksum at 72 left as 0 (unvalidated by our parser)
    return bytes(descriptor) + body


def _build_synthetic_e01(chunk0: bytes, chunk1: bytes) -> bytes:
    header = EWF1_SIGNATURE + bytes([0x01]) + struct.pack("<H", 1) + b"\x00\x00"
    assert len(header) == 13

    compressed_chunk0 = zlib.compress(chunk0)
    # chunk1 deliberately NOT valid zlib (won't inflate) -> exercises the raw fallback path
    raw_chunk1 = b"\xffRAWDATA_NOT_ZLIB_COMPRESSED_1234567890" + chunk1

    sectors_body = compressed_chunk0 + raw_chunk1
    sectors_offset = len(header)

    # Table section placeholder; we'll patch next_offset fields after computing layout.
    table_header = struct.pack("<I", 2) + b"\x00" * 4 + struct.pack("<Q", sectors_offset) + b"\x00" * 4 + b"\x00" * 4
    table_entries = struct.pack("<II", 0, len(compressed_chunk0))
    table_body = table_header + table_entries

    done_body = b""

    # First pass: compute offsets assuming we know section sizes.
    sectors_section_size = 76 + len(sectors_body)
    table_section_size = 76 + len(table_body)

    table_offset = sectors_offset + sectors_section_size
    done_offset = table_offset + table_section_size

    sectors_section = _build_section("sectors", sectors_body, next_offset=table_offset)
    table_section = _build_section("table", table_body, next_offset=done_offset)
    done_section = _build_section("done", done_body, next_offset=0)

    return header + sectors_section + table_section + done_section


def test_iter_sections_walks_the_chain(tmp_path: Path):
    data = _build_synthetic_e01(b"A" * 400, b"B" * 100)
    sections = list(iter_sections(data))
    types = [s.type for s in sections]
    assert types == ["sectors", "table", "done"]


def test_rejects_non_ewf_file():
    with pytest.raises(EwfError):
        list(iter_sections(b"not an EWF file at all, just junk bytes"))


def test_reconstruct_raw_image_decompresses_and_passes_through(tmp_path: Path):
    chunk0 = b"A" * 400
    chunk1 = b"B" * 100
    data = _build_synthetic_e01(chunk0, chunk1)
    path = tmp_path / "evidence.E01"
    path.write_bytes(data)

    raw = reconstruct_raw_image(path)
    assert raw.startswith(chunk0)
    assert chunk1 in raw


def test_summarize_reports_section_types(tmp_path: Path):
    data = _build_synthetic_e01(b"X" * 50, b"Y" * 50)
    path = tmp_path / "evidence.E01"
    path.write_bytes(data)
    summary = summarize(path)
    assert summary["signature_valid"] is True
    assert summary["table_section_count"] == 1
    assert "sectors" in summary["section_types"]


def test_get_case_info_decompresses_header_section(tmp_path: Path):
    header_text = "1\r\nmain\r\nc\tn\tv\r\nCase123\tExaminer\t1\r\n\r\n"
    compressed_header = zlib.compress(header_text.encode("utf-16le"))
    ewf_header = EWF1_SIGNATURE + bytes([0x01]) + struct.pack("<H", 1) + b"\x00\x00"

    header_section_offset = len(ewf_header)
    header_section_size = 76 + len(compressed_header)
    done_offset = header_section_offset + header_section_size

    header_section = _build_section("header", compressed_header, next_offset=done_offset)
    done_section = _build_section("done", b"", next_offset=0)

    data = ewf_header + header_section + done_section
    path = tmp_path / "evidence.E01"
    path.write_bytes(data)

    info = get_case_info(path)
    assert info is not None
    assert "Case123" in info
