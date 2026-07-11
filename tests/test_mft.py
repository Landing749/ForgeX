import struct
from datetime import datetime, timezone
from pathlib import Path

from modules.windows.mft import (
    MftRecord,
    _apply_fixup,
    build_path_index,
    parse_mft_file,
    parse_record,
    resolve_path,
)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _to_filetime(dt: datetime) -> int:
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


def test_apply_fixup_restores_sector_end_bytes():
    record = bytearray(1024)
    record[0:4] = b"FILE"
    usa_offset, usa_count = 48, 3
    struct.pack_into("<HH", record, 4, usa_offset, usa_count)
    # USN value written at usa_offset, "real" saved bytes follow for each sector.
    struct.pack_into("<H", record, usa_offset, 0x0001)
    struct.pack_into("<2s", record, usa_offset + 2, b"\xaa\xbb")
    struct.pack_into("<2s", record, usa_offset + 4, b"\xcc\xdd")
    # Simulate on-disk state: last 2 bytes of each 512-byte sector hold the USN.
    struct.pack_into("<H", record, 510, 0x0001)
    struct.pack_into("<H", record, 1022, 0x0001)

    fixed = _apply_fixup(record)
    assert bytes(fixed[510:512]) == b"\xaa\xbb"
    assert bytes(fixed[1022:1024]) == b"\xcc\xdd"


def _build_resident_attr(attr_type: int, attr_id: int, content: bytes) -> bytes:
    header_size = 24
    total = header_size + len(content)
    pad = (-total) % 8
    padded_total = total + pad
    header = bytearray(header_size)
    struct.pack_into("<I", header, 0, attr_type)
    struct.pack_into("<I", header, 4, padded_total)
    header[8] = 0  # resident
    header[9] = 0  # name length
    struct.pack_into("<H", header, 10, 0)
    struct.pack_into("<H", header, 12, 0)
    struct.pack_into("<H", header, 14, attr_id)
    struct.pack_into("<I", header, 16, len(content))
    struct.pack_into("<H", header, 20, header_size)
    header[22] = 0
    header[23] = 0
    return bytes(header) + content + b"\x00" * pad


def _build_standard_information(created, modified, mft_modified, accessed, dos_flags=0x20) -> bytes:
    content = bytearray(48)
    struct.pack_into("<QQQQ", content, 0, _to_filetime(created), _to_filetime(modified),
                      _to_filetime(mft_modified), _to_filetime(accessed))
    struct.pack_into("<I", content, 32, dos_flags)
    return bytes(content)


def _build_file_name(name: str, parent_ref: int, parent_seq: int, created, modified,
                      mft_modified, accessed, real_size: int, allocated_size: int,
                      namespace: int = 1) -> bytes:
    name_bytes = name.encode("utf-16le")
    content = bytearray(66 + len(name_bytes))
    combined_parent = (parent_seq << 48) | (parent_ref & 0x0000FFFFFFFFFFFF)
    struct.pack_into("<Q", content, 0, combined_parent)
    struct.pack_into("<QQQQ", content, 8, _to_filetime(created), _to_filetime(modified),
                      _to_filetime(mft_modified), _to_filetime(accessed))
    struct.pack_into("<QQ", content, 40, allocated_size, real_size)
    struct.pack_into("<I", content, 56, 0)
    struct.pack_into("<I", content, 60, 0)
    content[64] = len(name)
    content[65] = namespace
    content[66:66 + len(name_bytes)] = name_bytes
    return bytes(content)


def _build_mft_record(record_number: int, name: str, parent_ref: int, is_directory: bool = False,
                       record_size: int = 1024) -> bytes:
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    std_info = _build_standard_information(now, now, now, now)
    file_name = _build_file_name(name, parent_ref, 0, now, now, now, now,
                                  real_size=1234, allocated_size=4096)

    attr1 = _build_resident_attr(0x10, 0, std_info)  # $STANDARD_INFORMATION
    attr2 = _build_resident_attr(0x30, 1, file_name)  # $FILE_NAME
    end_marker = struct.pack("<I", 0xFFFFFFFF)

    attr_offset = 56
    body = attr1 + attr2 + end_marker
    total_len = attr_offset + len(body)

    record = bytearray(record_size)
    record[0:4] = b"FILE"
    usa_offset, usa_count = 48, 3
    struct.pack_into("<HH", record, 4, usa_offset, usa_count)
    struct.pack_into("<Q", record, 8, 0)  # LSN
    struct.pack_into("<H", record, 16, 1)  # sequence number
    struct.pack_into("<H", record, 18, 1)  # hard link count
    struct.pack_into("<H", record, 20, attr_offset)
    flags = 0x0001 | (0x0002 if is_directory else 0)
    struct.pack_into("<H", record, 22, flags)
    struct.pack_into("<I", record, 24, total_len)
    struct.pack_into("<I", record, 28, record_size)
    struct.pack_into("<Q", record, 32, 0)  # base record ref
    struct.pack_into("<H", record, 40, 2)  # next attr id
    struct.pack_into("<I", record, 44, record_number)

    # USA: USN + saved sector-end bytes; no need to actually corrupt the
    # sector-end bytes here since our content doesn't reach that far, but
    # write a self-consistent USA/sector-end pair so fixup is a no-op.
    struct.pack_into("<H", record, usa_offset, 0x0001)
    struct.pack_into("<H", record, usa_offset + 2, 0x0001)
    struct.pack_into("<H", record, usa_offset + 4, 0x0001)
    struct.pack_into("<H", record, 510, 0x0001)
    struct.pack_into("<H", record, 1022, 0x0001)

    record[attr_offset:attr_offset + len(body)] = body
    return bytes(record)


def test_parse_single_record():
    raw = _build_mft_record(record_number=64, name="secrets.docx", parent_ref=5)
    record = parse_record(raw)
    assert isinstance(record, MftRecord)
    assert record.record_number == 64
    assert record.in_use is True
    assert record.is_directory is False
    assert record.best_name == "secrets.docx"
    assert record.standard_information is not None
    assert record.standard_information.created is not None
    assert "ARCHIVE" in record.standard_information.file_flags
    assert record.file_names[0].logical_size == 1234


def test_parse_record_rejects_bad_signature():
    junk = b"\x00" * 1024
    assert parse_record(junk) is None


def test_parse_mft_file_streaming(tmp_path: Path):
    rec1 = _build_mft_record(record_number=5, name="", parent_ref=5, is_directory=True)
    rec2 = _build_mft_record(record_number=64, name="notes.txt", parent_ref=5)
    unused = b"\x00" * 1024  # unallocated slot, should be skipped

    mft_path = tmp_path / "$MFT"
    mft_path.write_bytes(rec1 + unused + rec2)

    records = list(parse_mft_file(mft_path))
    assert len(records) == 2
    assert {r.record_number for r in records} == {5, 64}


def test_resolve_path_chain(tmp_path: Path):
    root = _build_mft_record(record_number=5, name="", parent_ref=5, is_directory=True)
    child_dir = _build_mft_record(record_number=10, name="Users", parent_ref=5, is_directory=True)
    leaf = _build_mft_record(record_number=64, name="notes.txt", parent_ref=10)

    mft_path = tmp_path / "$MFT"
    mft_path.write_bytes(root + child_dir + leaf)
    records = list(parse_mft_file(mft_path))
    index = build_path_index(records)

    leaf_record = index[64]
    path = resolve_path(leaf_record, index)
    assert path == "\\Users\\notes.txt"
