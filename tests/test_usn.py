import struct
from datetime import datetime, timezone
from pathlib import Path

from modules.windows.usn import parse_usn_buffer, parse_usn_journal

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _to_filetime(dt: datetime) -> int:
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


def _build_v2_record(file_ref: int, file_seq: int, parent_ref: int, parent_seq: int,
                      usn: int, timestamp: datetime, reason: int, file_attrs: int,
                      name: str) -> bytes:
    name_bytes = name.encode("utf-16le")
    name_offset = 60
    total = name_offset + len(name_bytes)
    pad = (-total) % 8
    total_padded = total + pad

    record = bytearray(total_padded)
    struct.pack_into("<I", record, 0, total_padded)
    struct.pack_into("<H", record, 4, 2)  # major version
    struct.pack_into("<H", record, 6, 0)  # minor version
    file_ref_raw = (file_seq << 48) | file_ref
    parent_ref_raw = (parent_seq << 48) | parent_ref
    struct.pack_into("<QQ", record, 8, file_ref_raw, parent_ref_raw)
    struct.pack_into("<q", record, 24, usn)
    struct.pack_into("<q", record, 32, _to_filetime(timestamp))
    struct.pack_into("<IIII", record, 40, reason, 0, 0, file_attrs)
    struct.pack_into("<HH", record, 56, len(name_bytes), name_offset)
    record[name_offset:name_offset + len(name_bytes)] = name_bytes
    return bytes(record)


def test_parse_single_record_from_buffer():
    ts = datetime(2026, 6, 1, 8, 30, 0, tzinfo=timezone.utc)
    raw = _build_v2_record(file_ref=64, file_seq=1, parent_ref=5, parent_seq=1,
                            usn=4096, timestamp=ts, reason=0x00000100 | 0x80000000,
                            file_attrs=0x20, name="ransom_note.txt")
    records = list(parse_usn_buffer(raw))
    assert len(records) == 1
    r = records[0]
    assert r.file_ref == 64
    assert r.parent_ref == 5
    assert r.file_name == "ransom_note.txt"
    assert "FILE_CREATE" in r.reasons
    assert "CLOSE" in r.reasons
    assert r.timestamp is not None


def test_parse_multiple_records_with_sparse_padding():
    ts = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    rec1 = _build_v2_record(1, 1, 5, 1, 100, ts, 0x00000100, 0x20, "a.txt")
    rec2 = _build_v2_record(2, 1, 5, 1, 200, ts, 0x00000200, 0x20, "b.txt")  # FILE_DELETE
    sparse_gap = b"\x00" * 4096  # journal extents are sparse between allocations
    buf = rec1 + sparse_gap + rec2

    records = list(parse_usn_buffer(buf))
    assert len(records) == 2
    assert records[0].file_name == "a.txt"
    assert records[1].file_name == "b.txt"
    assert "FILE_DELETE" in records[1].reasons


def test_rename_reason_flags():
    ts = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    old = _build_v2_record(10, 1, 5, 1, 300, ts, 0x00001000, 0x20, "old_name.txt")
    new = _build_v2_record(10, 1, 5, 1, 301, ts, 0x00002000, 0x20, "new_name.txt")
    records = list(parse_usn_buffer(old + new))
    assert "RENAME_OLD_NAME" in records[0].reasons
    assert records[0].file_name == "old_name.txt"
    assert "RENAME_NEW_NAME" in records[1].reasons
    assert records[1].file_name == "new_name.txt"


def test_streaming_parse_across_chunk_boundary(tmp_path: Path):
    ts = datetime(2026, 6, 1, 11, 0, 0, tzinfo=timezone.utc)
    records_raw = [
        _build_v2_record(i, 1, 5, 1, i * 100, ts, 0x00000100, 0x20, f"file_{i}.dat")
        for i in range(1, 6)
    ]
    buf = b"".join(records_raw)
    path = tmp_path / "usnjrnl_J"
    path.write_bytes(buf)

    # Force a tiny chunk size so records straddle chunk boundaries, exercising
    # the leftover-carry logic in _stream_parse.
    parsed = list(parse_usn_journal(path, chunk_size=32))
    assert len(parsed) == 5
    assert [r.file_name for r in parsed] == [f"file_{i}.dat" for i in range(1, 6)]


def test_empty_buffer_yields_nothing():
    assert list(parse_usn_buffer(b"")) == []
    assert list(parse_usn_buffer(b"\x00" * 1000)) == []
