"""NTFS USN Journal ($UsnJrnl:$J) parser.

Parses the $J alternate data stream (a raw, sparse, append-only log of
USN_RECORD_V2 structures) extracted from an NTFS volume. Every file
system change (create, rename, delete, data write, security change,
...) produces one record, making this one of the highest-value
sources for reconstructing what happened to a specific file over
time -- especially useful for anti-forensic activity where the file
itself (and its $STANDARD_INFORMATION timestamps) may have been
altered or deleted.

USN_RECORD_V2 (the common version on NTFS; V3/V4 add 128-bit file IDs
for ReFS and are not covered here):

    0   4   RecordLength (total size of this record, incl. padding)
    4   2   MajorVersion (2)
    6   2   MinorVersion (0)
    8   8   FileReferenceNumber
    16  8   ParentFileReferenceNumber
    24  8   Usn (this record's own byte offset in the journal)
    32  8   TimeStamp (FILETIME)
    40  4   Reason (bitmask, see USN_REASON_FLAGS)
    44  4   SourceInfo
    48  4   SecurityId
    52  4   FileAttributes
    56  2   FileNameLength (bytes)
    58  2   FileNameOffset (from start of record)
    60+     FileName (UTF-16LE)

The journal is sparse: large stretches between allocated extents are
zero-filled, so a RecordLength of 0 means "keep scanning forward",
not "end of file".
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE", 0x00000002: "DATA_EXTEND", 0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE", 0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION", 0x00000100: "FILE_CREATE", 0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE", 0x00000800: "SECURITY_CHANGE", 0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME", 0x00004000: "INDEXABLE_CHANGE", 0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE", 0x00020000: "COMPRESSION_CHANGE", 0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE", 0x00100000: "REPARSE_POINT_CHANGE", 0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE", 0x80000000: "CLOSE",
}

MIN_RECORD_SIZE = 60


def filetime_to_iso(filetime: int) -> str | None:
    if not filetime:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)).isoformat()
    except (OverflowError, OSError):
        return None


def _decode_reasons(mask: int) -> list[str]:
    return [name for bit, name in USN_REASON_FLAGS.items() if mask & bit]


@dataclass
class UsnRecord:
    file_ref: int
    file_seq: int
    parent_ref: int
    parent_seq: int
    usn: int
    timestamp: str | None
    reasons: list[str] = field(default_factory=list)
    file_attributes: int = 0
    file_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _split_ref(raw: int) -> tuple[int, int]:
    return raw & 0x0000FFFFFFFFFFFF, (raw >> 48) & 0xFFFF


def _parse_v2_record(raw: bytes) -> UsnRecord | None:
    if len(raw) < MIN_RECORD_SIZE:
        return None
    major_version = struct.unpack_from("<H", raw, 4)[0]
    if major_version != 2:
        return None  # V3/V4 (ReFS 128-bit IDs) not handled by this parser

    file_ref_raw, parent_ref_raw, usn, timestamp = struct.unpack_from("<QQqq", raw, 8)
    reason, _source_info, _security_id, file_attrs = struct.unpack_from("<IIII", raw, 40)
    name_len, name_offset = struct.unpack_from("<HH", raw, 56)

    file_ref, file_seq = _split_ref(file_ref_raw)
    parent_ref, parent_seq = _split_ref(parent_ref_raw)

    name = ""
    if name_offset and name_len and name_offset + name_len <= len(raw):
        name = raw[name_offset:name_offset + name_len].decode("utf-16le", errors="ignore")

    return UsnRecord(
        file_ref=file_ref, file_seq=file_seq, parent_ref=parent_ref, parent_seq=parent_seq,
        usn=usn, timestamp=filetime_to_iso(timestamp), reasons=_decode_reasons(reason),
        file_attributes=file_attrs, file_name=name,
    )


def parse_usn_buffer(data: bytes) -> Iterator[UsnRecord]:
    """Parse USN records from an in-memory buffer (small/extracted $J streams)."""
    pos, n = 0, len(data)
    while pos + 4 <= n:
        (record_length,) = struct.unpack_from("<I", data, pos)
        if record_length == 0:
            pos += 8  # sparse padding -- keep scanning forward
            continue
        if record_length < MIN_RECORD_SIZE or pos + record_length > n:
            break  # malformed or truncated at the boundary; stop rather than misparse
        record = _parse_v2_record(data[pos:pos + record_length])
        if record:
            yield record
        pos += record_length


def parse_usn_journal(path: str | Path, chunk_size: int = 4 * 1024 * 1024) -> Iterator[UsnRecord]:
    """Stream-parse a (potentially very large) extracted $J file without
    loading it entirely into memory."""
    with Path(path).open("rb") as fh:
        yield from _stream_parse(fh, chunk_size)


def _stream_parse(fh: BinaryIO, chunk_size: int) -> Iterator[UsnRecord]:
    leftover = b""
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        buf = leftover + chunk
        pos, n = 0, len(buf)
        while pos + 4 <= n:
            (record_length,) = struct.unpack_from("<I", buf, pos)
            if record_length == 0:
                pos += 8
                continue
            if record_length < MIN_RECORD_SIZE:
                pos += 8
                continue
            if pos + record_length > n:
                break  # incomplete record at chunk boundary -- carry over
            record = _parse_v2_record(buf[pos:pos + record_length])
            if record:
                yield record
            pos += record_length
        leftover = buf[pos:]
