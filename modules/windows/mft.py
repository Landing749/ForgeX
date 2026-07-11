"""NTFS Master File Table ($MFT) parser.

Parses raw MFT records from an extracted `$MFT` file (or any buffer of
concatenated 1024-byte FILE records, e.g. carved from a disk image).
Implements the documented on-disk structure directly:

FILE record header (fixed part, all NTFS versions):
    0   4   signature "FILE" ("BAAD" marks a corrupt/unrecovered record)
    4   2   Update Sequence Array (USA) offset
    6   2   USA size (in 2-byte words; includes the USN itself)
    8   8   $LogFile sequence number
    16  2   sequence number
    18  2   hard link count
    20  2   offset to first attribute
    22  2   flags (0x01 = in use, 0x02 = directory)
    24  4   used size of this MFT entry
    28  4   allocated size of this MFT entry
    32  8   file reference to base record (for attribute lists)
    40  2   next attribute id
    44  4   MFT record number (NTFS 3.1+ / XP and later)

Every sector of a record has its last 2 bytes replaced by the "Update
Sequence Number" at write time (corruption detection); the *real*
bytes are saved in the Update Sequence Array right after the header
and must be written back ("fixup") before the record's attribute data
can be trusted. This module applies that fixup before parsing.

Attributes are TLV-like: type code, length, resident/non-resident
flag, then either inline content (resident) or a data-run list
(non-resident, not decoded here -- only resident attribute content,
i.e. $STANDARD_INFORMATION and $FILE_NAME, which is what a timeline
needs, is decoded).
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RECORD_SIGNATURE = b"FILE"
DEFAULT_RECORD_SIZE = 1024
SECTOR_SIZE = 512

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

FILE_NAME_NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 & DOS"}

FILE_ATTRIBUTE_FLAGS = {
    0x0001: "READ_ONLY", 0x0002: "HIDDEN", 0x0004: "SYSTEM", 0x0020: "ARCHIVE",
    0x0400: "REPARSE_POINT", 0x0800: "COMPRESSED", 0x2000: "ENCRYPTED",
    0x10000000: "DIRECTORY",
}


def filetime_to_iso(filetime: int) -> str | None:
    if not filetime:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)).isoformat()
    except (OverflowError, OSError):
        return None


class MftError(Exception):
    pass


@dataclass
class StandardInformation:
    created: str | None
    modified: str | None
    mft_modified: str | None
    accessed: str | None
    file_flags: list[str]


@dataclass
class FileNameAttribute:
    name: str
    namespace: str
    parent_ref: int
    parent_seq: int
    created: str | None
    modified: str | None
    mft_modified: str | None
    accessed: str | None
    logical_size: int
    physical_size: int


@dataclass
class MftRecord:
    record_number: int
    sequence_number: int
    in_use: bool
    is_directory: bool
    hard_link_count: int
    base_record_ref: int
    standard_information: StandardInformation | None = None
    file_names: list[FileNameAttribute] = field(default_factory=list)

    @property
    def best_name(self) -> str | None:
        # Prefer the Win32 namespace name when multiple $FILE_NAME attrs exist
        # (short 8.3 DOS names are also common and less useful for a timeline).
        for fn in self.file_names:
            if fn.namespace == "Win32":
                return fn.name
        return self.file_names[0].name if self.file_names else None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["best_name"] = self.best_name
        return d


def _apply_fixup(record: bytearray, sector_size: int = SECTOR_SIZE) -> bytearray:
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count == 0:
        return record
    for i in range(1, usa_count):
        sector_end = i * sector_size
        if sector_end > len(record):
            break
        original = record[usa_offset + i * 2: usa_offset + i * 2 + 2]
        # (We don't hard-fail on USN mismatch -- some tools/carved records
        # won't have a perfectly matching trailing USN -- but we still
        # restore the saved original bytes, which is the actual fixup.)
        record[sector_end - 2:sector_end] = original
    return record


def parse_record(raw: bytes, record_size: int = DEFAULT_RECORD_SIZE) -> MftRecord | None:
    """Parse a single MFT record. Returns None for unused/unallocated or
    non-FILE-signature (e.g. all-zero, carved-junk) slots."""
    if len(raw) < 48:
        return None
    if raw[:4] != RECORD_SIGNATURE:
        return None

    buf = _apply_fixup(bytearray(raw[:record_size]))

    seq_number, hard_link_count, attr_offset, flags = struct.unpack_from("<HHHH", buf, 16)
    base_record_ref = struct.unpack_from("<Q", buf, 32)[0]
    record_number = struct.unpack_from("<I", buf, 44)[0] if len(buf) >= 48 else 0

    in_use = bool(flags & 0x0001)
    is_directory = bool(flags & 0x0002)

    record = MftRecord(
        record_number=record_number, sequence_number=seq_number, in_use=in_use,
        is_directory=is_directory, hard_link_count=hard_link_count,
        base_record_ref=base_record_ref,
    )

    offset = attr_offset
    while offset + 8 <= len(buf):
        attr_type = struct.unpack_from("<I", buf, offset)[0]
        if attr_type == ATTR_END or attr_type == 0:
            break
        attr_len = struct.unpack_from("<I", buf, offset + 4)[0]
        if attr_len == 0 or offset + attr_len > len(buf):
            break
        non_resident = buf[offset + 8]

        if not non_resident:
            content_len, content_offset = struct.unpack_from("<IH", buf, offset + 16)
            content = bytes(buf[offset + content_offset: offset + content_offset + content_len])
            if attr_type == ATTR_STANDARD_INFORMATION and len(content) >= 32:
                record.standard_information = _parse_standard_information(content)
            elif attr_type == ATTR_FILE_NAME and len(content) >= 66:
                fn = _parse_file_name(content)
                if fn:
                    record.file_names.append(fn)

        offset += attr_len

    return record


def _parse_standard_information(content: bytes) -> StandardInformation:
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", content, 0)
    dos_flags = struct.unpack_from("<I", content, 32)[0]
    flags = [name for bit, name in FILE_ATTRIBUTE_FLAGS.items() if dos_flags & bit]
    return StandardInformation(
        created=filetime_to_iso(created), modified=filetime_to_iso(modified),
        mft_modified=filetime_to_iso(mft_modified), accessed=filetime_to_iso(accessed),
        file_flags=flags,
    )


def _parse_file_name(content: bytes) -> FileNameAttribute | None:
    parent_ref_raw = struct.unpack_from("<Q", content, 0)[0]
    parent_ref = parent_ref_raw & 0x0000FFFFFFFFFFFF
    parent_seq = (parent_ref_raw >> 48) & 0xFFFF
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", content, 8)
    allocated_size, real_size = struct.unpack_from("<QQ", content, 40)
    name_length = content[64]
    namespace = content[65]
    name_bytes = content[66:66 + name_length * 2]
    if len(name_bytes) < name_length * 2:
        return None
    name = name_bytes.decode("utf-16le", errors="ignore")
    return FileNameAttribute(
        name=name, namespace=FILE_NAME_NAMESPACE.get(namespace, str(namespace)),
        parent_ref=parent_ref, parent_seq=parent_seq,
        created=filetime_to_iso(created), modified=filetime_to_iso(modified),
        mft_modified=filetime_to_iso(mft_modified), accessed=filetime_to_iso(accessed),
        logical_size=real_size, physical_size=allocated_size,
    )


def parse_mft_file(path: str | Path, record_size: int = DEFAULT_RECORD_SIZE) -> Iterator[MftRecord]:
    """Stream-parse an extracted $MFT file, yielding one MftRecord per
    allocated FILE-signature slot (skips unused/corrupt slots)."""
    with Path(path).open("rb") as fh:
        while True:
            raw = fh.read(record_size)
            if len(raw) < record_size:
                break
            record = parse_record(raw, record_size)
            if record is not None:
                yield record


def build_path_index(records: list[MftRecord]) -> dict[int, MftRecord]:
    """Index records by MFT record number, useful for resolving
    parent_ref chains into full paths via resolve_path()."""
    return {r.record_number: r for r in records}


def resolve_path(record: MftRecord, index: dict[int, MftRecord], max_depth: int = 64) -> str:
    """Walk parent_ref chains (via $FILE_NAME) to reconstruct a full path.
    Record 5 is the volume root ('.') in every NTFS volume."""
    parts = []
    current = record
    depth = 0
    while current and depth < max_depth:
        name = current.best_name
        if current.record_number == 5:
            break
        if name:
            parts.append(name)
        if not current.file_names:
            break
        parent_num = current.file_names[0].parent_ref
        if parent_num == current.record_number:
            break
        current = index.get(parent_num)
        depth += 1
    return "\\" + "\\".join(reversed(parts))
