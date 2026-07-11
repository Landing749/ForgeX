"""MBR and GPT partition table parser.

**MBR** (Master Boot Record), the classic BIOS-era scheme: 512 bytes
at LBA 0 -- 446 bytes of boot code, four 16-byte partition entries at
offset 446, and the 0x55AA boot signature at offset 510.

Partition entry (16 bytes):
    0   1   status (0x80 = bootable/active)
    1   3   CHS start (legacy, ignored here)
    4   1   partition type byte (0xEE = "GPT protective")
    5   3   CHS end (legacy, ignored here)
    8   4   LBA of first sector
    12  4   number of sectors

**GPT** (GUID Partition Table), the modern UEFI scheme: a protective
MBR (single 0xEE entry spanning the disk) at LBA 0, then a GPT header
at LBA 1 pointing at an array of 128-byte partition entries (each
carrying a type GUID, a unique GUID, an LBA range, and a UTF-16LE
name).
"""
from __future__ import annotations

import struct
import uuid as uuid_module
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SECTOR_SIZE = 512
MBR_SIGNATURE = b"\x55\xaa"
GPT_SIGNATURE = b"EFI PART"

MBR_PARTITION_TYPES = {
    0x00: "Empty", 0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)", 0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM",
    0xEE: "GPT protective", 0xEF: "EFI System",
}

# A handful of well-known GPT partition type GUIDs; anything else is
# reported as its raw GUID rather than guessed at.
GPT_PARTITION_TYPE_NAMES = {
    "00000000-0000-0000-0000-000000000000": "Unused",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data (NTFS/FAT)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery Environment",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux LVM",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
}


class PartitionTableError(Exception):
    pass


@dataclass
class MbrPartition:
    index: int
    bootable: bool
    type_byte: int
    type_name: str
    start_lba: int
    sector_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GptPartition:
    index: int
    type_guid: str
    type_name: str
    unique_guid: str
    first_lba: int
    last_lba: int
    attributes: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PartitionTable:
    scheme: str  # "MBR" or "GPT"
    mbr_partitions: list[MbrPartition] = field(default_factory=list)
    gpt_partitions: list[GptPartition] = field(default_factory=list)
    disk_guid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_mbr_partitions(sector0: bytes) -> list[MbrPartition]:
    partitions = []
    for i in range(4):
        offset = 446 + i * 16
        entry = sector0[offset:offset + 16]
        if len(entry) < 16:
            break
        status = entry[0]
        type_byte = entry[4]
        start_lba, sector_count = struct.unpack_from("<II", entry, 8)
        if type_byte == 0 and start_lba == 0 and sector_count == 0:
            continue  # unused entry
        partitions.append(MbrPartition(
            index=i, bootable=(status == 0x80), type_byte=type_byte,
            type_name=MBR_PARTITION_TYPES.get(type_byte, f"0x{type_byte:02X}"),
            start_lba=start_lba, sector_count=sector_count,
        ))
    return partitions


def _parse_gpt(data: bytes, sector_size: int = SECTOR_SIZE) -> PartitionTable:
    header = data[sector_size:sector_size + 512]
    if header[:8] != GPT_SIGNATURE:
        raise PartitionTableError("GPT signature not found at LBA 1")

    disk_guid = uuid_module.UUID(bytes_le=header[56:72])
    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    num_entries = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]

    entries_offset = entries_lba * sector_size
    partitions = []
    for i in range(num_entries):
        entry_start = entries_offset + i * entry_size
        entry = data[entry_start:entry_start + entry_size]
        if len(entry) < 128:
            break
        type_guid_raw = entry[0:16]
        if type_guid_raw == b"\x00" * 16:
            continue  # unused entry
        type_guid = uuid_module.UUID(bytes_le=type_guid_raw)
        unique_guid = uuid_module.UUID(bytes_le=entry[16:32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        name_raw = entry[56:56 + 72]
        name = name_raw.decode("utf-16le", errors="ignore").rstrip("\x00")

        type_guid_str = str(type_guid).upper()
        partitions.append(GptPartition(
            index=i, type_guid=type_guid_str,
            type_name=GPT_PARTITION_TYPE_NAMES.get(type_guid_str, type_guid_str),
            unique_guid=str(unique_guid), first_lba=first_lba, last_lba=last_lba,
            attributes=attrs, name=name,
        ))

    return PartitionTable(scheme="GPT", gpt_partitions=partitions, disk_guid=str(disk_guid))


def parse_partition_table(data: bytes, sector_size: int = SECTOR_SIZE) -> PartitionTable:
    if len(data) < sector_size:
        raise PartitionTableError("Buffer too short to contain a partition table")
    sector0 = data[:sector_size]
    if sector0[510:512] != MBR_SIGNATURE:
        raise PartitionTableError("Missing 0x55AA MBR boot signature at end of LBA 0")

    mbr_partitions = _parse_mbr_partitions(sector0)
    is_protective_gpt = any(p.type_byte == 0xEE for p in mbr_partitions)

    if is_protective_gpt and len(data) >= sector_size * 2:
        try:
            return _parse_gpt(data, sector_size)
        except PartitionTableError:
            pass  # fall through to plain MBR if the GPT header looks malformed

    return PartitionTable(scheme="MBR", mbr_partitions=mbr_partitions)


def parse_partition_table_file(path: str | Path, sector_size: int = SECTOR_SIZE,
                                max_read: int = 4 * 1024 * 1024) -> PartitionTable:
    with Path(path).open("rb") as fh:
        data = fh.read(max_read)
    return parse_partition_table(data, sector_size=sector_size)
