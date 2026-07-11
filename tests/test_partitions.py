import struct
import uuid

import pytest

from modules.disk.partitions import (
    GPT_SIGNATURE,
    MBR_SIGNATURE,
    PartitionTableError,
    parse_partition_table,
)


def _build_mbr(entries: list[tuple[int, int, int, int]]) -> bytes:
    """entries: list of (status, type_byte, start_lba, sector_count)"""
    sector = bytearray(512)
    for i, (status, type_byte, start_lba, count) in enumerate(entries):
        offset = 446 + i * 16
        sector[offset] = status
        sector[offset + 4] = type_byte
        struct.pack_into("<II", sector, offset + 8, start_lba, count)
    sector[510:512] = MBR_SIGNATURE
    return bytes(sector)


def test_parse_simple_mbr():
    data = _build_mbr([
        (0x80, 0x07, 2048, 204800),   # bootable NTFS partition
        (0x00, 0x83, 206848, 409600),  # Linux partition
    ])
    table = parse_partition_table(data)
    assert table.scheme == "MBR"
    assert len(table.mbr_partitions) == 2
    assert table.mbr_partitions[0].bootable is True
    assert table.mbr_partitions[0].type_name == "NTFS/exFAT"
    assert table.mbr_partitions[0].start_lba == 2048
    assert table.mbr_partitions[1].type_name == "Linux"


def test_mbr_skips_unused_entries():
    data = _build_mbr([(0x80, 0x07, 2048, 204800), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0)])
    table = parse_partition_table(data)
    assert len(table.mbr_partitions) == 1


def test_rejects_missing_boot_signature():
    data = bytearray(512)
    data[446 + 4] = 0x07  # a plausible-looking entry, but no 0x55AA signature
    with pytest.raises(PartitionTableError):
        parse_partition_table(bytes(data))


def _build_gpt_entry(type_guid: uuid.UUID, unique_guid: uuid.UUID, first_lba: int,
                      last_lba: int, name: str, entry_size: int = 128) -> bytes:
    entry = bytearray(entry_size)
    entry[0:16] = type_guid.bytes_le
    entry[16:32] = unique_guid.bytes_le
    struct.pack_into("<QQQ", entry, 32, first_lba, last_lba, 0)
    name_bytes = name.encode("utf-16le")
    entry[56:56 + len(name_bytes)] = name_bytes
    return bytes(entry)


def _build_gpt_disk(partitions: list[tuple[str, str, int, int]], sector_size: int = 512) -> bytes:
    """partitions: list of (type_guid_str, name, first_lba, last_lba)"""
    protective_mbr = _build_mbr([(0x00, 0xEE, 1, 0xFFFFFFFF)])

    entry_size = 128
    num_entries = 128
    entries_lba = 2
    entries_bytes = bytearray(entry_size * num_entries)
    for i, (type_guid_str, name, first_lba, last_lba) in enumerate(partitions):
        entry = _build_gpt_entry(uuid.UUID(type_guid_str), uuid.uuid4(), first_lba, last_lba, name, entry_size)
        entries_bytes[i * entry_size:(i + 1) * entry_size] = entry

    header = bytearray(sector_size)
    header[0:8] = GPT_SIGNATURE
    struct.pack_into("<I", header, 8, 0x00010000)  # revision
    struct.pack_into("<I", header, 12, 92)  # header size
    disk_guid = uuid.uuid4()
    header[56:72] = disk_guid.bytes_le
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 80, num_entries)
    struct.pack_into("<I", header, 84, entry_size)

    disk = protective_mbr + bytes(header)
    # pad up to entries_lba, then place the entries array
    disk += b"\x00" * (sector_size * (entries_lba - 2))
    disk += bytes(entries_bytes)
    return disk


def test_parse_gpt_disk():
    ntfs_type = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
    esp_type = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    data = _build_gpt_disk([
        (esp_type, "EFI System", 34, 2081),
        (ntfs_type, "Windows", 2082, 2000000),
    ])
    table = parse_partition_table(data)
    assert table.scheme == "GPT"
    assert len(table.gpt_partitions) == 2
    assert table.gpt_partitions[0].type_name == "EFI System Partition"
    assert table.gpt_partitions[0].name == "EFI System"
    assert table.gpt_partitions[1].type_name == "Microsoft Basic Data (NTFS/FAT)"
    assert table.gpt_partitions[1].first_lba == 2082
    assert table.disk_guid is not None


def test_gpt_skips_unused_entries():
    data = _build_gpt_disk([("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "OnlyOne", 100, 200)])
    table = parse_partition_table(data)
    assert len(table.gpt_partitions) == 1
