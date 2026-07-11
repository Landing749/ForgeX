import struct
from pathlib import Path

import pytest

from modules.windows.registry_native import RegistryError, RegistryHive


def _make_cell(payload: bytes) -> bytes:
    total = 4 + len(payload)
    pad = (-total) % 8
    total_padded = total + pad
    return struct.pack("<i", -total_padded) + payload + b"\x00" * pad


def _build_vk(name: bytes, data_size_raw: int, data_offset: int, type_id: int, flags: int) -> bytes:
    payload = bytearray(20 + len(name))
    payload[0:2] = b"vk"
    struct.pack_into("<H", payload, 2, len(name))
    struct.pack_into("<i", payload, 4, data_size_raw)
    struct.pack_into("<I", payload, 8, data_offset)
    struct.pack_into("<I", payload, 12, type_id)
    struct.pack_into("<H", payload, 16, flags)
    struct.pack_into("<H", payload, 18, 0)
    payload[20:20 + len(name)] = name
    return bytes(payload)


def _build_nk(name: bytes, num_subkeys: int, subkeys_list_offset: int,
              num_values: int, values_list_offset: int, flags: int) -> bytes:
    payload = bytearray(76 + len(name))
    payload[0:2] = b"nk"
    struct.pack_into("<H", payload, 2, flags)
    struct.pack_into("<Q", payload, 4, 0)
    struct.pack_into("<I", payload, 12, 0)
    struct.pack_into("<I", payload, 16, 0)
    struct.pack_into("<I", payload, 20, num_subkeys)
    struct.pack_into("<I", payload, 24, 0)
    struct.pack_into("<I", payload, 28, subkeys_list_offset)
    struct.pack_into("<I", payload, 32, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 36, num_values)
    struct.pack_into("<I", payload, 40, values_list_offset)
    struct.pack_into("<I", payload, 44, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 48, 0xFFFFFFFF)
    for off in (52, 56, 60, 64, 68):
        struct.pack_into("<I", payload, off, 0)
    struct.pack_into("<H", payload, 72, len(name))
    struct.pack_into("<H", payload, 74, 0)
    payload[76:76 + len(name)] = name
    return bytes(payload)


def _build_lf(entries: list[tuple[int, int]]) -> bytes:
    payload = bytearray(4 + 8 * len(entries))
    payload[0:2] = b"lf"
    struct.pack_into("<H", payload, 2, len(entries))
    for i, (off, h) in enumerate(entries):
        struct.pack_into("<I", payload, 4 + i * 8, off)
        struct.pack_into("<I", payload, 8 + i * 8, h)
    return bytes(payload)


def _build_value_list(offsets: list[int]) -> bytes:
    payload = bytearray(4 * len(offsets))
    for i, off in enumerate(offsets):
        struct.pack_into("<I", payload, i * 4, off)
    return bytes(payload)


def _build_synthetic_hive(tmp_path: Path) -> Path:
    buf = bytearray()
    rel = 32  # first cell offset, right after the 32-byte hbin header

    def append(payload: bytes) -> int:
        nonlocal rel
        cell = _make_cell(payload)
        offset = rel
        buf.extend(cell)
        rel += len(cell)
        return offset

    offset_data = append("hello".encode("utf-16le"))
    offset_vk = append(_build_vk(b"ValueA", 10, offset_data, 1, 0x0001))  # REG_SZ, ascii name
    offset_value_list = append(_build_value_list([offset_vk]))
    offset_subkey_nk = append(_build_nk(b"Sub1", 0, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0x0020))
    offset_lf = append(_build_lf([(offset_subkey_nk, 0)]))
    offset_root_nk = append(_build_nk(b"RootKey", 1, offset_lf, 1, offset_value_list, 0x0020))

    hbin_size = 32 + len(buf)
    hbin_header = b"hbin" + struct.pack("<II", 0, hbin_size) + b"\x00" * 20
    hbins = hbin_header + bytes(buf)

    header = bytearray(4096)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 4, 1)
    struct.pack_into("<I", header, 8, 1)
    struct.pack_into("<Q", header, 12, 0)
    struct.pack_into("<I", header, 20, 1)
    struct.pack_into("<I", header, 24, 5)
    struct.pack_into("<I", header, 28, 0)
    struct.pack_into("<I", header, 32, 1)
    struct.pack_into("<I", header, 36, offset_root_nk)
    struct.pack_into("<I", header, 40, hbin_size)
    struct.pack_into("<I", header, 44, 1)
    name_bytes = "TESTHIVE".encode("utf-16le")
    header[48:48 + len(name_bytes)] = name_bytes
    checksum = RegistryHive._xor32(bytes(header[:508]))
    struct.pack_into("<I", header, 508, checksum)

    hive_path = tmp_path / "synthetic.hive"
    hive_path.write_bytes(bytes(header) + hbins)
    return hive_path


def test_parses_synthetic_hive_header(tmp_path: Path):
    path = _build_synthetic_hive(tmp_path)
    hive = RegistryHive(path)
    assert hive.checksum_valid is True
    assert hive.hive_name.startswith("TESTHIVE")


def test_root_key_and_value(tmp_path: Path):
    path = _build_synthetic_hive(tmp_path)
    hive = RegistryHive(path)
    root = hive.root()
    assert root.name == "RootKey"
    assert root.value_count == 1
    assert root.values[0].name == "ValueA"
    assert root.values[0].type_name == "REG_SZ"
    assert root.values[0].data == "hello"


def test_subkey_traversal(tmp_path: Path):
    path = _build_synthetic_hive(tmp_path)
    hive = RegistryHive(path)
    root = hive.root()
    assert root.subkey_count == 1
    assert len(root.subkeys) == 1
    assert root.subkeys[0].name == "Sub1"


def test_open_key_by_path(tmp_path: Path):
    path = _build_synthetic_hive(tmp_path)
    hive = RegistryHive(path)
    sub = hive.open_key("Sub1")
    assert sub.name == "Sub1"
    with pytest.raises(RegistryError):
        hive.open_key("DoesNotExist")


def test_walk_visits_all_keys(tmp_path: Path):
    path = _build_synthetic_hive(tmp_path)
    hive = RegistryHive(path)
    names = {k.name for k in hive.walk()}
    assert names == {"RootKey", "Sub1"}


def test_rejects_non_hive_file(tmp_path: Path):
    bogus = tmp_path / "notahive.bin"
    bogus.write_bytes(b"not a registry hive at all")
    with pytest.raises(RegistryError):
        RegistryHive(bogus)
