"""Native Windows Registry hive (REGF) parser.

Implements the on-disk NT Registry File format from scratch (no
`python-registry` dependency): base block header, hbin allocation
blocks, and the nk (key node) / vk (value key) / lf,lh,li,ri (subkey
index) cell types.

Format reference (structure is stable across all NT registry hives:
SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve):

Base block (first 4096 bytes, only first 512 meaningful):
    0   4   signature "regf"
    4   4   primary sequence number
    8   4   secondary sequence number
    12  8   last written FILETIME
    20  4   major version
    24  4   minor version
    28  4   file type (0 = primary)
    32  4   file format (1)
    36  4   root cell offset (relative to first hbin)
    40  4   hbins data size
    44  4   clustering factor
    48  64  file name (UTF-16LE)
    508 4   XOR-32 checksum of bytes 0..507

hbin block (repeats until hbins data size is consumed), each starting
with "hbin", followed by variable-size cells. A cell is a signed
4-byte size (negative = allocated) followed by its payload, whose
first 2 bytes (for structured cells) are a type signature: nk, vk,
sk, lf, lh, li, ri, db.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REGF_SIGNATURE = b"regf"
HBIN_SIGNATURE = b"hbin"
HIVE_HEADER_SIZE = 4096

VALUE_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}


def filetime_to_iso(filetime: int) -> str | None:
    if not filetime:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)
        return dt.isoformat()
    except (OverflowError, OSError):
        return None


class RegistryError(Exception):
    pass


@dataclass
class RegistryValue:
    name: str
    type_id: int
    type_name: str
    data: Any

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type_name, "data": self.data}


@dataclass
class RegistryKey:
    name: str
    path: str
    last_written: str | None
    subkey_count: int
    value_count: int
    values: list[RegistryValue] = field(default_factory=list)
    subkeys: list[RegistryKey] = field(default_factory=list)

    def to_dict(self, recursive: bool = True) -> dict[str, Any]:
        d = {
            "name": self.name, "path": self.path, "last_written": self.last_written,
            "subkey_count": self.subkey_count, "value_count": self.value_count,
            "values": [v.to_dict() for v in self.values],
        }
        if recursive:
            d["subkeys"] = [k.to_dict(recursive=True) for k in self.subkeys]
        else:
            d["subkeys"] = [k.name for k in self.subkeys]
        return d


class RegistryHive:
    """Read-only, in-memory-mapped access to a single hive file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:4] != REGF_SIGNATURE:
            raise RegistryError(f"{path} is not a valid registry hive (bad 'regf' signature)")
        self._parse_header()

    def _parse_header(self) -> None:
        h = self.data
        (self.major_version,) = struct.unpack_from("<I", h, 20)
        (self.minor_version,) = struct.unpack_from("<I", h, 24)
        (self.root_cell_offset,) = struct.unpack_from("<I", h, 36)
        (self.hbins_data_size,) = struct.unpack_from("<I", h, 40)
        name_raw = h[48:112]
        self.hive_name = name_raw.decode("utf-16le", errors="ignore").rstrip("\x00")
        checksum = self._xor32(h[:508])
        (stored_checksum,) = struct.unpack_from("<I", h, 508)
        self.checksum_valid = checksum == stored_checksum

    @staticmethod
    def _xor32(buf: bytes) -> int:
        value = 0
        for i in range(0, len(buf) - 3, 4):
            (word,) = struct.unpack_from("<I", buf, i)
            value ^= word
        return value & 0xFFFFFFFF

    # -- cell access ---------------------------------------------------
    def _abs_offset(self, relative_offset: int) -> int:
        return HIVE_HEADER_SIZE + relative_offset

    def _cell(self, relative_offset: int) -> bytes:
        """Return the payload bytes of the cell at the given hbins-relative offset."""
        abs_off = self._abs_offset(relative_offset)
        if abs_off + 4 > len(self.data):
            raise RegistryError(f"Cell offset {relative_offset} out of bounds")
        (size,) = struct.unpack_from("<i", self.data, abs_off)
        cell_size = abs(size)
        return self.data[abs_off + 4: abs_off + cell_size]

    # -- record parsers --------------------------------------------------
    def _parse_nk(self, relative_offset: int, path: str = "") -> RegistryKey:
        cell = self._cell(relative_offset)
        if cell[:2] != b"nk":
            raise RegistryError(f"Expected nk record at offset {relative_offset}, got {cell[:2]!r}")

        last_written = struct.unpack_from("<Q", cell, 4)[0]
        num_subkeys = struct.unpack_from("<I", cell, 20)[0]
        subkeys_list_offset = struct.unpack_from("<I", cell, 28)[0]
        num_values = struct.unpack_from("<I", cell, 36)[0]
        values_list_offset = struct.unpack_from("<I", cell, 40)[0]
        name_length = struct.unpack_from("<H", cell, 72)[0]
        flags = struct.unpack_from("<H", cell, 2)[0]
        is_ascii_name = bool(flags & 0x0020)
        raw_name = cell[76:76 + name_length]
        name = raw_name.decode("ascii" if is_ascii_name else "utf-16le", errors="ignore")

        full_path = f"{path}\\{name}" if path else name
        key = RegistryKey(
            name=name, path=full_path, last_written=filetime_to_iso(last_written),
            subkey_count=num_subkeys, value_count=num_values,
        )

        if num_values and values_list_offset != 0xFFFFFFFF:
            key.values = self._parse_value_list(values_list_offset, num_values)

        if num_subkeys and subkeys_list_offset != 0xFFFFFFFF:
            for subkey_offset in self._subkey_offsets(subkeys_list_offset):
                try:
                    key.subkeys.append(self._parse_nk(subkey_offset, path=full_path))
                except RegistryError:
                    continue
        return key

    def _subkey_offsets(self, list_offset: int) -> list[int]:
        cell = self._cell(list_offset)
        sig = cell[:2]
        (count,) = struct.unpack_from("<H", cell, 2)
        offsets: list[int] = []
        if sig in (b"lf", b"lh"):
            for i in range(count):
                offset = struct.unpack_from("<I", cell, 4 + i * 8)[0]
                offsets.append(offset)
        elif sig == b"li":
            for i in range(count):
                offset = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                offsets.append(offset)
        elif sig == b"ri":
            for i in range(count):
                sub_list_offset = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                offsets.extend(self._subkey_offsets(sub_list_offset))
        return offsets

    def _parse_value_list(self, list_offset: int, count: int) -> list[RegistryValue]:
        cell = self._cell(list_offset)
        values = []
        for i in range(count):
            if (i + 1) * 4 > len(cell):
                break
            (vk_offset,) = struct.unpack_from("<I", cell, i * 4)
            try:
                values.append(self._parse_vk(vk_offset))
            except RegistryError:
                continue
        return values

    def _parse_vk(self, relative_offset: int) -> RegistryValue:
        cell = self._cell(relative_offset)
        if cell[:2] != b"vk":
            raise RegistryError(f"Expected vk record at offset {relative_offset}, got {cell[:2]!r}")

        name_length = struct.unpack_from("<H", cell, 2)[0]
        (data_size_raw,) = struct.unpack_from("<i", cell, 4)
        (data_offset,) = struct.unpack_from("<I", cell, 8)
        (type_id,) = struct.unpack_from("<I", cell, 12)
        (flags,) = struct.unpack_from("<H", cell, 16)

        is_ascii_name = bool(flags & 0x0001)
        name = (cell[20:20 + name_length].decode("ascii" if is_ascii_name else "utf-16le", errors="ignore")
                if name_length else "(Default)")

        inline = data_size_raw < 0  # top bit set => data stored directly in the offset field
        data_size = abs(data_size_raw)
        if inline:
            raw_data = struct.pack("<I", data_offset)[:data_size]
        else:
            raw_data = self._read_value_data(data_offset, data_size)

        decoded = self._decode_value(type_id, raw_data)
        return RegistryValue(name=name, type_id=type_id,
                              type_name=VALUE_TYPES.get(type_id, f"UNKNOWN({type_id})"), data=decoded)

    def _read_value_data(self, data_offset: int, size: int) -> bytes:
        try:
            cell = self._cell(data_offset)
        except RegistryError:
            return b""
        if cell[:2] == b"db":  # big-data: indirect block list for values > ~16KB
            return self._read_big_data(cell, size)
        return cell[:size]

    def _read_big_data(self, db_cell: bytes, total_size: int) -> bytes:
        (num_segments,) = struct.unpack_from("<H", db_cell, 2)
        (segment_list_offset,) = struct.unpack_from("<I", db_cell, 4)
        segment_list = self._cell(segment_list_offset)
        chunks = []
        remaining = total_size
        for i in range(num_segments):
            (seg_offset,) = struct.unpack_from("<I", segment_list, i * 4)
            seg_cell = self._cell(seg_offset)
            take = min(len(seg_cell), remaining)
            chunks.append(seg_cell[:take])
            remaining -= take
            if remaining <= 0:
                break
        return b"".join(chunks)

    @staticmethod
    def _decode_value(type_id: int, raw: bytes) -> Any:
        try:
            if type_id in (1, 2):  # REG_SZ / REG_EXPAND_SZ
                return raw.decode("utf-16le", errors="ignore").rstrip("\x00")
            if type_id == 4:  # REG_DWORD
                return struct.unpack("<I", raw[:4])[0] if len(raw) >= 4 else None
            if type_id == 5:  # REG_DWORD_BIG_ENDIAN
                return struct.unpack(">I", raw[:4])[0] if len(raw) >= 4 else None
            if type_id == 11:  # REG_QWORD
                return struct.unpack("<Q", raw[:8])[0] if len(raw) >= 8 else None
            if type_id == 7:  # REG_MULTI_SZ
                text = raw.decode("utf-16le", errors="ignore")
                return [s for s in text.split("\x00") if s]
        except struct.error:
            return raw.hex()
        return raw.hex()  # REG_BINARY and anything else: hex-encoded

    # -- public API ---------------------------------------------------
    def root(self) -> RegistryKey:
        return self._parse_nk(self.root_cell_offset)

    def open_key(self, key_path: str) -> RegistryKey:
        """Navigate a backslash-delimited path from the hive root."""
        current = self.root()
        if not key_path:
            return current
        for part in key_path.strip("\\").split("\\"):
            match = next((k for k in current.subkeys if k.name.lower() == part.lower()), None)
            if match is None:
                raise RegistryError(f"Subkey '{part}' not found under '{current.path}'")
            current = match
        return current

    def walk(self) -> Iterator[RegistryKey]:
        def _recurse(key: RegistryKey) -> Iterator[RegistryKey]:
            yield key
            for sub in key.subkeys:
                yield from _recurse(sub)
        yield from _recurse(self.root())


def parse_hive(path: str | Path, key_path: str | None = None) -> dict[str, Any]:
    """CLI/engine-facing entry point matching the interface used elsewhere
    in modules/windows/artifacts.py."""
    hive = RegistryHive(path)
    key = hive.open_key(key_path) if key_path else hive.root()
    return key.to_dict(recursive=True)
