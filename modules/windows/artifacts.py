"""Windows Module.

Covers: Registry, Prefetch, Amcache, Shimcache, Jump Lists, EVTX, USN,
MFT, LNK, Services, Tasks, USB.

Parsing strategy:
  - LNK (Shell Link binary format) is a fixed, documented structure and
    is fully parsed here with stdlib `struct` only.
  - Registry hives (regf format) are parsed by Forgex's own native
    parser (modules.windows.registry_native) -- no external dependency.
  - EVTX logs are parsed by Forgex's own native binary-XML parser
    (modules.windows.evtx_native) -- no external dependency.
  - Prefetch (both legacy uncompressed and Win10+ MAM/LZXPRESS-Huffman
    compressed), MFT, and the USN journal are parsed by native parsers
    in modules.windows.prefetch / mft / usn respectively.
  - Amcache.hve is a registry hive with its own schema and is parsed
    via parse_registry_hive() below.
  - Shimcache and Jump Lists remain documented extension points: the
    former needs OS-version-dependent binary-blob decoding of a
    specific registry value, the latter is an OLE Compound File
    Binary format best parsed with the optional `olefile` package.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# -- LNK (Shell Link) ------------------------------------------------------
_LNK_MAGIC = b"L\x00\x00\x00"
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


@dataclass
class LnkInfo:
    path: str
    target_path: str | None
    working_dir: str | None
    arguments: str | None
    icon_location: str | None
    relative_path: str | None
    flags: int


def parse_lnk(path: str | Path) -> LnkInfo:
    data = Path(path).read_bytes()
    if len(data) < 76 or data[:4] != _LNK_MAGIC:
        raise ValueError("Not a valid .lnk file (bad header magic)")

    flags = struct.unpack_from("<I", data, 20)[0]
    HAS_LINK_TARGET_ID_LIST = 0x01
    HAS_LINK_INFO = 0x02
    HAS_NAME = 0x04
    HAS_RELATIVE_PATH = 0x08
    HAS_WORKING_DIR = 0x10
    HAS_ARGUMENTS = 0x20
    HAS_ICON_LOCATION = 0x40
    IS_UNICODE = 0x80

    offset = 76  # end of ShellLinkHeader

    if flags & HAS_LINK_TARGET_ID_LIST:
        (id_list_size,) = struct.unpack_from("<H", data, offset)
        offset += 2 + id_list_size

    target_path = None
    if flags & HAS_LINK_INFO:
        link_info_start = offset
        (link_info_size,) = struct.unpack_from("<I", data, offset)
        try:
            (local_base_offset,) = struct.unpack_from("<I", data, offset + 16)
            if local_base_offset:
                abs_off = link_info_start + local_base_offset
                end = data.index(b"\x00", abs_off)
                target_path = data[abs_off:end].decode("ascii", errors="ignore")
        except (struct.error, ValueError):
            pass
        offset += link_info_size

    def read_string_data(off: int) -> tuple[str, int]:
        (char_count,) = struct.unpack_from("<H", data, off)
        off += 2
        if flags & IS_UNICODE:
            raw = data[off: off + char_count * 2]
            text = raw.decode("utf-16le", errors="ignore")
            off += char_count * 2
        else:
            raw = data[off: off + char_count]
            text = raw.decode("ascii", errors="ignore")
            off += char_count
        return text, off

    name = relative_path = working_dir = arguments = icon_location = None
    if flags & HAS_NAME:
        name, offset = read_string_data(offset)
    if flags & HAS_RELATIVE_PATH:
        relative_path, offset = read_string_data(offset)
    if flags & HAS_WORKING_DIR:
        working_dir, offset = read_string_data(offset)
    if flags & HAS_ARGUMENTS:
        arguments, offset = read_string_data(offset)
    if flags & HAS_ICON_LOCATION:
        icon_location, offset = read_string_data(offset)

    return LnkInfo(
        path=str(path),
        target_path=target_path or relative_path,
        working_dir=working_dir,
        arguments=arguments,
        icon_location=icon_location,
        relative_path=relative_path,
        flags=flags,
    )


# -- Registry ------------------------------------------------------------
def parse_registry_hive(path: str | Path, key_path: str | None = None) -> list[dict[str, Any]]:
    """Parse a registry hive using Forgex's native regf parser
    (modules.windows.registry_native) -- no external dependency required."""
    from modules.windows.registry_native import RegistryHive

    hive = RegistryHive(path)
    key = hive.open_key(key_path) if key_path else hive.root()
    return [key.to_dict(recursive=True)]


# -- EVTX ------------------------------------------------------------------
def parse_evtx(path: str | Path, max_records: int = 10_000) -> list[dict[str, Any]]:
    """Parse a Windows Event Log (.evtx) file using Forgex's native
    binary-XML parser (modules.windows.evtx_native) -- no external
    dependency required."""
    from modules.windows.evtx_native import parse_evtx_file

    return [r.to_dict() for r in parse_evtx_file(path, max_records=max_records)]


# -- Extension points requiring format-specific decompression/parsing ------
def parse_prefetch(path: str | Path) -> dict[str, Any]:
    """Parse a Prefetch file using Forgex's native parser
    (modules.windows.prefetch). Legacy uncompressed formats (v17/v23+)
    are fully parsed; Windows 10+ MAM/Xpress-Huffman-compressed files
    are detected and their container header parsed, but payload
    decompression is an explicit extension point -- see that module's
    docstring for why and for recommended approaches."""
    from modules.windows.prefetch import parse_file

    return parse_file(path)


def parse_amcache(path: str | Path) -> list[dict[str, Any]]:
    return parse_registry_hive(path, key_path="Root\\InventoryApplicationFile")


def parse_shimcache(_hive_or_evtx_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "Shimcache (AppCompatCache) requires binary-blob parsing of a "
        "specific registry value with OS-version-dependent structure."
    )


def parse_jump_lists(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "Jump Lists are OLE Compound File Binary format; parse with "
        "`olefile` (optional dep) in a plugin, then extract embedded LNK "
        "streams via parse_lnk() above."
    )


def parse_usn_journal(path: str | Path) -> list[dict[str, Any]]:
    """Parse an extracted $UsnJrnl:$J stream using Forgex's native parser
    (modules.windows.usn) -- no external dependency required."""
    from modules.windows.usn import parse_usn_journal as _parse

    return [r.to_dict() for r in _parse(path)]


def parse_mft(path: str | Path) -> list[dict[str, Any]]:
    """Parse an extracted $MFT file using Forgex's native parser
    (modules.windows.mft) -- no external dependency required."""
    from modules.windows.mft import parse_mft_file

    return [r.to_dict() for r in parse_mft_file(path)]


def list_services(_hive_path: str | Path) -> list[dict[str, Any]]:
    return parse_registry_hive(_hive_path, key_path="ControlSet001\\Services")


def list_scheduled_tasks(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError("Scheduled Tasks require parsing Task Scheduler XML under System32/Tasks.")


def usb_history(_hive_path: str | Path) -> list[dict[str, Any]]:
    return parse_registry_hive(_hive_path, key_path="ControlSet001\\Enum\\USBSTOR")
