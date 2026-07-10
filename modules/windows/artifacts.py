"""Windows Module.

Covers: Registry, Prefetch, Amcache, Shimcache, Jump Lists, EVTX, USN,
MFT, LNK, Services, Tasks, USB.

Parsing strategy:
  - LNK (Shell Link binary format) is a fixed, documented structure and
    is fully parsed here with stdlib `struct` only.
  - Registry hives and EVTX logs are parsed via the optional
    `python-registry` and `python-evtx` packages when installed
    (`pip install forgex[full]`); without them these functions raise a
    clear NotImplementedError rather than silently returning nothing.
  - Prefetch (compressed w/ MAM header on Win10+), Amcache.hve
    (a registry hive with its own schema), Shimcache, Jump Lists (OLE
    compound files), USN journal, MFT, Services/Tasks, and USB history
    are all defined here as stable interfaces + parsing notes; each
    requires either binary-format-specific decompression/parsing or
    reading from the same optional registry backend, which is a
    natural Plugin SDK extension point (see plugins/).
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
    try:
        from Registry import Registry
    except ImportError as exc:
        raise NotImplementedError(
            "Registry parsing requires the optional 'python-registry' package "
            "(pip install forgex[full])."
        ) from exc

    reg = Registry.Registry(str(path))
    root = reg.open(key_path) if key_path else reg.root()

    def _walk(key) -> dict[str, Any]:
        return {
            "name": key.name(),
            "timestamp": key.timestamp().isoformat(),
            "values": [{"name": v.name(), "type": v.value_type_str(), "value": str(v.value())}
                       for v in key.values()],
            "subkeys": [_walk(k) for k in key.subkeys()],
        }
    return [_walk(root)]


# -- EVTX ------------------------------------------------------------------
def parse_evtx(path: str | Path, max_records: int = 10_000) -> list[dict[str, Any]]:
    try:
        import Evtx.Evtx as evtx
    except ImportError as exc:
        raise NotImplementedError(
            "EVTX parsing requires the optional 'python-evtx' package "
            "(pip install forgex[full])."
        ) from exc

    records = []
    with evtx.Evtx(str(path)) as log:
        for i, record in enumerate(log.records()):
            if i >= max_records:
                break
            records.append({"record_num": record.record_num(), "xml": record.xml()})
    return records


# -- Extension points requiring format-specific decompression/parsing ------
def parse_prefetch(_path: str | Path) -> dict[str, Any]:
    raise NotImplementedError(
        "Prefetch parsing requires MAM decompression (Win10+) and version-"
        "specific offsets; implement via a plugin using e.g. `libscca`."
    )


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


def parse_usn_journal(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError("USN journal parsing requires raw $UsnJrnl:$J record parsing.")


def parse_mft(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError("MFT parsing requires raw $MFT record structure parsing (native backend).")


def list_services(_hive_path: str | Path) -> list[dict[str, Any]]:
    return parse_registry_hive(_hive_path, key_path="ControlSet001\\Services")


def list_scheduled_tasks(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError("Scheduled Tasks require parsing Task Scheduler XML under System32/Tasks.")


def usb_history(_hive_path: str | Path) -> list[dict[str, Any]]:
    return parse_registry_hive(_hive_path, key_path="ControlSet001\\Enum\\USBSTOR")
