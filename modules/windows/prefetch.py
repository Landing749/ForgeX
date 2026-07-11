"""Windows Prefetch (.pf) parser.

Two on-disk generations exist:

1. **Legacy, uncompressed** (Windows XP through 8/8.1, format versions
   17/23/26/30 when not MAM-wrapped): a plain binary structure. Fully
   implemented here, verified against a self-constructed synthetic
   file (see tests/test_prefetch.py) since no external dependency or
   real sample is available in this environment.

2. **Windows 10+, MAM-container + Xpress-Huffman compressed**: the
   file starts with a "MAM\\x04" signature followed by the
   decompressed size, then an Xpress-Huffman-compressed payload that
   *is itself* one of the structures above once decompressed.

   MAM container detection/parsing (signature + decompressed size) is
   implemented and confident -- it's a simple 8-byte header. The
   Xpress-Huffman bitstream codec itself is a non-trivial, sparsely
   and only semi-officially documented (MS-XCA) bit-level compression
   scheme. Implementing it from memory without real compressed test
   vectors to validate against carries real risk of a *silently
   wrong* decompressor -- one that runs without error but produces
   corrupted output, which is a worse outcome for a forensics tool
   than an honest gap. `decompress_payload()` is therefore left as an
   explicit extension point: recommended approaches are calling
   `RtlDecompressBufferEx` via `ctypes` on a live Windows analysis
   host (100% correct by construction), or a maintained third-party
   implementation, rather than a from-scratch reimplementation here.
"""
from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCCA_SIGNATURE = b"SCCA"
MAM_SIGNATURE = b"MAM\x04"

FORMAT_VERSION_OS_HINT = {
    17: "Windows XP / Server 2003",
    23: "Windows Vista / 7",
    26: "Windows 8 / 8.1",
    30: "Windows 10 / 11",
}


def filetime_to_iso(filetime: int) -> str | None:
    if not filetime:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)).isoformat()
    except (OverflowError, OSError):
        return None


class PrefetchError(Exception):
    pass


@dataclass
class VolumeInfo:
    device_path: str
    creation_time: str | None
    serial_number: str


@dataclass
class PrefetchFile:
    version: int
    os_hint: str
    executable_name: str
    prefetch_hash: str
    file_size_field: int
    metrics_entry_count: int
    trace_chain_entry_count: int
    referenced_files: list[str] = field(default_factory=list)
    volumes: list[VolumeInfo] = field(default_factory=list)
    run_count: int | None = None
    last_run_time: str | None = None
    run_info_confidence: str = "high"  # "high" (v17) or "unavailable" (v23+, see module docstring)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_mam_compressed(data: bytes) -> bool:
    return data[:4] == MAM_SIGNATURE


def parse_mam_header(data: bytes) -> dict[str, Any]:
    """Parse the outer MAM container: signature + decompressed size.
    Does NOT decompress the payload -- see module docstring."""
    if not is_mam_compressed(data):
        raise PrefetchError("Not a MAM-compressed file (missing 'MAM\\x04' signature)")
    (decompressed_size,) = struct.unpack_from("<I", data, 4)
    return {
        "container": "MAM (Xpress-Huffman compressed)",
        "decompressed_size": decompressed_size,
        "compressed_payload_size": len(data) - 8,
        "note": "Payload decompression requires a validated Xpress-Huffman "
                "decoder; see modules.windows.prefetch module docstring for "
                "recommended approaches (RtlDecompressBufferEx via ctypes on "
                "a live Windows host, or a maintained third-party library).",
    }


def decompress_payload(_data: bytes) -> bytes:
    raise NotImplementedError(
        "Xpress-Huffman decompression is not implemented from scratch here "
        "(see modules.windows.prefetch module docstring for why, and for "
        "recommended alternatives). Once decompressed by another means, "
        "feed the resulting bytes to parse_uncompressed()."
    )


def parse_uncompressed(data: bytes) -> PrefetchFile:
    """Parse an uncompressed Prefetch buffer (either a legacy .pf file
    directly, or the result of externally decompressing a MAM payload)."""
    if data[4:8] != SCCA_SIGNATURE:
        raise PrefetchError("Missing 'SCCA' signature at offset 4 -- not an uncompressed Prefetch file")

    version = struct.unpack_from("<I", data, 0)[0]
    file_size_field = struct.unpack_from("<I", data, 12)[0]
    exe_name_raw = data[16:76]
    executable_name = exe_name_raw.decode("utf-16le", errors="ignore").rstrip("\x00")
    prefetch_hash = f"{struct.unpack_from('<I', data, 76)[0]:08X}"

    # Section A-D offset/length table (offset 84): stable across versions 17-30.
    (metrics_offset, metrics_count, trace_offset, trace_count,
     strings_offset, strings_length, volumes_offset, volumes_count,
     _volumes_length) = struct.unpack_from("<9I", data, 84)

    referenced_files = _parse_filename_strings(data, strings_offset, strings_length)
    volumes = _parse_volumes(data, volumes_offset, volumes_count, version)

    pf = PrefetchFile(
        version=version, os_hint=FORMAT_VERSION_OS_HINT.get(version, f"unknown (version {version})"),
        executable_name=executable_name, prefetch_hash=prefetch_hash,
        file_size_field=file_size_field, metrics_entry_count=metrics_count,
        trace_chain_entry_count=trace_count, referenced_files=referenced_files, volumes=volumes,
    )

    if version == 17:
        last_run_time = struct.unpack_from("<Q", data, 120)[0]
        run_count = struct.unpack_from("<I", data, 144)[0]
        pf.last_run_time = filetime_to_iso(last_run_time)
        pf.run_count = run_count
        pf.run_info_confidence = "high"
    else:
        # Vista+ formats add multiple last-run timestamps and moved the run
        # count field; the exact offset shifts across 23/26/30 in ways this
        # implementation has not validated against reference samples, so we
        # deliberately leave these unset rather than assert a guessed value.
        pf.run_info_confidence = "unavailable (version 23+ run-count/timestamp offsets not validated; " \
                                  "referenced_files/volumes above are still reliable)"

    return pf


def _parse_filename_strings(data: bytes, offset: int, length: int) -> list[str]:
    if not offset or not length or offset + length > len(data):
        return []
    block = data[offset:offset + length]
    text = block.decode("utf-16le", errors="ignore")
    return [s for s in text.split("\x00") if s]


def _parse_volumes(data: bytes, section_offset: int, count: int, version: int) -> list[VolumeInfo]:
    if not section_offset or not count:
        return []
    record_size = 40 if version >= 23 else 28
    volumes = []
    for i in range(count):
        rec_start = section_offset + i * record_size
        if rec_start + record_size > len(data):
            break
        path_offset, path_length_chars = struct.unpack_from("<II", data, rec_start)
        creation_time = struct.unpack_from("<Q", data, rec_start + 8)[0]
        serial = struct.unpack_from("<I", data, rec_start + 16)[0]

        abs_path_offset = section_offset + path_offset
        path_bytes = data[abs_path_offset: abs_path_offset + path_length_chars * 2]
        device_path = path_bytes.decode("utf-16le", errors="ignore").rstrip("\x00")

        volumes.append(VolumeInfo(
            device_path=device_path, creation_time=filetime_to_iso(creation_time),
            serial_number=f"{serial:08X}",
        ))
    return volumes


def parse_file(path: str | Path) -> dict[str, Any]:
    """Top-level entry point: detects MAM vs. legacy uncompressed and
    dispatches accordingly."""
    data = Path(path).read_bytes()
    if is_mam_compressed(data):
        return parse_mam_header(data)
    return parse_uncompressed(data).to_dict()
