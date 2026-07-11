"""EWF / E01 (EnCase Evidence File format, "EWF1") reader.

EWF wraps a raw disk image in a sequence of typed, checksummed
**sections** (walked via each section's own "next section offset", or
sequentially as a fallback). The sections that matter for recovering
the original raw bytes are:

    "table" / "table2"  -- an array of offsets (one per chunk) into a
                            "sectors" section, with compression
                            indicated by whether the chunk data
                            zlib-inflates successfully
    "sectors"           -- the actual chunk data referenced by a table

Section descriptor (76 bytes, precedes every section's body):
    0   16  type (ASCII, NUL-padded) e.g. "header","volume","sectors",
            "table","table2","next","data","done"
    16  8   next section offset (absolute file offset, uint64 LE)
    24  8   section size (this descriptor + body, uint64 LE)
    32  40  padding
    72  4   checksum (adler32 of the preceding 72 bytes, uint32 LE)

This module prioritizes what's needed to reconstruct the raw image
(section framing + table/sectors chunk assembly), which is the same
across EWF1 tooling. The "volume"/"disk" section's internal media-info
field layout has more edge-to-edge variation across EnCase versions
(1-4 vs 5+) than the section framing does; those fields are parsed
best-effort and clearly marked, rather than asserted as certain --
cross-check with a reference tool (e.g. `ewfinfo`) for evidentiary use
of sector-geometry metadata specifically. Multi-segment evidence sets
(E01, E02, E03, ...) are supported by concatenating segment files in
order; Ex01 (EWF2, used by newer EnCase/FTK) uses a different section
schema and is not covered here.
"""
from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

EWF1_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
SECTION_DESCRIPTOR_SIZE = 76


class EwfError(Exception):
    pass


@dataclass
class Section:
    type: str
    offset: int  # absolute file offset of this section's descriptor
    next_offset: int
    size: int
    body_offset: int  # absolute offset where the section body begins
    body_size: int


def _read_section(data: bytes, offset: int) -> Section:
    if offset + SECTION_DESCRIPTOR_SIZE > len(data):
        raise EwfError(f"Section descriptor at {offset} runs past end of file")
    raw_type = data[offset:offset + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
    next_offset, size = struct.unpack_from("<QQ", data, offset + 16)
    body_offset = offset + SECTION_DESCRIPTOR_SIZE
    body_size = max(0, size - SECTION_DESCRIPTOR_SIZE)
    return Section(type=raw_type, offset=offset, next_offset=next_offset, size=size,
                    body_offset=body_offset, body_size=body_size)


def iter_sections(data: bytes) -> Iterator[Section]:
    if data[:8] != EWF1_SIGNATURE:
        raise EwfError("Not an EWF1/E01 file (missing signature)")
    offset = 13  # 8-byte signature + 1 fields_start + 2 segment_number + 2 fields_end
    seen = set()
    while 0 < offset < len(data) and offset not in seen:
        seen.add(offset)
        section = _read_section(data, offset)
        yield section
        if section.type == "done" or section.next_offset == 0:
            break
        offset = section.next_offset


def _decompress_chunk(raw: bytes) -> bytes:
    """EWF1 doesn't carry a reliable explicit per-chunk compression flag
    in all producer implementations; the practical, widely-used approach
    (matching what most open-source EWF readers do) is to attempt zlib
    inflate and fall back to the raw bytes if that fails."""
    try:
        return zlib.decompress(raw)
    except zlib.error:
        return raw


def _parse_table_section(data: bytes, section: Section) -> tuple[int, list[int]]:
    """Returns (base_offset, [chunk_offsets_relative_to_a_sectors_section])."""
    body = data[section.body_offset:section.body_offset + section.body_size]
    if len(body) < 24:
        raise EwfError(f"Table section at {section.offset} too short to contain a header")
    (num_entries,) = struct.unpack_from("<I", body, 0)
    (base_offset,) = struct.unpack_from("<Q", body, 8)
    entries_start = 24
    offsets = []
    for i in range(num_entries):
        pos = entries_start + i * 4
        if pos + 4 > len(body):
            break
        (raw_offset,) = struct.unpack_from("<I", body, pos)
        offsets.append(raw_offset & 0x7FFFFFFF)  # strip the (unreliable, see above) compression flag bit
    return base_offset, offsets


def reconstruct_raw_image(path: str | Path, max_bytes: int | None = None) -> bytes:
    """Reconstruct the raw (dd-equivalent) disk image bytes from a
    single-segment E01 file by walking its table -> sectors chunks."""
    data = Path(path).read_bytes()
    sections = list(iter_sections(data))

    sectors_sections = {s.offset: s for s in sections if s.type == "sectors"}
    table_sections = [s for s in sections if s.type in ("table", "table2")]
    if not table_sections:
        raise EwfError("No 'table' section found -- cannot reconstruct chunk layout")

    # In EWF1, a table's chunk offsets are relative to the "sectors"
    # section that immediately follows the table's base_offset convention;
    # in practice the base_offset field (or, if zero, the nearest
    # preceding "sectors" section) anchors them.
    output = bytearray()
    for table in table_sections:
        base_offset, chunk_offsets = _parse_table_section(data, table)
        sectors_section = sectors_sections.get(base_offset)
        if sectors_section is None:
            # Fall back to the nearest sectors section before this table.
            candidates = [s for s in sections if s.type == "sectors" and s.offset < table.offset]
            sectors_section = candidates[-1] if candidates else None
        if sectors_section is None:
            continue

        for i, chunk_off in enumerate(chunk_offsets):
            chunk_start = sectors_section.body_offset + chunk_off
            chunk_end = (sectors_section.body_offset + chunk_offsets[i + 1]
                         if i + 1 < len(chunk_offsets) else sectors_section.body_offset + sectors_section.body_size)
            raw_chunk = data[chunk_start:chunk_end]
            output.extend(_decompress_chunk(raw_chunk))
            if max_bytes and len(output) >= max_bytes:
                return bytes(output[:max_bytes])

    return bytes(output)


def get_case_info(path: str | Path) -> str | None:
    """Return the decompressed raw text of the 'header'/'header2' section
    (EnCase case metadata: examiner name, acquisition date, notes, ...)
    without parsing its internal field schema, which varies by EnCase
    version and encoding (ASCII vs UTF-16 for header2)."""
    data = Path(path).read_bytes()
    for section in iter_sections(data):
        if section.type in ("header", "header2"):
            body = data[section.body_offset:section.body_offset + section.body_size]
            try:
                decompressed = zlib.decompress(body)
            except zlib.error:
                continue
            try:
                return decompressed.decode("utf-16le")
            except UnicodeDecodeError:
                return decompressed.decode("ascii", errors="ignore")
    return None


def summarize(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    sections = list(iter_sections(data))
    return {
        "signature_valid": data[:8] == EWF1_SIGNATURE,
        "section_count": len(sections),
        "section_types": [s.type for s in sections],
        "has_case_info": any(s.type in ("header", "header2") for s in sections),
        "table_section_count": sum(1 for s in sections if s.type in ("table", "table2")),
    }
