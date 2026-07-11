"""Native Windows Event Log (EVTX) parser.

Implements the on-disk EVTX container (file header -> 64KB chunks ->
event records) and the Binary XML encoding used for each record's
payload, from scratch -- no `python-evtx` dependency.

Binary XML is a token stream that reconstructs an XML document:
    0x00            EOF (end of stream)
    0x01 (|0x40)    OpenStartElement (flag bit = "has attributes/children")
    0x02            CloseStartElement
    0x03            CloseEmptyElement
    0x04            EndElement
    0x05            Value (inline typed value)
    0x06 (|0x40)    Attribute
    0x0C            TemplateInstance
    0x0D            NormalSubstitution
    0x0E            OptionalSubstitution
    0x0F            FragmentHeader

A TemplateInstance either defines a template inline (element tree with
substitution placeholders) or references one already seen earlier in
the chunk, followed by a substitution *value* array; decoding walks
the template tree and, at each substitution token, splices in the
corresponding typed value.

This covers the structures that appear in real Windows-generated
records (single top-level TemplateInstance, nested elements/attributes,
the common EVTX value types). Less common corners of the format
(nested BXML-typed values embedded as substitutions, multi-fragment
records) are handled best-effort and won't raise on the common path.
"""
from __future__ import annotations

import re
import struct
import uuid as uuid_module
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FILE_SIGNATURE = b"ElfFile\x00"
CHUNK_SIGNATURE = b"ElfChnk\x00"
RECORD_SIGNATURE = b"\x2a\x2a\x00\x00"
CHUNK_SIZE = 65536
FILE_HEADER_SIZE = 4096

TOK_EOF = 0x00
TOK_OPEN_START_ELEMENT = 0x01
TOK_CLOSE_START_ELEMENT = 0x02
TOK_CLOSE_EMPTY_ELEMENT = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_CDATA = 0x07
TOK_ENTITY_REF = 0x09
TOK_TEMPLATE_INSTANCE = 0x0C
TOK_NORMAL_SUBSTITUTION = 0x0D
TOK_OPTIONAL_SUBSTITUTION = 0x0E
TOK_FRAGMENT_HEADER = 0x0F


def filetime_to_iso(filetime: int) -> str | None:
    if not filetime:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)).isoformat()
    except (OverflowError, OSError):
        return None


class EvtxError(Exception):
    pass


@dataclass
class XmlElement:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    text: str = ""
    children: list[XmlElement] = field(default_factory=list)

    def to_xml(self, indent: int = 0) -> str:
        pad = "  " * indent
        attrs = "".join(f' {k}="{v}"' for k, v in self.attributes.items())
        if not self.children and not self.text:
            return f"{pad}<{self.name}{attrs} />"
        inner = self.text
        child_xml = "\n".join(c.to_xml(indent + 1) for c in self.children)
        body = "\n".join(x for x in (inner, child_xml) if x)
        return f"{pad}<{self.name}{attrs}>\n{body}\n{pad}</{self.name}>" if body else f"{pad}<{self.name}{attrs}></{self.name}>"

    def find(self, name: str) -> XmlElement | None:
        for c in self.children:
            if c.name == name:
                return c
        return None

    def findall(self, name: str) -> list[XmlElement]:
        return [c for c in self.children if c.name == name]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "attributes": self.attributes, "text": self.text,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class EvtxRecord:
    record_id: int
    timestamp: str | None
    xml: XmlElement

    def to_dict(self) -> dict[str, Any]:
        return {"record_id": self.record_id, "timestamp": self.timestamp, "xml": self.xml.to_dict()}


# -- value type decoding -----------------------------------------------
def _decode_value(type_id: int, raw: bytes) -> Any:
    base_type = type_id & 0x7F
    is_array = bool(type_id & 0x80)
    if is_array:
        return raw.hex()  # arrays of typed values: best-effort, exposed as raw hex
    try:
        if base_type == 0x00:
            return None
        if base_type == 0x01:  # unicode string
            return raw.decode("utf-16le", errors="ignore").rstrip("\x00")
        if base_type == 0x02:  # ansi string
            return raw.decode("ascii", errors="ignore").rstrip("\x00")
        if base_type == 0x03:
            return struct.unpack("<b", raw[:1])[0]
        if base_type == 0x04:
            return raw[0]
        if base_type == 0x05:
            return struct.unpack("<h", raw[:2])[0]
        if base_type == 0x06:
            return struct.unpack("<H", raw[:2])[0]
        if base_type == 0x07:
            return struct.unpack("<i", raw[:4])[0]
        if base_type == 0x08:
            return struct.unpack("<I", raw[:4])[0]
        if base_type == 0x09:
            return struct.unpack("<q", raw[:8])[0]
        if base_type == 0x0A:
            return struct.unpack("<Q", raw[:8])[0]
        if base_type == 0x0B:
            return struct.unpack("<f", raw[:4])[0]
        if base_type == 0x0C:
            return struct.unpack("<d", raw[:8])[0]
        if base_type == 0x0D:
            return bool(struct.unpack("<i", raw[:4])[0])
        if base_type == 0x0E:
            return raw.hex()  # binary
        if base_type == 0x0F:  # GUID
            return str(uuid_module.UUID(bytes_le=raw[:16])) if len(raw) >= 16 else raw.hex()
        if base_type == 0x11:  # FILETIME
            return filetime_to_iso(struct.unpack("<Q", raw[:8])[0])
        if base_type in (0x14, 0x15):  # HexInt32 / HexInt64
            n = struct.unpack("<I" if base_type == 0x14 else "<Q", raw[:4 if base_type == 0x14 else 8])[0]
            return hex(n)
    except struct.error:
        return raw.hex()
    return raw.hex()


class _BxmlReader:
    """Cursor over a chunk buffer, decoding one binary-XML token stream."""

    def __init__(self, buf: bytes, pos: int, chunk_start: int):
        self.buf = buf
        self.pos = pos
        self.chunk_start = chunk_start  # absolute offset where this chunk begins (for cached template refs)
        self.substitutions: list[Any] = []

    def u8(self) -> int:
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.buf, self.pos)[0]
        self.pos += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def bytes_(self, n: int) -> bytes:
        v = self.buf[self.pos:self.pos + n]
        self.pos += n
        return v

    def read_name(self) -> str:
        """Element/attribute names are stored either inline (a small
        header of hash+char-count followed by a NUL-terminated
        UTF-16LE string) when the 4-byte offset field points at itself,
        or as a back-reference to a name already defined earlier in the
        chunk (offset relative to chunk start) otherwise."""
        field_start = self.pos
        ref_offset = self.u32()
        inline = ref_offset == (field_start - self.chunk_start)
        if inline:
            self.u16()  # hash
            char_count = self.u16()
            name = self.bytes_(char_count * 2).decode("utf-16le", errors="ignore")
            self.u16()  # trailing NUL terminator
            return name
        saved_pos = self.pos
        self.pos = self.chunk_start + ref_offset
        self.u16()  # hash
        char_count = self.u16()
        name = self.bytes_(char_count * 2).decode("utf-16le", errors="ignore")
        self.pos = saved_pos
        return name

    def read_value_text(self) -> str:
        type_id = self.u8()
        length = self.u16()
        raw = self.bytes_(length)
        val = _decode_value(type_id, raw)
        return "" if val is None else str(val)

    def parse_element(self) -> XmlElement:
        token = self.u8()
        if token & 0x0F != TOK_OPEN_START_ELEMENT:
            raise EvtxError(f"Expected OpenStartElement, got token 0x{token:02x} at {self.pos - 1}")
        self.u16()  # unknown/dependency id
        self.u32()  # element data size
        name = self.read_name()
        element = XmlElement(name=name)

        # Attributes (zero or more), until CloseStartElement/CloseEmptyElement.
        while True:
            peek = self.buf[self.pos]
            if peek & 0x0F == TOK_ATTRIBUTE:
                self.u8()
                attr_name = self.read_name()
                value_token = self.buf[self.pos]
                if value_token & 0x0F in (TOK_NORMAL_SUBSTITUTION, TOK_OPTIONAL_SUBSTITUTION):
                    element.attributes[attr_name] = self._parse_substitution()
                else:
                    element.attributes[attr_name] = self.read_value_text()
            else:
                break

        close_token = self.u8()
        if close_token & 0x0F == TOK_CLOSE_EMPTY_ELEMENT:
            return element
        if close_token & 0x0F != TOK_CLOSE_START_ELEMENT:
            raise EvtxError(f"Expected CloseStartElement, got 0x{close_token:02x}")

        # Children: nested elements, text values, substitutions, until EndElement.
        while True:
            child_token = self.buf[self.pos]
            base = child_token & 0x0F
            if base == TOK_END_ELEMENT:
                self.u8()
                break
            if base == TOK_OPEN_START_ELEMENT:
                element.children.append(self.parse_element())
            elif base == TOK_VALUE:
                self.u8()
                element.text += self.read_value_text()
            elif base in (TOK_NORMAL_SUBSTITUTION, TOK_OPTIONAL_SUBSTITUTION):
                element.text += self._parse_substitution()
            elif base == TOK_CDATA:
                self.u8()
                length = self.u16()
                element.text += self.bytes_(length).decode("utf-16le", errors="ignore")
            elif base == TOK_ENTITY_REF:
                self.u8()
                element.text += "&" + self.read_name() + ";"
            elif base == TOK_EOF:
                break
            else:
                # Unrecognized token in a content position: stop rather
                # than mis-walk the rest of the stream.
                break
        return element

    def _parse_substitution(self) -> str:
        self.u8()  # substitution token byte (already dispatched on by caller)
        index = self.u16()
        _value_type = self.u8()
        # Substitution *values* are only known after the whole element tree
        # has been walked (they follow it in the stream), so emit a
        # placeholder here and patch it in a second pass -- see
        # _apply_substitutions().
        return f"\ue000{index}\ue000"


def _parse_template_instance(buf: bytes, pos: int, chunk_start: int) -> tuple[XmlElement, int]:
    """Parse a TemplateInstance token (already consumed) at `pos`:
    template definition (inline, in this common case) followed by the
    substitution descriptor array + values, then decode the element tree."""
    pos += 1  # skip the TemplateInstance token byte itself
    pos += 1  # unknown byte
    _template_id = struct.unpack_from("<I", buf, pos)[0]
    pos += 4
    definition_offset = struct.unpack_from("<I", buf, pos)[0]
    pos += 4

    body_start = pos
    if definition_offset and definition_offset != (pos - chunk_start):
        # Points elsewhere in the chunk (already-defined template) -- jump there to read the tree.
        body_start = chunk_start + definition_offset
        # Skip the definition's own GUID+size header at that location.
        body_start += 16 + 4
    else:
        pos += 16  # template GUID
        pos += 4  # data size
        body_start = pos

    reader = _BxmlReader(buf, body_start, chunk_start)
    # Read past the FragmentHeader token that starts every template body.
    if reader.buf[reader.pos] & 0x0F == TOK_FRAGMENT_HEADER:
        reader.pos += 4  # major, minor, flags bytes (token + 3)

    # Substitution array follows the element tree's declared size in the
    # inline-definition case; scan forward from the element tree end.
    # We instead take the simpler, robust path used by real EVTX records:
    # after the (single) root element closes, the substitution count and
    # descriptor array immediately follow.
    root = reader.parse_element()

    sub_count = struct.unpack_from("<I", buf, reader.pos)[0]
    reader.pos += 4
    descriptors = []
    for _ in range(sub_count):
        size, type_id = struct.unpack_from("<HB", buf, reader.pos)
        reader.pos += 4
        descriptors.append((size, type_id))

    values = []
    for size, type_id in descriptors:
        raw = buf[reader.pos: reader.pos + size]
        reader.pos += size
        values.append(_decode_value(type_id, raw))

    reader.substitutions = values
    _resolve_substitutions(root, values)
    return root, reader.pos


_SUBST_PLACEHOLDER = re.compile("\ue000(\\d+)\ue000")


def _resolve_substitutions(element: XmlElement, values: list[Any]) -> None:
    """Second pass: replace every '\\ue000<index>\\ue000' placeholder left
    by _BxmlReader._parse_substitution() with the actual resolved value,
    now that the substitution value array has been read."""
    def _patch(text: str) -> str:
        def _sub(match: Any) -> str:
            idx = int(match.group(1))
            if 0 <= idx < len(values):
                val = values[idx]
                return "" if val is None else str(val)
            return ""
        return _SUBST_PLACEHOLDER.sub(_sub, text)

    element.text = _patch(element.text)
    for key in list(element.attributes.keys()):
        element.attributes[key] = _patch(element.attributes[key])
    for child in element.children:
        _resolve_substitutions(child, values)


@dataclass
class EvtxFileHeader:
    first_chunk_number: int
    last_chunk_number: int
    next_record_id: int
    major_version: int
    minor_version: int
    chunk_count: int
    dirty: bool


def parse_file_header(data: bytes) -> EvtxFileHeader:
    if data[:8] != FILE_SIGNATURE:
        raise EvtxError("Not an EVTX file (missing 'ElfFile' signature)")
    first_chunk, last_chunk, next_record_id = struct.unpack_from("<QQQ", data, 8)
    minor_version, major_version = struct.unpack_from("<HH", data, 36)
    chunk_count = struct.unpack_from("<H", data, 42)[0]
    flags = struct.unpack_from("<I", data, 120)[0]
    return EvtxFileHeader(
        first_chunk_number=first_chunk, last_chunk_number=last_chunk, next_record_id=next_record_id,
        major_version=major_version, minor_version=minor_version, chunk_count=chunk_count,
        dirty=bool(flags & 0x1),
    )


def _parse_chunk_records(data: bytes, chunk_start: int) -> list[EvtxRecord]:
    if data[chunk_start:chunk_start + 8] != CHUNK_SIGNATURE:
        return []
    free_space_offset = struct.unpack_from("<I", data, chunk_start + 48)[0]
    records = []
    pos = chunk_start + 512  # event records begin after the chunk header + string/template tables
    chunk_end = chunk_start + (free_space_offset if free_space_offset else CHUNK_SIZE)

    while pos + 24 <= min(chunk_end, chunk_start + CHUNK_SIZE):
        if data[pos:pos + 4] != RECORD_SIGNATURE:
            break
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if size < 24 or pos + size > len(data):
            break
        record_id = struct.unpack_from("<Q", data, pos + 8)[0]
        timestamp = struct.unpack_from("<Q", data, pos + 16)[0]

        bxml_pos = pos + 24
        try:
            first_token = data[bxml_pos] & 0x0F
            if first_token == TOK_FRAGMENT_HEADER:
                bxml_pos += 4
            if data[bxml_pos] & 0x0F == TOK_TEMPLATE_INSTANCE:
                root, _end = _parse_template_instance(data, bxml_pos, chunk_start)
            else:
                reader = _BxmlReader(data, bxml_pos, chunk_start)
                root = reader.parse_element()
            records.append(EvtxRecord(record_id=record_id, timestamp=filetime_to_iso(timestamp), xml=root))
        except (EvtxError, struct.error, IndexError, UnicodeDecodeError):
            pass  # skip unparseable record rather than aborting the whole chunk

        pos += size

    return records


def parse_evtx_bytes(data: bytes, max_records: int = 100_000) -> list[EvtxRecord]:
    header = parse_file_header(data)
    records: list[EvtxRecord] = []
    for chunk_index in range(header.chunk_count or ((len(data) - FILE_HEADER_SIZE) // CHUNK_SIZE)):
        chunk_start = FILE_HEADER_SIZE + chunk_index * CHUNK_SIZE
        if chunk_start + 8 > len(data):
            break
        records.extend(_parse_chunk_records(data, chunk_start))
        if len(records) >= max_records:
            break
    return records[:max_records]


def parse_evtx_file(path: str | Path, max_records: int = 100_000) -> list[EvtxRecord]:
    return parse_evtx_bytes(Path(path).read_bytes(), max_records=max_records)
