import struct
from datetime import datetime, timezone

from modules.windows.evtx_native import (
    CHUNK_SIZE,
    FILE_HEADER_SIZE,
    parse_evtx_bytes,
    parse_file_header,
)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
CHUNK_START = FILE_HEADER_SIZE  # first (only) chunk in our synthetic files


def _to_filetime(dt: datetime) -> int:
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


class _Writer:
    """Appends binary-XML tokens to a buffer, tracking absolute chunk
    offsets so inline name references can point at themselves."""

    def __init__(self, chunk_start: int):
        self.chunk_start = chunk_start
        self.buf = bytearray()

    @property
    def pos(self) -> int:
        return self.chunk_start + len(self.buf)

    def u8(self, v: int):
        self.buf += struct.pack("<B", v)

    def u16(self, v: int):
        self.buf += struct.pack("<H", v)

    def u32(self, v: int):
        self.buf += struct.pack("<I", v)

    def raw(self, b: bytes):
        self.buf += b

    def write_inline_name(self, name: str):
        self.u32(self.pos - self.chunk_start)  # ref_offset == current position (chunk-relative) => inline
        self.u16(0)  # hash (unused by parser)
        self.u16(len(name))
        self.raw(name.encode("utf-16le"))
        self.u16(0)  # NUL terminator

    def open_element(self, name: str, has_attrs: bool = False):
        self.u8(0x01)
        self.u16(0xFFFF)  # dependency id (unused)
        self.u32(0)  # element data size (unused by this parser)
        self.write_inline_name(name)

    def close_start(self):
        self.u8(0x02)

    def close_empty(self):
        self.u8(0x03)

    def end_element(self):
        self.u8(0x04)

    def value_text(self, text: str, type_id: int = 0x01):
        self.u8(0x05)  # Value token
        self.u8(type_id)
        data = text.encode("utf-16le")
        self.u16(len(data))
        self.raw(data)

    def attribute(self, name: str, value: str):
        self.u8(0x06)  # Attribute token
        self.write_inline_name(name)
        # Attribute value: type+length+data, no separate Value token wrapper.
        self.u8(0x01)
        data = value.encode("utf-16le")
        self.u16(len(data))
        self.raw(data)

    def template_instance_start(self):
        self.u8(0x0C)
        self.u8(0x01)  # unknown
        self.u32(1)  # template id
        def_offset_after_field = (self.pos + 4) - self.chunk_start
        self.u32(def_offset_after_field)  # points at itself => inline definition follows
        self.raw(b"\x00" * 16)  # template GUID (unused by parser)
        self.u32(0)  # data size (unused by parser)

    def fragment_header(self):
        self.u8(0x0F)
        self.u8(1)
        self.u8(1)
        self.u8(0)

    def substitution(self, index: int, value_type: int = 0x01, optional: bool = False):
        self.u8(0x0E if optional else 0x0D)
        self.u16(index)
        self.u8(value_type)

    def template_instance_end(self, substitution_values: list[tuple[int, bytes]]):
        self.u32(len(substitution_values))
        for type_id, raw in substitution_values:
            self.u16(len(raw))
            self.u8(type_id)
            self.u8(0)  # padding
        for _type_id, raw in substitution_values:
            self.raw(raw)


def _build_evtx_file(record_builder) -> bytes:
    """record_builder(writer) should emit one complete record's binary-XML
    body (starting right after the 24-byte record header)."""
    file_header = bytearray(FILE_HEADER_SIZE)
    file_header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", file_header, 8, 0, 0, 1)
    struct.pack_into("<HH", file_header, 36, 1, 3)  # minor, major version
    struct.pack_into("<H", file_header, 42, 1)  # chunk count

    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"

    writer = _Writer(CHUNK_START)
    writer.buf = bytearray(512 + 24)  # reserve chunk header/table region *and* the record header
    record_builder(writer)

    record_bxml = writer.buf[512 + 24:]
    record_start_in_chunk = 512
    total_record_size = 24 + len(record_bxml)

    record_header = bytearray(24)
    record_header[0:4] = b"\x2a\x2a\x00\x00"
    struct.pack_into("<I", record_header, 4, total_record_size)
    struct.pack_into("<Q", record_header, 8, 42)  # record id
    ts = datetime(2026, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
    struct.pack_into("<Q", record_header, 16, _to_filetime(ts))

    full_record = bytes(record_header) + bytes(record_bxml)
    chunk[record_start_in_chunk:record_start_in_chunk + len(full_record)] = full_record

    free_space_offset = record_start_in_chunk + len(full_record)
    struct.pack_into("<I", chunk, 48, free_space_offset)

    return bytes(file_header) + bytes(chunk)


def test_parse_file_header():
    data = _build_evtx_file(lambda w: (w.open_element("Event"), w.close_start(), w.end_element()))
    header = parse_file_header(data)
    assert header.major_version == 3
    assert header.chunk_count == 1
    assert header.next_record_id == 1


def test_parse_simple_element_with_text_child():
    def build(w: _Writer):
        w.open_element("Event")
        w.close_start()
        w.open_element("EventID")
        w.close_start()
        w.value_text("4624")
        w.end_element()  # closes EventID
        w.end_element()  # closes Event

    data = _build_evtx_file(build)
    records = parse_evtx_bytes(data)
    assert len(records) == 1
    root = records[0].xml
    assert root.name == "Event"
    event_id = root.find("EventID")
    assert event_id is not None
    assert event_id.text == "4624"


def test_parse_record_metadata():
    data = _build_evtx_file(lambda w: (w.open_element("Event"), w.close_start(), w.end_element()))
    records = parse_evtx_bytes(data)
    assert records[0].record_id == 42
    assert records[0].timestamp is not None
    assert records[0].timestamp.startswith("2026-06-15")


def test_parse_element_with_attribute():
    def build(w: _Writer):
        w.open_element("Data", has_attrs=True)
        w.attribute("Name", "TargetUserName")
        w.close_start()
        w.value_text("jdoe")
        w.end_element()

    data = _build_evtx_file(build)
    records = parse_evtx_bytes(data)
    root = records[0].xml
    assert root.name == "Data"
    assert root.attributes["Name"] == "TargetUserName"
    assert root.text == "jdoe"


def test_parse_nested_elements_and_empty_element():
    def build(w: _Writer):
        w.open_element("System")
        w.close_start()
        w.open_element("Provider", has_attrs=True)
        w.attribute("Name", "Microsoft-Windows-Security-Auditing")
        w.close_empty()
        w.open_element("EventID")
        w.close_start()
        w.value_text("4624")
        w.end_element()
        w.end_element()  # closes System

    data = _build_evtx_file(build)
    root = parse_evtx_bytes(data)[0].xml
    assert root.name == "System"
    provider = root.find("Provider")
    assert provider is not None
    assert provider.attributes["Name"] == "Microsoft-Windows-Security-Auditing"
    assert root.find("EventID").text == "4624"


def test_xml_roundtrip_rendering():
    def build(w: _Writer):
        w.open_element("Event")
        w.close_start()
        w.open_element("EventID")
        w.close_start()
        w.value_text("1102")
        w.end_element()
        w.end_element()

    data = _build_evtx_file(build)
    root = parse_evtx_bytes(data)[0].xml
    xml_str = root.to_xml()
    assert "<Event>" in xml_str
    assert "<EventID>" in xml_str
    assert "1102" in xml_str


def test_parse_template_instance_with_substitution():
    def build(w: _Writer):
        w.template_instance_start()
        w.fragment_header()
        w.open_element("Event")
        w.close_start()
        w.open_element("TargetUserName")
        w.close_start()
        w.substitution(index=0, value_type=0x01)
        w.end_element()
        w.end_element()
        sub_value = "jdoe".encode("utf-16le")
        w.template_instance_end([(0x01, sub_value)])

    data = _build_evtx_file(build)
    records = parse_evtx_bytes(data)
    assert len(records) == 1
    root = records[0].xml
    assert root.name == "Event"
    target_user = root.find("TargetUserName")
    assert target_user is not None
    assert target_user.text == "jdoe"


def test_template_instance_substitution_in_attribute():
    def build(w: _Writer):
        w.template_instance_start()
        w.fragment_header()
        w.open_element("Data")
        w.u8(0x06)  # Attribute token
        w.write_inline_name("Name")
        w.substitution(index=0, value_type=0x01)
        w.close_start()
        w.substitution(index=1, value_type=0x08)  # UInt32 substitution as element text
        w.end_element()
        name_value = "LogonType".encode("utf-16le")
        num_value = struct.pack("<I", 3)
        w.template_instance_end([(0x01, name_value), (0x08, num_value)])

    data = _build_evtx_file(build)
    root = parse_evtx_bytes(data)[0].xml
    assert root.attributes["Name"] == "LogonType"
    assert root.text == "3"
