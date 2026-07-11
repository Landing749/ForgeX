import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from modules.windows.prefetch import (
    PrefetchError,
    is_mam_compressed,
    parse_file,
    parse_mam_header,
    parse_uncompressed,
)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _to_filetime(dt: datetime) -> int:
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


def _build_prefetch_v17(exe_name: str = "MALWARE.EXE", run_count: int = 7) -> bytes:
    strings = ["\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
               "\\DEVICE\\HARDDISKVOLUME1\\MALWARE.EXE"]
    strings_block = ("\x00".join(strings) + "\x00").encode("utf-16le")

    volume_path = "\\DEVICE\\HARDDISKVOLUME1"
    volume_record_size = 28  # v17
    volumes_section_size = volume_record_size + len(volume_path.encode("utf-16le")) + 2

    header_size = 84
    fileinfo_size = 68  # v17 FileInformation size
    strings_offset = header_size + fileinfo_size
    volumes_offset = strings_offset + len(strings_block)
    # pad volumes offset to be safe (not required, but realistic)
    total_size = volumes_offset + volumes_section_size

    buf = bytearray(total_size)
    struct.pack_into("<I", buf, 0, 17)  # version
    buf[4:8] = b"SCCA"
    struct.pack_into("<I", buf, 8, 0)
    struct.pack_into("<I", buf, 12, total_size)
    name_bytes = exe_name.encode("utf-16le")
    buf[16:16 + len(name_bytes)] = name_bytes
    struct.pack_into("<I", buf, 76, 0xDEADBEEF)
    struct.pack_into("<I", buf, 80, 0)

    # Section A-D table at offset 84
    struct.pack_into("<9I", buf, 84,
                      0, 0,  # metrics offset/count (unused in this test)
                      0, 0,  # trace chain offset/count
                      strings_offset, len(strings_block),
                      volumes_offset, 1, volumes_section_size)

    # v17 run info
    last_run = datetime(2026, 5, 20, 14, 0, 0, tzinfo=timezone.utc)
    struct.pack_into("<Q", buf, 120, _to_filetime(last_run))
    struct.pack_into("<I", buf, 144, run_count)

    buf[strings_offset:strings_offset + len(strings_block)] = strings_block

    # Volume record (relative offsets within the volumes section)
    vol_path_bytes = volume_path.encode("utf-16le")
    struct.pack_into("<II", buf, volumes_offset, volume_record_size, len(volume_path))
    vol_created = datetime(2025, 1, 1, tzinfo=timezone.utc)
    struct.pack_into("<Q", buf, volumes_offset + 8, _to_filetime(vol_created))
    struct.pack_into("<I", buf, volumes_offset + 16, 0x12345678)
    path_abs_offset = volumes_offset + volume_record_size
    buf[path_abs_offset:path_abs_offset + len(vol_path_bytes)] = vol_path_bytes

    return bytes(buf)


def test_parse_v17_header_fields():
    data = _build_prefetch_v17()
    pf = parse_uncompressed(data)
    assert pf.version == 17
    assert pf.executable_name == "MALWARE.EXE"
    assert pf.prefetch_hash == "DEADBEEF"
    assert pf.run_count == 7
    assert pf.last_run_time is not None
    assert pf.run_info_confidence == "high"


def test_parse_v17_referenced_files():
    data = _build_prefetch_v17()
    pf = parse_uncompressed(data)
    assert "\\DEVICE\\HARDDISKVOLUME1\\MALWARE.EXE" in pf.referenced_files
    assert any("KERNEL32.DLL" in f for f in pf.referenced_files)


def test_parse_v17_volume_info():
    data = _build_prefetch_v17()
    pf = parse_uncompressed(data)
    assert len(pf.volumes) == 1
    assert pf.volumes[0].device_path == "\\DEVICE\\HARDDISKVOLUME1"
    assert pf.volumes[0].serial_number == "12345678"
    assert pf.volumes[0].creation_time is not None


def test_rejects_bad_signature():
    with pytest.raises(PrefetchError):
        parse_uncompressed(b"\x00" * 200)


def test_mam_header_detection_and_parsing():
    payload = b"\x01\x02\x03\x04" * 100
    mam_file = b"MAM\x04" + struct.pack("<I", 65536) + payload
    assert is_mam_compressed(mam_file) is True
    info = parse_mam_header(mam_file)
    assert info["decompressed_size"] == 65536
    assert info["compressed_payload_size"] == len(payload)


def test_parse_file_dispatches_mam_vs_uncompressed(tmp_path: Path):
    uncompressed_path = tmp_path / "legacy.pf"
    uncompressed_path.write_bytes(_build_prefetch_v17())
    result = parse_file(uncompressed_path)
    assert result["version"] == 17

    mam_path = tmp_path / "win10.pf"
    mam_path.write_bytes(b"MAM\x04" + struct.pack("<I", 4096) + b"\x00" * 100)
    result2 = parse_file(mam_path)
    assert "MAM" in result2["container"]
