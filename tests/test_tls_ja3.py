import hashlib
import struct

import pytest

from modules.network.tls import (
    TlsParseError,
    compute_ja3,
    compute_ja3_string,
    parse_client_hello,
)


def _build_extension(ext_type: int, ext_data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(ext_data)) + ext_data


def _build_client_hello(cipher_suites: list[int], curves: list[int],
                         point_formats: list[int], sni: str | None = None,
                         tls_version: int = 0x0303) -> bytes:
    random_bytes = b"\x11" * 32
    session_id = b""  # empty session id

    cipher_bytes = struct.pack(f">{len(cipher_suites)}H", *cipher_suites)
    compression = b"\x00"  # 1 method: null compression

    extensions = b""
    if curves:
        curve_bytes = struct.pack(f">{len(curves)}H", *curves)
        ext_data = struct.pack(">H", len(curve_bytes)) + curve_bytes
        extensions += _build_extension(0x000A, ext_data)
    if point_formats:
        ext_data = bytes([len(point_formats)]) + bytes(point_formats)
        extensions += _build_extension(0x000B, ext_data)
    if sni:
        name_bytes = sni.encode("ascii")
        server_name_entry = b"\x00" + struct.pack(">H", len(name_bytes)) + name_bytes
        ext_data = struct.pack(">H", len(server_name_entry)) + server_name_entry
        extensions += _build_extension(0x0000, ext_data)

    body = (
        struct.pack(">H", tls_version) + random_bytes
        + bytes([len(session_id)]) + session_id
        + struct.pack(">H", len(cipher_bytes)) + cipher_bytes
        + bytes([len(compression)]) + compression
        + struct.pack(">H", len(extensions)) + extensions
    )

    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    record = bytes([0x16]) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def test_parse_client_hello_basic_fields():
    data = _build_client_hello(
        cipher_suites=[0x002F, 0x0035, 0xC02F],
        curves=[0x001D, 0x0017],
        point_formats=[0],
        sni="malicious-c2.example.net",
    )
    hello = parse_client_hello(data)
    assert hello.tls_version == 0x0303
    assert hello.cipher_suites == [0x002F, 0x0035, 0xC02F]
    assert hello.elliptic_curves == [0x001D, 0x0017]
    assert hello.ec_point_formats == [0]
    assert hello.sni == "malicious-c2.example.net"
    assert 0x000A in hello.extensions
    assert 0x0000 in hello.extensions


def test_grease_values_stripped_from_ja3_string():
    grease = 0x0A0A
    data = _build_client_hello(
        cipher_suites=[grease, 0x002F, 0x0035, 0xC02F],
        curves=[grease, 0x001D, 0x0017],
        point_formats=[0],
    )
    hello = parse_client_hello(data)
    ja3_str = compute_ja3_string(hello)
    parts = ja3_str.split(",")
    assert "2570" not in parts[1]  # 0x0A0A == 2570 decimal; must be stripped
    assert parts[1] == "47-53-49199"
    assert parts[3] == "29-23"


def test_ja3_string_and_hash_are_self_consistent():
    data = _build_client_hello(
        cipher_suites=[0x002F, 0x0035, 0xC02F],
        curves=[0x001D, 0x0017],
        point_formats=[0],
        sni="example.com",
    )
    result = compute_ja3(data)
    expected_string = "771,47-53-49199,10-11-0,29-23,0"
    assert result["ja3_string"] == expected_string
    assert result["ja3_hash"] == hashlib.md5(expected_string.encode()).hexdigest()
    assert result["sni"] == "example.com"


def test_rejects_non_client_hello():
    with pytest.raises(TlsParseError):
        parse_client_hello(b"\x17\x03\x01\x00\x05hello")  # 0x17 = application_data, not handshake


def test_bare_handshake_without_record_header():
    data = _build_client_hello(cipher_suites=[0x002F], curves=[], point_formats=[])
    # Strip the 5-byte TLS record header, leaving just the handshake message.
    bare = data[5:]
    hello = parse_client_hello(bare)
    assert hello.cipher_suites == [0x002F]
