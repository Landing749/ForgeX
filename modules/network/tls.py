"""TLS ClientHello parsing and JA3 fingerprinting.

JA3 (Salesforce, 2017) fingerprints a TLS client by hashing a
normalized string built from five fields pulled straight out of the
ClientHello handshake message:

    JA3 = MD5(
        TLSVersion,GreaseStrippedCipherSuites,GreaseStrippedExtensions,
        EllipticCurves,EllipticCurvePointFormats
    )

joined with '-' within each field and ',' between fields. This module
parses a raw TLS record containing a ClientHello (as extracted from a
TCP payload -- see modules.network.pcap for getting there from a pcap/
pcapng capture) directly with stdlib `struct`, then computes JA3
per the published algorithm. No scapy dependency required.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass, field
from typing import Any

# "GREASE" values (RFC 8701) are reserved cipher/extension/group IDs of the
# form 0x?A?A used by real clients to detect naive parsers; JA3 always
# strips them before hashing.
_GREASE_VALUES = {(b << 8 | b) for b in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                                          0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)}

TLS_HANDSHAKE_CONTENT_TYPE = 0x16
CLIENT_HELLO_MSG_TYPE = 0x01


class TlsParseError(Exception):
    pass


@dataclass
class ClientHello:
    tls_version: int
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    elliptic_curves: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    sni: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE_VALUES]


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse a ClientHello from a raw TCP payload. Accepts either a full
    TLS record (starting with the 0x16 handshake content-type byte) or a
    bare handshake message (starting with the 0x01 ClientHello type)."""
    pos = 0
    if len(data) < 6:
        raise TlsParseError("Buffer too short to contain a TLS record")

    if data[0] == TLS_HANDSHAKE_CONTENT_TYPE:
        # TLS record header: type(1) + version(2) + length(2)
        pos = 5

    if pos >= len(data) or data[pos] != CLIENT_HELLO_MSG_TYPE:
        raise TlsParseError("Not a ClientHello (unexpected handshake message type)")
    pos += 1

    handshake_len = int.from_bytes(data[pos:pos + 3], "big")
    pos += 3
    body_end = pos + handshake_len
    if body_end > len(data):
        body_end = len(data)  # tolerate truncated capture; parse what we have

    tls_version = struct.unpack_from(">H", data, pos)[0]
    pos += 2

    pos += 32  # client random (32 bytes) -- not used by JA3

    session_id_len = data[pos]
    pos += 1 + session_id_len

    cipher_suites_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    cipher_suites = list(struct.unpack_from(f">{cipher_suites_len // 2}H", data, pos))
    pos += cipher_suites_len

    compression_len = data[pos]
    pos += 1 + compression_len

    extensions: list[int] = []
    elliptic_curves: list[int] = []
    ec_point_formats: list[int] = []
    sni: str | None = None

    if pos + 2 <= body_end:
        extensions_total_len = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        ext_end = min(pos + extensions_total_len, body_end)

        while pos + 4 <= ext_end:
            ext_type = struct.unpack_from(">H", data, pos)[0]
            ext_len = struct.unpack_from(">H", data, pos + 2)[0]
            ext_data = data[pos + 4: pos + 4 + ext_len]
            extensions.append(ext_type)

            if ext_type == 0x000A and len(ext_data) >= 2:  # supported_groups (elliptic curves)
                list_len = struct.unpack_from(">H", ext_data, 0)[0]
                count = list_len // 2
                elliptic_curves = list(struct.unpack_from(f">{count}H", ext_data, 2))
            elif ext_type == 0x000B and len(ext_data) >= 1:  # ec_point_formats
                fmt_len = ext_data[0]
                ec_point_formats = list(ext_data[1:1 + fmt_len])
            elif ext_type == 0x0000 and len(ext_data) >= 5:  # server_name (SNI)
                # server_name_list: 2-byte list len, then 1-byte type + 2-byte len + name
                name_len = struct.unpack_from(">H", ext_data, 3)[0]
                sni = ext_data[5:5 + name_len].decode("ascii", errors="ignore")

            pos += 4 + ext_len

    return ClientHello(
        tls_version=tls_version, cipher_suites=cipher_suites, extensions=extensions,
        elliptic_curves=elliptic_curves, ec_point_formats=ec_point_formats, sni=sni,
    )


def compute_ja3_string(hello: ClientHello) -> str:
    ciphers = _strip_grease(hello.cipher_suites)
    exts = _strip_grease(hello.extensions)
    curves = _strip_grease(hello.elliptic_curves)
    return ",".join([
        str(hello.tls_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(c) for c in curves),
        "-".join(str(f) for f in hello.ec_point_formats),
    ])


def compute_ja3(data: bytes) -> dict[str, str]:
    """Top-level entry point: parse a ClientHello and return both the
    normalized JA3 string and its MD5 hash (the conventional JA3
    fingerprint used for threat-intel matching)."""
    hello = parse_client_hello(data)
    ja3_string = compute_ja3_string(hello)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return {"ja3_string": ja3_string, "ja3_hash": ja3_hash, "sni": hello.sni}
