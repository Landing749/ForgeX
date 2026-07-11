import socket
import struct

from modules.network import pcap, pcapng


def _build_dns_query_packet(src_ip: str, dst_ip: str, src_port: int, domain: str) -> bytes:
    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack(">H", 0x0800)

    labels = b"".join(bytes([len(p)]) + p.encode() for p in domain.split("."))
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)

    udp_len = 8 + len(dns)
    udp = struct.pack(">HHHH", src_port, 53, udp_len, 0) + dns

    ip_total_len = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return eth + ip + udp


def _build_classic_pcap(packets: list[bytes]) -> bytes:
    global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    body = b""
    for i, pkt in enumerate(packets):
        body += struct.pack("<IIII", 1_700_000_000 + i, 0, len(pkt), len(pkt)) + pkt
    return global_header + body


def _build_pcapng(packets: list[bytes]) -> bytes:
    def block(block_type: int, body: bytes) -> bytes:
        total_len = 12 + len(body)
        pad = (-len(body)) % 4
        body += b"\x00" * pad
        total_len = 12 + len(body)
        return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)

    shb_body = struct.pack("<IHHq", pcapng.BYTE_ORDER_MAGIC, 1, 0, -1)
    shb = block(pcapng.BLOCK_SECTION_HEADER, shb_body)

    idb_body = struct.pack("<HHI", 1, 0, 65535)  # LinkType=1 (Ethernet), reserved, snaplen
    idb = block(pcapng.BLOCK_INTERFACE_DESCRIPTION, idb_body)

    buf = shb + idb
    for i, pkt in enumerate(packets):
        ts = (1_700_000_000 + i) * 1_000_000
        ts_high, ts_low = (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF
        epb_body = struct.pack("<IIIII", 0, ts_high, ts_low, len(pkt), len(pkt)) + pkt
        buf += block(pcapng.BLOCK_ENHANCED_PACKET, epb_body)
    return buf


def test_classic_pcap_decodes_dns_query():
    pkt = _build_dns_query_packet("10.0.0.5", "8.8.8.8", 51820, "malicious-c2.example")
    data = _build_classic_pcap([pkt])
    packets = list(pcap.read_packets(_write_temp(data)))
    assert len(packets) == 1
    p = packets[0]
    assert p.src_ip == "10.0.0.5"
    assert p.dst_ip == "8.8.8.8"
    assert p.protocol == "UDP"
    assert p.dns_query == "malicious-c2.example"


def test_classic_pcap_summarize_conversations():
    pkt1 = _build_dns_query_packet("10.0.0.5", "8.8.8.8", 51820, "a.example")
    pkt2 = _build_dns_query_packet("8.8.8.8", "10.0.0.5", 53, "a.example")
    data = _build_classic_pcap([pkt1, pkt2])
    summary = pcap.summarize(_write_temp(data))
    assert summary["packet_count"] == 2
    assert summary["top_conversations"][0]["packets"] == 2
    assert "a.example" in summary["dns_queries"]


def test_pcapng_decodes_dns_query():
    pkt = _build_dns_query_packet("192.168.1.10", "1.1.1.1", 40000, "beacon.evil-domain.net")
    data = _build_pcapng([pkt])
    packets = pcapng.parse_pcapng_bytes(data)
    assert len(packets) == 1
    p = packets[0]
    assert p.src_ip == "192.168.1.10"
    assert p.dst_ip == "1.1.1.1"
    assert p.dns_query == "beacon.evil-domain.net"
    assert p.timestamp  # EPB carries a real timestamp


def test_pcapng_rejects_non_pcapng_file():
    import pytest
    with pytest.raises(pcapng.PcapNgError):
        pcapng.parse_pcapng_bytes(b"not a pcapng file at all")


def test_pcapng_multiple_packets():
    pkt1 = _build_dns_query_packet("10.0.0.1", "8.8.8.8", 1000, "one.example")
    pkt2 = _build_dns_query_packet("10.0.0.2", "8.8.4.4", 1001, "two.example")
    data = _build_pcapng([pkt1, pkt2])
    packets = pcapng.parse_pcapng_bytes(data)
    assert len(packets) == 2
    assert {p.dns_query for p in packets} == {"one.example", "two.example"}


def _write_temp(data: bytes):
    import tempfile
    from pathlib import Path
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    Path(f.name).write_bytes(data)
    return f.name
